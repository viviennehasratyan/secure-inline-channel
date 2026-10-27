#include <openssl/kdf.h>
/*
 * secchan.c - inline TCP-payload protection between two Linux devices.
 *
 *   PC1 -> Device1 -> Device2 -> PC2
 *
 * Handshake : finite-field Diffie-Hellman (RFC 3526 group 14 / modp_2048) over a
 *             separate control TCP connection between the devices, with the
 *             hello messages authenticated by a pre-shared key (anti-MITM).
 *             Session key = HKDF-SHA256(DH secret, client_rnd || server_rnd).
 * Data path : iptables NFQUEUE. Only the TCP payload is encrypted with
 *             AES-256-GCM; IP/TCP headers are kept; the 16-byte tag is appended
 *             to the payload. No UDP encapsulation, no extra header.
 *
 * Queue 0 = encrypt (plaintext side), queue 1 = decrypt (ciphertext side).
 *
 * Nonce design (receiver must be able to rebuild it from the packet alone):
 *   per-connection key = HKDF(session_key, 4-tuple || client ISN)   [taken from the SYN]
 *   nonce (12 B)       = gen(1) | 0(3) | ext_seq(8, big endian)
 *   ext_seq = 64-bit extension of (tcp_seq - ISN).
 *   gen     = bumped by the sender whenever the *same* seq is sent again with
 *             *different* plaintext (e.g. coalesced retransmissions). The sender
 *             keeps a ring of what it has sent; if it cannot prove a nonce is
 *             unused it DROPS the packet (fail closed) instead of risking reuse.
 *   Receiver tries gen = 0..MAXGEN; the GCM tag decides.
 *
 * Build: gcc -O2 -Wall -o secchan secchan.c -lnetfilter_queue -lnfnetlink -lcrypto
 * Run  : SECCHAN_PSK='secret' ./secchan server|client <peer/bind ip> <port>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#define TAGLEN    16
#define KEYLEN    32
#define DH_BYTES  256            /* modp_2048 */
#define MAXGEN    7
#define RING      512            /* sent-segment memory per connection */
#define MAXFLOWS  256
#define OUTBUF    (65535 + 64)

static uint8_t g_key[KEYLEN];            /* session key from the DH handshake */
static EVP_CIPHER_CTX *g_ctx;
static int g_verbose;
#define LOG(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

/* ------------------------------------------------------------ helpers */
static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static int hkdf(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il,
                const uint8_t *info, size_t nl, uint8_t *out, size_t ol)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ok = c && EVP_PKEY_derive_init(c) > 0 &&
             EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_salt(c, salt, (int)sl) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_key(c, ikm, (int)il) > 0 &&
             EVP_PKEY_CTX_add1_hkdf_info(c, info, (int)nl) > 0 &&
             EVP_PKEY_derive(c, out, &ol) > 0;
    EVP_PKEY_CTX_free(c);
    return ok;
}

/* ------------------------------------------------------------ DH (OpenSSL 3) */
static EVP_PKEY *dh_generate(void)
{
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM p[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"modp_2048", 0),
        OSSL_PARAM_construct_end()
    };
    if (c && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_CTX_set_params(c, p) > 0)
        EVP_PKEY_generate(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static int dh_pub_bytes(EVP_PKEY *k, uint8_t *out)
{
    BIGNUM *bn = NULL;
    if (!EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PUB_KEY, &bn)) return 0;
    int ok = BN_bn2binpad(bn, out, DH_BYTES) == DH_BYTES;
    BN_free(bn);
    return ok;
}

static EVP_PKEY *dh_import_peer(const uint8_t *pub)
{
    EVP_PKEY *k = NULL;
    BIGNUM *bn = BN_bin2bn(pub, DH_BYTES, NULL);
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (bn && b && c &&
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "modp_2048", 0) &&
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, bn) &&
        (ps = OSSL_PARAM_BLD_to_param(b)) &&
        EVP_PKEY_fromdata_init(c) > 0)
        EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, ps);
    OSSL_PARAM_free(ps); OSSL_PARAM_BLD_free(b); BN_free(bn); EVP_PKEY_CTX_free(c);
    if (k) {                                    /* reject 0, 1, p-1, out-of-range ... */
        EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        if (!v || EVP_PKEY_public_check(v) <= 0) { EVP_PKEY_free(k); k = NULL; }
        EVP_PKEY_CTX_free(v);
    }
    return k;
}

static int dh_derive(EVP_PKEY *mine, EVP_PKEY *peer, uint8_t *out /*DH_BYTES*/)
{
    size_t l = 0;
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    int ok = d && EVP_PKEY_derive_init(d) > 0 && EVP_PKEY_CTX_set_dh_pad(d, 1) > 0 &&
             EVP_PKEY_derive_set_peer(d, peer) > 0 &&
             EVP_PKEY_derive(d, NULL, &l) > 0 && l == DH_BYTES &&
             EVP_PKEY_derive(d, out, &l) > 0;
    EVP_PKEY_CTX_free(d);
    return ok;
}

/* ------------------------------------------------------------ handshake */
struct __attribute__((packed)) hello {
    uint8_t magic[4];
    uint8_t role;                 /* 'C' or 'S'  (MAC covers from here on) */
    uint8_t pub[DH_BYTES];
    uint8_t rnd[32];
    uint8_t mac[32];              /* HMAC-SHA256(psk, role||pub||rnd) */
};

static void hello_mac(const char *psk, const struct hello *h, uint8_t out[32])
{
    unsigned int ol = 32;
    HMAC(EVP_sha256(), psk, (int)strlen(psk), &h->role, 1 + DH_BYTES + 32, out, &ol);
}

static int write_full(int fd, const void *b, size_t n)
{
    const uint8_t *p = b;
    while (n) { ssize_t r = write(fd, p, n); if (r <= 0) return 0; p += r; n -= r; }
    return 1;
}
static int read_full(int fd, void *b, size_t n)
{
    uint8_t *p = b;
    while (n) { ssize_t r = read(fd, p, n); if (r <= 0) return 0; p += r; n -= r; }
    return 1;
}

static int control_connect(int server, const char *ip, int port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &a.sin_addr);
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    if (server) {
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(s, (void *)&a, sizeof a) || listen(s, 1)) { perror("bind/listen"); exit(1); }
        fprintf(stderr, "waiting for peer on %s:%d ...\n", ip, port);
        int c = accept(s, NULL, NULL);
        close(s);
        return c;
    }
    for (;;) {
        if (connect(s, (void *)&a, sizeof a) == 0) return s;
        close(s); sleep(1); s = socket(AF_INET, SOCK_STREAM, 0);
    }
}

static int handshake(int fd, int server, const char *psk)
{
    struct hello me, peer;
    memset(&me, 0, sizeof me);
    memcpy(me.magic, "SCH1", 4);
    me.role = server ? 'S' : 'C';
    EVP_PKEY *k = dh_generate();
    if (!k || !dh_pub_bytes(k, me.pub) || RAND_bytes(me.rnd, 32) != 1) return 0;
    hello_mac(psk, &me, me.mac);

    if (!write_full(fd, &me, sizeof me) || !read_full(fd, &peer, sizeof peer)) return 0;
    uint8_t m[32];
    hello_mac(psk, &peer, m);
    if (memcmp(peer.magic, "SCH1", 4) || peer.role != (server ? 'C' : 'S') ||
        CRYPTO_memcmp(m, peer.mac, 32)) { fprintf(stderr, "peer authentication failed\n"); return 0; }

    EVP_PKEY *pk = dh_import_peer(peer.pub);
    uint8_t secret[DH_BYTES], salt[64];
    if (!pk || !dh_derive(k, pk, secret)) { fprintf(stderr, "DH failed\n"); return 0; }
    memcpy(salt,      server ? peer.rnd : me.rnd, 32);      /* client rnd first */
    memcpy(salt + 32, server ? me.rnd : peer.rnd, 32);
    int ok = hkdf(salt, 64, secret, sizeof secret,
                  (const uint8_t *)"secchan session key v1", 22, g_key, KEYLEN);
    OPENSSL_cleanse(secret, sizeof secret);
    EVP_PKEY_free(k); EVP_PKEY_free(pk);
    return ok;
}

/* ------------------------------------------------------------ AES-GCM */
static int gcm_seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, int al,
                    const uint8_t *pt, int pl, uint8_t *ct, uint8_t *tag)
{
    int l = 0, ok;
    ok = EVP_EncryptInit_ex(g_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
         EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
         EVP_EncryptInit_ex(g_ctx, NULL, NULL, key, nonce) &&
         EVP_EncryptUpdate(g_ctx, NULL, &l, aad, al) &&
         EVP_EncryptUpdate(g_ctx, ct, &l, pt, pl) &&
         EVP_EncryptFinal_ex(g_ctx, ct + l, &l) &&
         EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, tag);
    return ok;
}

static int gcm_open(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, int al,
                    const uint8_t *ct, int cl, const uint8_t *tag, uint8_t *pt)
{
    int l = 0;
    return EVP_DecryptInit_ex(g_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
           EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
           EVP_DecryptInit_ex(g_ctx, NULL, NULL, key, nonce) &&
           EVP_DecryptUpdate(g_ctx, NULL, &l, aad, al) &&
           EVP_DecryptUpdate(g_ctx, pt, &l, ct, cl) &&
           EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, (void *)tag) &&
           EVP_DecryptFinal_ex(g_ctx, pt + l, &l) > 0;
}

/* ------------------------------------------------------------ per-connection state */
struct sent { uint64_t ext; uint16_t plen; uint8_t gen; uint8_t h[16]; };

struct flow {
    uint8_t  id[12];              /* saddr|daddr|sport|dport as on the wire */
    uint32_t isn;
    uint8_t  key[KEYLEN];
    uint64_t last_ext;
    /* sender-side nonce bookkeeping */
    struct sent ring[RING];
    int cnt, head;
    uint64_t high, evicted_max;
    int have_high, evicted_any;
};

static struct flow g_flows[MAXFLOWS];
static int g_nflows;

static struct flow *flow_find(const uint8_t *sip, const uint8_t *dip, const uint8_t *tcp)
{
    uint8_t id[12];
    memcpy(id, sip, 4); memcpy(id + 4, dip, 4); memcpy(id + 8, tcp, 4);
    for (int i = 0; i < g_nflows; i++)
        if (!memcmp(g_flows[i].id, id, 12)) return &g_flows[i];
    return NULL;
}

/* SYN seen: create the connection state (both devices see the same SYN). */
static struct flow *flow_syn(const uint8_t *sip, const uint8_t *dip, const uint8_t *tcp, uint32_t isn)
{
    struct flow *f = flow_find(sip, dip, tcp);
    if (f && f->isn == isn) return f;
    if (!f) {
        if (g_nflows >= MAXFLOWS) { LOG("flow table full\n"); return NULL; }   /* fail closed */
        f = &g_flows[g_nflows++];
    }
    memset(f, 0, sizeof *f);
    memcpy(f->id, sip, 4); memcpy(f->id + 4, dip, 4); memcpy(f->id + 8, tcp, 4);
    f->isn = isn;
    uint8_t info[15 + 12 + 4] = "secchan flow v1";
    memcpy(info + 15, f->id, 12);
    info[27] = isn >> 24; info[28] = isn >> 16; info[29] = isn >> 8; info[30] = isn;
    if (!hkdf(NULL, 0, g_key, KEYLEN, info, sizeof info, f->key, KEYLEN)) return NULL;
    LOG("new flow, isn=%u\n", isn);
    return f;
}

static uint64_t extend(uint64_t last, uint32_t rel)
{
    uint64_t c = (last & ~0xffffffffULL) | rel;
    if (c + 0x80000000ULL < last) c += 1ULL << 32;
    else if (c > last + 0x80000000ULL && c >= (1ULL << 32)) c -= 1ULL << 32;
    return c;
}

/* Choose a gen so that (key, nonce) is never used for two different plaintexts. */
static int pick_gen(struct flow *f, uint64_t ext, const uint8_t *pt, int plen)
{
    uint8_t d[32]; unsigned int dl = 32;
    EVP_Digest(pt, plen, d, &dl, EVP_sha256(), NULL);

    struct sent *e = NULL;
    if (f->have_high && ext <= f->high)
        for (int i = 0; i < f->cnt; i++)
            if (f->ring[i].ext == ext) { e = &f->ring[i]; break; }
    if (e) {
        if (e->plen == plen && !memcmp(e->h, d, 16)) return e->gen;   /* identical resend */
        if (e->gen >= MAXGEN) return -1;
        e->gen++; e->plen = plen; memcpy(e->h, d, 16);
        return e->gen;
    }
    if (f->evicted_any && ext <= f->evicted_max) return -1;           /* cannot prove unused */

    struct sent *s;
    if (f->cnt < RING) s = &f->ring[f->cnt++];
    else {
        s = &f->ring[f->head]; f->head = (f->head + 1) % RING;
        if (!f->evicted_any || s->ext > f->evicted_max) f->evicted_max = s->ext;
        f->evicted_any = 1;
    }
    s->ext = ext; s->plen = plen; s->gen = 0; memcpy(s->h, d, 16);
    if (!f->have_high || ext > f->high) { f->high = ext; f->have_high = 1; }
    return 0;
}

static void make_nonce(uint8_t n[12], int gen, uint64_t ext)
{
    memset(n, 0, 12);
    n[0] = gen;
    for (int i = 0; i < 8; i++) n[4 + i] = ext >> (56 - 8 * i);
}

/* ------------------------------------------------------------ checksums */
static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s)
{
    while (n > 1) { s += (p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) s += p[0] << 8;
    return s;
}
static uint16_t fold(uint32_t s) { while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }

static void fix_checksums(uint8_t *p, int ihl, int tot)
{
    p[10] = p[11] = 0;
    wr16(p + 10, fold(sum16(p, ihl, 0)));
    uint8_t *t = p + ihl; int tl = tot - ihl;
    t[16] = t[17] = 0;
    uint32_t s = sum16(p + 12, 8, 0) + 6 + tl;               /* pseudo header */
    wr16(t + 16, fold(sum16(t, tl, s)));
}

/* ------------------------------------------------------------ packet logic */
static uint8_t g_out[OUTBUF];

static int handle(int enc, const uint8_t *in, int len, int *outlen)
{
    *outlen = 0;
    if (len < 40 || (in[0] >> 4) != 4) return NF_DROP;
    int ihl = (in[0] & 15) * 4, tot = rd16(in + 2);
    if (ihl < 20 || tot > len || tot < ihl + 20 || in[9] != 6) return NF_DROP;
    if (rd16(in + 6) & 0x3fff) return NF_DROP;                 /* fragments: not supported */
    const uint8_t *tcp = in + ihl;
    int doff = (tcp[12] >> 4) * 4;
    if (doff < 20 || ihl + doff > tot) return NF_DROP;
    int hdr = ihl + doff, plen = tot - hdr;
    uint32_t seq = rd32(tcp + 4);
    int syn = tcp[13] & 0x02;

    struct flow *f = syn ? flow_syn(in + 12, in + 16, tcp, seq) : flow_find(in + 12, in + 16, tcp);
    if (syn && !f) return NF_DROP;
    if (plen == 0) return NF_ACCEPT;       /* SYN/ACK/FIN without data: nothing to protect */
    if (!f) { LOG("data without known connection -> drop\n"); return NF_DROP; }

    uint8_t aad[16], nonce[12];
    memcpy(aad, in + 12, 8);               /* saddr, daddr */
    memcpy(aad + 8, tcp, 8);               /* sport, dport, seq */
    uint64_t ext = extend(f->last_ext, seq - f->isn);

    memcpy(g_out, in, tot);
    if (enc) {
        if (tot + TAGLEN > 65535) return NF_DROP;
        int gen = pick_gen(f, ext, in + hdr, plen);
        if (gen < 0) { LOG("nonce uniqueness cannot be guaranteed -> drop\n"); return NF_DROP; }
        make_nonce(nonce, gen, ext);
        if (!gcm_seal(f->key, nonce, aad, 16, in + hdr, plen, g_out + hdr, g_out + hdr + plen))
            return NF_DROP;
        if (ext > f->last_ext) f->last_ext = ext;
        tot += TAGLEN;
    } else {
        int cl = plen - TAGLEN, ok = 0;
        if (cl <= 0) return NF_DROP;
        for (int g = 0; g <= MAXGEN && !ok; g++) {
            make_nonce(nonce, g, ext);
            ok = gcm_open(f->key, nonce, aad, 16, in + hdr, cl, in + hdr + cl, g_out + hdr);
        }
        if (!ok) { LOG("auth tag mismatch -> drop\n"); return NF_DROP; }
        if (ext > f->last_ext) f->last_ext = ext;
        tot -= TAGLEN;
    }
    wr16(g_out + 2, tot);
    fix_checksums(g_out, ihl, tot);
    *outlen = tot;
    return NF_ACCEPT;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *data)
{
    (void)m;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *pkt = NULL;
    int len = nfq_get_payload(nfa, &pkt), outlen = 0;
    int v = len > 0 ? handle((intptr_t)data == 0, pkt, len, &outlen) : NF_DROP;
    if (v == NF_ACCEPT && outlen > 0) return nfq_set_verdict(qh, id, NF_ACCEPT, outlen, g_out);
    return nfq_set_verdict(qh, id, v, 0, NULL);
}

/* ------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        fprintf(stderr, "usage: SECCHAN_PSK=... %s server|client <ip> <port>\n", argv[0]);
        return 2;
    }
    const char *psk = getenv("SECCHAN_PSK");
    if (!psk || !*psk) { fprintf(stderr, "set SECCHAN_PSK\n"); return 2; }
    g_verbose = getenv("SECCHAN_VERBOSE") != NULL;
    g_ctx = EVP_CIPHER_CTX_new();

    int server = !strcmp(argv[1], "server");
    int fd = control_connect(server, argv[2], atoi(argv[3]));
    if (!handshake(fd, server, psk)) { fprintf(stderr, "handshake failed\n"); return 1; }
    close(fd);
    fprintf(stderr, "session established, starting packet processing\n");

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    struct nfq_q_handle *q0 = nfq_create_queue(h, 0, cb, (void *)0);   /* encrypt */
    struct nfq_q_handle *q1 = nfq_create_queue(h, 1, cb, (void *)1);   /* decrypt */
    if (!q0 || !q1) { fprintf(stderr, "cannot bind queues (already in use? not root?)\n"); return 1; }
    nfq_set_mode(q0, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(q0, 4096);
    nfq_set_queue_maxlen(q1, 4096);

    static uint8_t rbuf[65536 + 4096];
    int nfd = nfq_fd(h);
    for (;;) {
        ssize_t r = recv(nfd, rbuf, sizeof rbuf, 0);
        if (r < 0) { if (errno == ENOBUFS || errno == EINTR) continue; perror("recv"); break; }
        nfq_handle_packet(h, (char *)rbuf, (int)r);
    }
    return 1;
}
