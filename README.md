# Secure Inline Channel (AES-GCM over TCP payloads)

A Linux prototype of a secure inline channel between two devices:

```
PC1 --> Device1 ==== Device2 --> PC2
```

Device1 and Device2 intercept selected TCP/IPv4 traffic (port 5001), encrypt only the TCP payload with AES-256-GCM, and forward the modified packet directly to the peer. There is no UDP encapsulation and no custom protocol header. The original IP and TCP headers are kept, and the 16-byte authentication tag is appended to the encrypted payload.

## Files

| File | Purpose |
|---|---|
| `secchan.c` | The device program (handshake, encryption, decryption, checksums) |
| `setup_lab.sh` | Builds the test network in one Linux machine using network namespaces |

## How it works

**Lab.** Four network namespaces (`pc1`, `d1`, `d2`, `pc2`) are connected by veth pairs inside one VM. Traffic to TCP port 5001 is intercepted with iptables `NFQUEUE` (queue 0 encrypts, queue 1 decrypts). Without a running device program, the rules drop this traffic, so nothing is sent in plaintext.

**Handshake.** The devices use a separate control TCP connection that never passes through the data path. Each side sends an RFC 3526 group 14 (2048-bit) Diffie-Hellman public key and a random value. The session key is derived with HKDF-SHA256 over the DH secret and both random values. Each hello message carries an HMAC with a pre-shared key, so a man in the middle cannot silently take part in the exchange. Packet processing starts only after the handshake succeeds.

**Encryption (Device1).** The TCP payload is encrypted with AES-256-GCM and the 16-byte tag is appended. The IP total length and the IP and TCP checksums are recalculated. Packets without payload (SYN, ACK, FIN) pass through unchanged.

**Decryption (Device2).** The tag is verified, the payload is decrypted, the tag is removed, and the lengths and checksums are restored. Packets that fail verification are dropped.

**Unique nonces.** With no custom header, the receiver must rebuild the nonce from the packet itself, so it is derived from the TCP sequence number:

- Each connection has its own key, derived from the 4-tuple and the initial sequence number seen in the SYN.
- The nonce is a 1-byte generation counter plus a 64-bit extension of (TCP sequence number minus ISN).
- If TCP retransmits the same sequence number with different data, the sender increments the generation counter. If it cannot prove that a nonce is unused, it drops the packet instead of reusing the nonce.
- The receiver tries generations 0 to 7, and the GCM tag decides which one is correct.

**MTU.** The tag makes packets 16 bytes longer, so the links facing PC1 and PC2 use MTU 1480 and the link between the devices uses 1500. Offloads (GSO, TSO, checksum) are turned off because NFQUEUE needs real packets.

## Build and run (Ubuntu 24.04)

I used a Multipass VM:

```bash
multipass launch 24.04 --name lab --cpus 2 --memory 2G
multipass transfer secchan.c setup_lab.sh lab:
multipass shell lab
```

Inside the VM:

```bash
sudo apt update
sudo apt install -y build-essential libnetfilter-queue-dev libssl-dev iptables ethtool netcat-openbsd tcpdump iperf3
gcc -O2 -Wall -o secchan secchan.c -lnetfilter_queue -lnfnetlink -lcrypto
chmod +x setup_lab.sh
sudo ./setup_lab.sh
```

Open four terminals (`multipass shell lab` in each) and run, in this order:

```bash
# 1  Device2
sudo ip netns exec d2 env SECCHAN_PSK=secret SECCHAN_VERBOSE=1 ./secchan server 10.0.12.2 9000
# 2  Device1
sudo ip netns exec d1 env SECCHAN_PSK=secret SECCHAN_VERBOSE=1 ./secchan client 10.0.12.2 9000
# 3  PC2
sudo ip netns exec pc2 nc -l 5001
# 4  PC1
echo "hello secret" | sudo ip netns exec pc1 nc 10.0.2.2 5001
```

`hello secret` appears on PC2. The pre-shared key `secret` is for the demo only.

## Verifying the encryption

Capture on the link between the devices while sending a message:

```bash
sudo ip netns exec d2 tcpdump -ni v-d2a -X tcp port 5001
```

The data packet is 16 bytes longer than the original (29 bytes for a 13-byte message), the payload is unreadable, and the IP and TCP headers stay readable.

## Test results

| Test | Result |
|---|---|
| `hello secret` message | Delivered, readable on PC2 |
| Wire capture | Payload encrypted, `length 29` for a 13-byte message |
| 1000 bytes and 5000 bytes with `nc` | Delivered exactly |
| iperf3, 10 seconds | 2.53 GBytes transferred, 2.17 Gbits/sec |

iperf3 reported many TCP retransmits (about 12,000) during the throughput test. All data arrived and every packet was authenticated, but the retransmits limit speed. I did not investigate the cause.

## Limitations

- Connections must start after the session is up, because both devices need to see the SYN.
- No rekeying and no replay protection beyond what TCP provides.
- The pre-shared key authenticates the key exchange, but there is no session expiry.
- IP fragments are not supported and are dropped.
- Flow state is capped at 256 connections, and further new connections are refused until restart.
- Prototype only: not audited for production use.
