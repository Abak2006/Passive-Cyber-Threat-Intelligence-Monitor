"""
Synthetic Dataset and PCAP Generator for NTRO Cyber Threat Detection.
Generates realistic training datasets and a multi-threat demo PCAP covering all 7 threat categories.
Uses Scapy for packet construction with zero active network transmission.
"""

from pathlib import Path
import random
import time
from typing import List
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

random.seed(42)
np.random.seed(42)


def generate_training_csvs(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. DGA Dataset
    benign_domains = [
        "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
        "amazon.com", "reddit.com", "twitter.com", "instagram.com", "linkedin.com",
        "github.com", "microsoft.com", "apple.com", "netflix.com", "spotify.com",
        "cnn.com", "nytimes.com", "bbc.co.uk", "medium.com", "stackoverflow.com",
        "cloudflare.com", "dropbox.com", "salesforce.com", "wordpress.org", "adobe.com",
        "weather.com", "craigslist.org", "twitch.tv", "paypal.com", "ebay.com",
        "office.com", "bing.com", "pinterest.com", "imdb.com", "walmart.com",
        "target.com", "espn.com", "hulu.com", "zoom.us", "mozilla.org"
    ]
    # Expand benign domains
    expanded_benign = []
    for d in benign_domains:
        expanded_benign.append(d)
        parts = d.split(".")
        expanded_benign.append(f"api.{d}")
        expanded_benign.append(f"cdn.{d}")
        expanded_benign.append(f"login.{d}")
        expanded_benign.append(f"mail.{d}")
        expanded_benign.append(f"support.{d}")

    dga_samples = [
        "x7k29a8d91b4.com", "q81m2k9x7a.net", "a91kd82mx0.biz", "v8x01ll9a2.info",
        "kz891m2xaa09.org", "plq98a12xz.cc", "m19028alxzq.ru", "b8871239aa.cn",
        "cvb981249aa0.com", "zx981kllaa0.net", "198aazx9012.biz", "mnbvcxza09.info",
        "kljashd8912.top", "poiuqwer0912.xyz", "asdfghjk981.club", "zxcvbnm1209.vip",
        "qweasdzxc901.pro", "1098234alskd.site", "lkjasd091823.online", "mnbvcxz9812.fun",
        "jhgfdsa89123.tech", "poiuytre1092.space", "zxcvbasd9812.icu", "qazwsxedc901.link",
        "rfvtgbyhn109.work", "ujmikolp9812.click", "1209384lasdk.bid", "0912384lasdk.loan",
        "kjahsd89123.trade", "lzkxjchv8912.date", "qwpoieurytlkj.win", "alskdjfhgzmx.vip",
        "zmxncbvlashd.biz", "qpwoeiruty10.org", "0981234lasdk.net", "mnbvcxzasdfg.com"
    ]
    # Expand DGA samples
    expanded_dga = []
    for d in dga_samples:
        expanded_dga.append(d)
        expanded_dga.append(f"sub1.{d}")
        expanded_dga.append(f"auth.{d}")
        expanded_dga.append(f"bot.{d}")

    dga_rows = []
    for dom in expanded_benign:
        dga_rows.append({"domain": dom, "label": 0})
    for dom in expanded_dga:
        dga_rows.append({"domain": dom, "label": 1})

    df_dga = pd.DataFrame(dga_rows)
    df_dga.to_csv(output_dir / "dga_train.csv", index=False)

    # 2. DDoS Dataset
    ddos_rows = []
    # Benign flows
    for _ in range(400):
        ddos_rows.append({
            "packets_per_sec": np.random.uniform(1.0, 30.0),
            "bytes_per_sec": np.random.uniform(500.0, 50000.0),
            "syn_count": np.random.randint(1, 4),
            "ack_count": np.random.randint(5, 50),
            "syn_ack_ratio": np.random.uniform(0.01, 0.5),
            "mean_packet_size": np.random.uniform(300.0, 1400.0),
            "label": 0
        })
    # DDoS attack flows
    for _ in range(400):
        ddos_rows.append({
            "packets_per_sec": np.random.uniform(150.0, 1000.0),
            "bytes_per_sec": np.random.uniform(10000.0, 200000.0),
            "syn_count": np.random.randint(50, 500),
            "ack_count": np.random.randint(0, 2),
            "syn_ack_ratio": np.random.uniform(25.0, 500.0),
            "mean_packet_size": np.random.uniform(40.0, 90.0),
            "label": 1
        })
    pd.DataFrame(ddos_rows).to_csv(output_dir / "ddos_train.csv", index=False)

    # 3. Encrypted Anomaly Dataset
    enc_rows = []
    # Benign TLS flows
    for _ in range(350):
        enc_rows.append({
            "mean_length": np.random.uniform(400.0, 1200.0),
            "length_variance": np.random.uniform(5000.0, 50000.0),
            "outbound_inbound_ratio": np.random.uniform(0.1, 2.0),
            "periodicity": np.random.uniform(0.0, 0.4),
            "suspicious_ja3": 0,
            "has_sni": 1,
            "label": 0
        })
    # Malicious / Suspicious encrypted flows
    for _ in range(350):
        enc_rows.append({
            "mean_length": np.random.uniform(60.0, 250.0),
            "length_variance": np.random.uniform(50.0, 1200.0),
            "outbound_inbound_ratio": np.random.uniform(8.0, 30.0),
            "periodicity": np.random.uniform(0.75, 0.98),
            "suspicious_ja3": np.random.choice([0, 1], p=[0.3, 0.7]),
            "has_sni": np.random.choice([0, 1], p=[0.6, 0.4]),
            "label": 1
        })
    pd.DataFrame(enc_rows).to_csv(output_dir / "encrypted_train.csv", index=False)

    # 4. Data Exfiltration Dataset
    exf_rows = []
    # Benign downloads / uploads
    for _ in range(350):
        fwd = np.random.randint(2000, 500000)
        bwd = np.random.randint(fwd // 2, fwd * 10)
        dur = np.random.uniform(2.0, 30.0)
        exf_rows.append({
            "forward_bytes": fwd,
            "backward_bytes": bwd,
            "ratio": fwd / (bwd + 1),
            "byte_rate": fwd / dur,
            "duration": dur,
            "label": 0
        })
    # Exfiltration uploads
    for _ in range(350):
        fwd = np.random.randint(4000000, 25000000)
        bwd = np.random.randint(1000, 50000)
        dur = np.random.uniform(1.0, 10.0)
        exf_rows.append({
            "forward_bytes": fwd,
            "backward_bytes": bwd,
            "ratio": fwd / (bwd + 1),
            "byte_rate": fwd / dur,
            "duration": dur,
            "label": 1
        })
    pd.DataFrame(exf_rows).to_csv(output_dir / "exfil_train.csv", index=False)

    print(f"[+] Generated training datasets under {output_dir}")


def generate_demo_pcap(output_file: Path):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    packets: List = []
    t = 1700000000.0  # Base timestamp

    # Helper: Build raw TLS Client Hello with specific JA3 components
    def make_tls_client_hello():
        # TLS Record Header: 0x16 0x03 0x01 (Handshake, TLS 1.0 record)
        # Handshake: 0x01 (Client Hello), len, version 0x0303 (TLS 1.2), random (32 bytes)
        # Session ID (0), Ciphers (0x002f, 0x0035, 0xc013), Comp (0), Extensions
        payload = bytearray()
        payload.extend(b"\x16\x03\x01\x00\x55")  # TLS Record Header (len 85)
        payload.extend(b"\x01\x00\x00\x51")      # Handshake Client Hello (len 81)
        payload.extend(b"\x03\x03")              # Handshake Version (0x0303)
        payload.extend(b"\x00" * 32)             # Random 32 bytes
        payload.extend(b"\x00")                  # Session ID len 0
        payload.extend(b"\x00\x06\xc0\x2f\xc0\x30\x00\x9e") # Ciphers (3 ciphers)
        payload.extend(b"\x01\x00")              # Compression len 1, method 0
        payload.extend(b"\x00\x28")              # Extensions len 40
        # SNI Extension (0x0000)
        payload.extend(b"\x00\x00\x00\x0e\x00\x0c\x00\x00\x09c2.c2net.org")
        # Supported Groups (0x000a)
        payload.extend(b"\x00\x0a\x00\x04\x00\x02\x00\x1d")
        # EC Point Formats (0x000b)
        payload.extend(b"\x00\x0b\x00\x02\x01\x00")
        return bytes(payload)

    # 1. BENIGN BACKGROUND TRAFFIC (t: 0s - 3s)
    for i in range(25):
        t += 0.1
        pkt = IP(src="10.0.0.15", dst="1.1.1.1") / UDP(sport=54321 + i, dport=53) / DNS(
            id=i, qr=0, qd=DNSQR(qname="cloudflare.com", qtype="A")
        )
        pkt.time = t
        packets.append(pkt)

        t += 0.05
        # HTTP GET
        pkt_http = IP(src="10.0.0.15", dst="104.16.132.229") / TCP(sport=50000 + i, dport=80, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n")
        pkt_http.time = t
        packets.append(pkt_http)

    # 2. SYN FLOOD ATTACK (t: 4s - 6s)
    victim_ip = "10.0.0.50"
    for i in range(80):
        t += 0.02
        spoofed_src = f"172.16.1.{(i % 250) + 1}"
        pkt_syn = IP(src=spoofed_src, dst=victim_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=1000 + i)
        pkt_syn.time = t
        packets.append(pkt_syn)

    # 3. BOTNET C2 BEACONING (t: 7s - 14s)
    # Emits regular connections at intervals of exactly 1.0s to C2 server
    c2_server = "198.51.100.44"
    bot_ip = "10.0.0.15"
    for step in range(7):
        t += 1.0 + random.uniform(-0.03, 0.03)  # Low jitter (CV < 0.05)
        # 3-way handshake + small beacon payload
        syn = IP(src=bot_ip, dst=c2_server) / TCP(sport=49152 + step, dport=8443, flags="S", seq=100)
        syn.time = t
        packets.append(syn)

        t += 0.01
        ack = IP(src=bot_ip, dst=c2_server) / TCP(sport=49152 + step, dport=8443, flags="A", seq=101, ack=200)
        ack.time = t
        packets.append(ack)

        t += 0.01
        beacon_data = IP(src=bot_ip, dst=c2_server) / TCP(sport=49152 + step, dport=8443, flags="PA", seq=101, ack=200) / Raw(load=b"\x00\x01HEARTBEAT_POLL_OK\x00")
        beacon_data.time = t
        packets.append(beacon_data)

    # 4. DGA DOMAIN QUERIES (t: 15s - 17s)
    dga_list = ["x7k29a8d91b4mz09.biz", "q81m2k9x7a11v.net", "z9x02k91la09qw.info"]
    for dga in dga_list:
        t += 0.2
        dns_pkt = IP(src="10.0.0.20", dst="8.8.8.8") / UDP(sport=random.randint(30000, 60000), dport=53) / DNS(
            id=random.randint(100, 999), qr=0, qd=DNSQR(qname=dga, qtype="A")
        )
        dns_pkt.time = t
        packets.append(dns_pkt)

    # 5. DNS TUNNELLING & EXFILTRATION (t: 18s - 21s)
    # Long high-entropy subdomains and TXT record queries to apex tunnel.exfil.org
    tunnel_subdomains = [
        "a8f93e2b109c4d87e65fa31298c.tunnel.exfil.org",
        "bc901ef45a87b1c3d4e5f6a7b8c.tunnel.exfil.org",
        "9876543210fedcba9876543210f.tunnel.exfil.org",
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4.tunnel.exfil.org",
        "f0e1d2c3b4a5968778695a4b3c2.tunnel.exfil.org",
        "89abcdef0123456789abcdef012.tunnel.exfil.org",
        "c0ffee1234567890abcdef12345.tunnel.exfil.org",
        "deadbeef1234567890abcdef123.tunnel.exfil.org",
    ]
    for sub in tunnel_subdomains:
        t += 0.15
        tunnel_pkt = IP(src="10.0.0.25", dst="8.8.4.4") / UDP(sport=random.randint(30000, 60000), dport=53) / DNS(
            id=random.randint(1000, 9999), qr=0, qd=DNSQR(qname=sub, qtype="TXT")
        )
        tunnel_pkt.time = t
        packets.append(tunnel_pkt)

    # 6. SUSPICIOUS ENCRYPTED TRAFFIC (t: 22s - 25s)
    # Cobalt Strike JA3 Client Hello, small uniform packets, high outbound ratio
    tls_client_bytes = make_tls_client_hello()
    enc_dst = "203.0.113.99"
    enc_src = "10.0.0.30"
    for step in range(5):
        t += 0.5
        tls_pkt = IP(src=enc_src, dst=enc_dst) / TCP(sport=51234 + step, dport=443, flags="PA", seq=500 + step*100) / Raw(load=tls_client_bytes)
        tls_pkt.time = t
        packets.append(tls_pkt)
        # Small uniform packet bursts
        t += 0.05
        burst_pkt = IP(src=enc_src, dst=enc_dst) / TCP(sport=51234 + step, dport=443, flags="PA", seq=600 + step*100) / Raw(load=b"\x17\x03\x03\x00\x30" + b"\xaa" * 48)
        burst_pkt.time = t
        packets.append(burst_pkt)

    # 7. RECONNAISSANCE / PORT SCANNING (t: 26s - 29s)
    # 7A. Vertical Scan (many ports on one target)
    scanner_ip = "10.0.0.88"
    scan_target = "10.0.0.50"
    target_ports = [21, 22, 23, 25, 80, 135, 443, 445, 1433, 3306, 3389, 8080]
    for p in target_ports:
        t += 0.05
        scan_pkt = IP(src=scanner_ip, dst=scan_target) / TCP(sport=random.randint(40000, 60000), dport=p, flags="S", seq=random.randint(1000, 9000))
        scan_pkt.time = t
        packets.append(scan_pkt)

    # 7B. Horizontal Scan (same port across multiple hosts)
    h_scanner = "10.0.0.89"
    for host_id in range(10, 22):
        t += 0.05
        h_pkt = IP(src=h_scanner, dst=f"10.0.0.{host_id}") / TCP(sport=55555, dport=22, flags="S", seq=2000)
        h_pkt.time = t
        packets.append(h_pkt)

    # 8. DATA EXFILTRATION (t: 30s - 34s)
    # Massive outbound transfer from internal host to drop server (outbound >> inbound)
    exfil_src = "10.0.0.22"
    exfil_dst = "203.0.113.80"
    for chunk in range(25):
        t += 0.02
        bulk_data = b"CONFIDENTIAL_INTEL_PAYLOAD_CHUNK_" + (b"X" * 1350)
        exf_pkt = IP(src=exfil_src, dst=exfil_dst) / TCP(sport=44890, dport=443, flags="PA", seq=10000 + chunk * 1400, ack=50) / Raw(load=bulk_data)
        exf_pkt.time = t
        packets.append(exf_pkt)

    # Single inbound ACK to simulate extreme asymmetry (outbound:inbound byte ratio > 50:1)
    t += 0.05
    inbound_ack = IP(src=exfil_dst, dst=exfil_src) / TCP(sport=443, dport=44890, flags="A", seq=50, ack=10000 + 25 * 1400)
    inbound_ack.time = t
    packets.append(inbound_ack)

    # Write PCAP file
    wrpcap(str(output_file), packets)
    print(f"[+] Wrote {len(packets)} packets to sample PCAP: {output_file}")


def main():
    print("=" * 65)
    print("   GENERATING SYNTHETIC TRAINING DATA & SAMPLE PCAP")
    print("=" * 65)
    train_dir = Path("data/synthetic_train")
    generate_training_csvs(train_dir)

    pcap_path = Path("data/sample/demo.pcap")
    generate_demo_pcap(pcap_path)
    print("[+] Synthetic dataset & PCAP generation completed successfully.")


if __name__ == "__main__":
    main()
