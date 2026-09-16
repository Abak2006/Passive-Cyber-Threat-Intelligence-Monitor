"""
Streamlit Real-Time Threat Intelligence Dashboard & Interactive Threat Sandbox.
Displays live traffic rates, threat distributions, alert logs, explainable evidence inspection,
and provides an interactive testing sandbox for custom PCAPs, domains, and flows.
"""

import json
from pathlib import Path
import sys
import tempfile
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.alerts.generator import AlertPipeline
from app.config import get_config
from app.detectors.dga import DGADetector
from app.features.dns_features import DNSFeatureExtractor
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.replay import PCAPReplayEngine
from app.storage.database import ThreatDatabase

st.set_page_config(
    page_title="NTRO Cyber Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling
st.markdown("""
<style>
    .kpi-card {
        background-color: #1e2530;
        border-radius: 8px;
        padding: 16px;
        border-left: 5px solid #00ADB5;
        margin-bottom: 12px;
    }
    .badge-critical { background-color: #e53e3e; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #dd6b20; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #d69e2e; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #3182ce; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

cfg = get_config()
db = ThreatDatabase(cfg.database_path)

# Sidebar controls
st.sidebar.title("🛡️ Enclave Controls")
st.sidebar.markdown("""
**Environment**: `Passive Enclave`  
**Mode**: `Unidirectional (Read-Only)`  
**Data Diode**: `Hardware Mirror Mode`  
**Decryption**: `DISABLED (Metadata Only)`  
""")

auto_refresh = st.sidebar.checkbox("Auto-refresh live monitor (every 3s)", value=False)

st.sidebar.markdown("---")
st.sidebar.subheader("Alert Filters")
sev_filter = st.sidebar.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
threat_filter = st.sidebar.selectbox(
    "Filter by Threat Class",
    [
        "ALL",
        "SYN_FLOOD",
        "UDP_FLOOD",
        "SPOOFED_SOURCE_DDOS",
        "BOTNET_C2_BEACONING",
        "DGA_DOMAIN_DETECTION",
        "DNS_TUNNELLING",
        "SUSPICIOUS_ENCRYPTED_TRAFFIC",
        "PORT_SCAN_HORIZONTAL",
        "PORT_SCAN_VERTICAL",
        "BROAD_RECONNAISSANCE",
        "DATA_EXFILTRATION",
        "POSSIBLE_ENCRYPTED_EXFILTRATION",
        "BOTNET_C2_INFRASTRUCTURE"
    ]
)

if st.sidebar.button("🧹 Clear All Historical Data"):
    db.clear_data()
    st.sidebar.success("Database records cleared.")
    st.rerun()

# Header banner
st.title("🛡️ NTRO Passive Cyber Threat Intelligence Monitor")
st.caption("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic | National Technical Research Organisation")
st.info("🔒 **ZERO-PROBE GUARANTEE**: Strictly passive ingestion. The monitoring system has NO physical/logical return path to the production network, injects zero packets, issues zero firewall changes, and strictly forbids TLS/QUIC payload decryption.")

# Main Navigation Tabs
tab_monitor, tab_sandbox = st.tabs(["📊 Live Enclave Threat Monitor", "🧪 Interactive Sandbox & Sample Input"])

# ==============================================================================
# TAB 1: LIVE ENCLAVE THREAT MONITOR
# ==============================================================================
with tab_monitor:
    stats = db.get_system_stats()

    # KPI Metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric(label="Total Flows", value=f"{stats['total_flows']:,}")
    with col2:
        st.metric(label="Throughput (Flows/s)", value=f"{stats['current_flows_per_sec']:,.1f}")
    with col3:
        st.metric(label="Total Alerts", value=f"{stats['total_alerts']:,}")
    with col4:
        st.metric(label="Critical Threats", value=f"{stats['critical_alerts']:,}")
    with col5:
        st.metric(label="High Threats", value=f"{stats['high_alerts']:,}")

    st.markdown("---")

    # Visualizations: Traffic Throughput & Threat Distribution
    chart_col1, chart_col2 = st.columns([3, 2])

    with chart_col1:
        st.subheader("📈 Traffic Throughput Over Time")
        metrics_history = db.get_metrics_timeseries(limit=60)
        if metrics_history:
            df_metrics = pd.DataFrame(metrics_history)
            df_metrics["timestamp"] = pd.to_datetime(df_metrics["timestamp"])
            fig_traffic = px.line(
                df_metrics,
                x="timestamp",
                y=["flows_per_sec", "packets_per_sec"],
                labels={"value": "Rate (events/sec)", "timestamp": "Time", "variable": "Metric"},
                title="Real-time Ingestion & Flow Processing Rate",
                template="plotly_dark",
                color_discrete_map={"flows_per_sec": "#00ADB5", "packets_per_sec": "#FF5722"}
            )
            fig_traffic.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=300)
            st.plotly_chart(fig_traffic, use_container_width=True)
        else:
            st.info("Awaiting traffic streaming to plot throughput metrics...")

    with chart_col2:
        st.subheader("🎯 Threat Distribution")
        threat_counts = db.get_alert_counts_by_threat()
        if threat_counts:
            df_threats = pd.DataFrame(list(threat_counts.items()), columns=["Threat Class", "Alert Count"])
            fig_dist = px.pie(
                df_threats,
                names="Threat Class",
                values="Alert Count",
                hole=0.4,
                template="plotly_dark",
                color_discrete_sequence=px.colors.qualitative.Safe
            )
            fig_dist.update_layout(margin=dict(l=10, r=10, t=30, b=10), height=300)
            st.plotly_chart(fig_dist, use_container_width=True)
        else:
            st.info("No threats detected yet.")

    st.markdown("---")

    # Recent Alerts Table
    st.subheader("🚨 Recent Structured Threat Alerts")
    filt_sev = None if sev_filter == "ALL" else sev_filter
    filt_threat = None if threat_filter == "ALL" else threat_filter
    recent_alerts = db.get_recent_alerts(limit=50, severity=filt_sev, threat_class=filt_threat)

    if recent_alerts:
        table_data = []
        for a in recent_alerts:
            table_data.append({
                "ID": a["id"],
                "Timestamp": a["timestamp"][:19],
                "Threat Class": a["threat_class"],
                "Severity": a["severity"],
                "Confidence": f"{float(a['confidence']) * 100:.1f}%",
                "Source": f"{a['src_ip']}:{a['src_port']}",
                "Destination": f"{a['dst_ip']}:{a['dst_port']}",
                "Protocol": a["protocol"],
                "Detector": a["detector"],
            })
        df_alerts = pd.DataFrame(table_data)
        st.dataframe(df_alerts, use_container_width=True, hide_index=True)

        # Drill-down inspection
        st.subheader("🔍 Alert Drill-Down & Evidence Inspector")
        alert_lookup = {a["id"]: a for a in recent_alerts}
        alert_ids = list(alert_lookup.keys())

        def format_alert_label(alert_id: int) -> str:
            item = alert_lookup.get(alert_id, {})
            tc = item.get("threat_class", "UNKNOWN")
            conf = float(item.get("confidence", 0.0)) * 100
            return f"Alert #{alert_id} - {tc} (Confidence: {conf:.1f}%)"

        selected_id = st.selectbox(
            "Select Alert ID to Inspect Evidence Dictionary & Flow Details",
            alert_ids,
            format_func=format_alert_label
        )

        selected_alert = alert_lookup.get(selected_id)
        if selected_alert:
            col_det1, col_det2 = st.columns([1, 2])
            with col_det1:
                st.markdown(f"**Threat Class:** `{selected_alert['threat_class']}`")
                st.markdown(f"**Severity:** `{selected_alert['severity']}`")
                st.markdown(f"**Confidence:** `{float(selected_alert['confidence']) * 100:.2f}%`")
                st.markdown(f"**Flow ID:** `{selected_alert['flow_id']}`")
                st.markdown(f"**Detector Module:** `{selected_alert['detector']}`")
                st.markdown(f"**Timestamp:** `{selected_alert['timestamp']}`")
            with col_det2:
                st.markdown("**Structured Evidence Dictionary:**")
                st.json(selected_alert["evidence"])
    else:
        st.info("No alerts match the selected criteria.")


# ==============================================================================
# TAB 2: INTERACTIVE SANDBOX & SAMPLE INPUT
# ==============================================================================
with tab_sandbox:
    st.subheader("🧪 Interactive Threat Sandbox & Custom Sample Input")
    st.markdown("Test individual components directly: upload any custom PCAP file, test domain names against the trained DGA model, or simulate custom flow dynamics.")

    sandbox_subtabs = st.tabs(["📁 Upload Custom PCAP File", "🌐 DGA & DNS Inspector", "⚡ Manual Flow Simulator"])

    # --- SUBTAB 1: UPLOAD PCAP ---
    with sandbox_subtabs[0]:
        st.markdown("#### Upload and Replay Any PCAP File")
        st.caption("Upload a `.pcap` or `.pcapng` capture. The pipeline will ingest it in read-only mode, assemble flows, extract passive features, and run threat detection.")

        uploaded_pcap = st.file_uploader("Select PCAP file to analyze", type=["pcap", "pcapng"])
        replay_speed = st.select_slider(
            "Replay Speed Multiplier",
            options=[0.0, 1.0, 2.0, 5.0, 10.0],
            value=0.0,
            format_func=lambda x: "Maximum Throughput (Fast)" if x == 0.0 else f"{x}x Real-time"
        )
        reset_db_option = st.checkbox("Clear existing database before analyzing", value=False)

        if uploaded_pcap is not None:
            if st.button("🚀 Analyze Uploaded PCAP"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
                    tmp_file.write(uploaded_pcap.read())
                    tmp_pcap_path = tmp_file.name

                if reset_db_option:
                    db.clear_data()

                with st.spinner("Processing packets through passive unidirectional pipeline..."):
                    engine = PCAPReplayEngine(
                        pcap_path=tmp_pcap_path,
                        speed=replay_speed,
                        db_path=cfg.database_path
                    )
                    t0 = time.time()
                    engine.run()
                    elapsed = max(0.001, time.time() - t0)

                st.success(f"Analysis Complete in {elapsed:.2f}s! Processed {engine.total_packets} packets, evaluated {engine.total_flows_processed} flows, generated {engine.total_alerts_emitted} alerts.")
                Path(tmp_pcap_path).unlink(missing_ok=True)
                st.rerun()

    # --- SUBTAB 2: DGA DOMAIN TESTER ---
    with sandbox_subtabs[1]:
        st.markdown("#### Test Any Domain Name with Trained DGA Classifier")
        st.caption("Enter any benign or malicious domain to inspect lexical features and real-time Random Forest predictions.")

        sample_domains = [
            "x7k29a8d91b4mz09.biz",
            "q81m2k9x7a11v.net",
            "google.com",
            "microsoft.com",
            "github.com",
            "a8f93e2b109c4d.tunnel.attacker.org"
        ]
        col_inp, col_quick = st.columns([2, 1])
        with col_quick:
            quick_pick = st.selectbox("Quick Samples:", ["(Custom)"] + sample_domains)
        with col_inp:
            default_val = quick_pick if quick_pick != "(Custom)" else "x7k29a8d91b4mz09.biz"
            test_domain = st.text_input("Domain to analyze:", value=default_val)

        if st.button("🔍 Evaluate Domain"):
            lex = DNSFeatureExtractor.extract_lexical_features(test_domain)
            dga_det = DGADetector()
            fake_flow = {
                "flow_id": f"DNS:TEST<->{test_domain}",
                "src_ip": "10.0.0.99",
                "src_port": 53535,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "UDP",
                "dns_queries": [test_domain],
            }
            res = dga_det.predict(fake_flow)

            mcol1, mcol2, mcol3, mcol4 = st.columns(4)
            mcol1.metric("Shannon Entropy", f"{lex['entropy']:.3f} bits")
            mcol2.metric("Domain Length", f"{lex['length']} chars")
            mcol3.metric("Digit Ratio", f"{lex['digit_ratio']*100:.1f}%")
            mcol4.metric("Vowel Ratio", f"{lex['vowel_ratio']*100:.1f}%")

            if res:
                st.error(f"🚨 **VERDICT: THREAT DETECTED** — `{res.threat_class}`")
                st.markdown(f"**Confidence:** `{res.confidence * 100:.1f}%` | **Severity:** `{res.severity.value}`")
                st.json(res.evidence)
            else:
                st.success(f"✅ **VERDICT: BENIGN DOMAIN** — Shannon entropy and character distributions match legitimate naming conventions.")

    # --- SUBTAB 3: MANUAL FLOW SIMULATOR ---
    with sandbox_subtabs[2]:
        st.markdown("#### Simulate Custom Flow Parameters")
        st.caption("Construct a custom flow vector to see how specialized detectors and the Threat Fusion engine respond.")

        preset = st.selectbox(
            "Select Attack or Benign Scenario Preset:",
            [
                "Custom",
                "SYN Flood Attack (High SYN rate, 0 ACKs)",
                "Data Exfiltration (High outbound volume ratio)",
                "Benign Normal Traffic (Balanced ratios)"
            ]
        )

        f_syn = 1
        f_ack = 9
        f_fwd_bytes = 1500
        f_bwd_bytes = 1500
        f_duration = 2.0
        f_proto = "TCP"
        f_dst_port = 443

        if preset == "SYN Flood Attack (High SYN rate, 0 ACKs)":
            f_syn = 120
            f_ack = 0
            f_fwd_bytes = 7200
            f_bwd_bytes = 0
            f_duration = 1.0
            f_dst_port = 80
        elif preset == "Data Exfiltration (High outbound volume ratio)":
            f_syn = 1
            f_ack = 20
            f_fwd_bytes = 15_000_000
            f_bwd_bytes = 20_000
            f_duration = 3.0
            f_dst_port = 443

        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            in_syn = st.number_input("SYN Flags Count", min_value=0, max_value=5000, value=f_syn)
            in_ack = st.number_input("ACK Flags Count", min_value=0, max_value=5000, value=f_ack)
        with col_f2:
            in_fwd = st.number_input("Outbound Forward Bytes", min_value=0, max_value=100_000_000, value=f_fwd_bytes)
            in_bwd = st.number_input("Inbound Backward Bytes", min_value=0, max_value=100_000_000, value=f_bwd_bytes)
        with col_f3:
            in_dur = st.number_input("Flow Duration (sec)", min_value=0.01, max_value=1000.0, value=f_duration)
            in_port = st.number_input("Destination Port", min_value=1, max_value=65535, value=f_dst_port)

        if st.button("⚡ Evaluate Flow Through Pipeline"):
            raw_flow = {
                "flow_id": f"{f_proto}:10.0.0.99:50000<->198.51.100.1:{in_port}",
                "src_ip": "10.0.0.99",
                "src_port": 50000,
                "dst_ip": "198.51.100.1",
                "dst_port": in_port,
                "protocol": f_proto,
                "duration": in_dur,
                "forward_packets": in_syn + 5,
                "backward_packets": in_ack,
                "forward_bytes": in_fwd,
                "backward_bytes": in_bwd,
                "syn_count": in_syn,
                "ack_count": in_ack,
                "packet_lengths": [100] * 10,
                "timestamps": [float(i) for i in range(10)],
            }
            features = FlowFeatureExtractor.extract_features(raw_flow)
            pipeline = AlertPipeline(db=db)
            alerts = pipeline.process_flow(features)

            if alerts:
                for alt in alerts:
                    st.error(f"🚨 **ALERT EMITTED**: `{alt.threat_class}` | Severity: `{alt.severity.value}` | Confidence: `{alt.confidence * 100:.1f}%`")
                    st.markdown(f"**Detector**: `{alt.detector}`")
                    st.json(alt.evidence)
            else:
                st.success("✅ **FLOW CLASSIFIED AS BENIGN**: No threat thresholds exceeded and ML anomaly models scored within normal baselines.")

# Auto-refresh loop
if auto_refresh:
    time.sleep(3)
    st.rerun()
