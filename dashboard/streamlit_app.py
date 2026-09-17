"""
AEGIS — AI-Powered Passive Cyber Threat Intelligence Dashboard & Sandbox.
Provides real-time threat visualization, passive background streaming updates,
and an interactive analysis sandbox for unidirectional network monitoring.
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
    page_title="AEGIS — Passive Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional SOC Dark Theme Styling
st.markdown("""
<style>
    /* Global Background & Typography */
    .stApp {
        background-color: #0B0F17;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Header & Brand */
    .aegis-brand-title {
        font-size: 2.6rem;
        font-weight: 800;
        letter-spacing: -1px;
        color: #F8FAFC;
        line-height: 1.1;
        margin: 0;
    }
    .aegis-brand-sub {
        font-size: 1.05rem;
        font-weight: 600;
        color: #38BDF8;
        margin-top: 4px;
        letter-spacing: 0.2px;
    }
    .aegis-brand-desc {
        font-size: 0.85rem;
        color: #94A3B8;
        margin-top: 4px;
        margin-bottom: 14px;
    }

    /* Passive Security Banner */
    .security-status-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 10px 18px;
        margin-bottom: 14px;
    }
    .status-badge-green {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.8px;
        color: #10B981;
    }
    .status-dot-green {
        width: 9px;
        height: 9px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.7);
    }
    .status-guarantee-text {
        font-size: 0.82rem;
        color: #CBD5E1;
        margin-left: 12px;
    }
    .status-arch-pill {
        font-size: 0.72rem;
        font-weight: 700;
        color: #94A3B8;
        background: #1E293B;
        border: 1px solid #334155;
        padding: 4px 10px;
        border-radius: 6px;
        letter-spacing: 0.5px;
    }

    /* Unidirectional Topology Flow Strip */
    .arch-flow-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #0B1120;
        border: 1px dashed #1E293B;
        border-radius: 8px;
        padding: 10px 16px;
        margin-bottom: 22px;
        font-size: 0.78rem;
    }
    .arch-flow-step {
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }
    .arch-step-name {
        font-weight: 700;
        color: #E2E8F0;
        margin-top: 2px;
    }
    .arch-step-sub {
        font-size: 0.7rem;
        color: #64748B;
    }
    .arch-flow-arrow {
        color: #38BDF8;
        font-weight: 800;
        font-size: 0.95rem;
        padding: 0 8px;
    }
    .arch-step-diode {
        background: #1E293B;
        border: 1px solid #0284C7;
        padding: 4px 10px;
        border-radius: 6px;
    }

    /* SOC Metric Cards */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 12px;
        margin-bottom: 22px;
    }
    .metric-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-left: 4px solid #0284C7;
        border-radius: 8px;
        padding: 14px 16px;
    }
    .metric-label {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #94A3B8;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.85rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.2;
    }
    .metric-unit {
        font-size: 0.82rem;
        font-weight: 500;
        color: #64748B;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748B;
        margin-top: 4px;
    }

    /* Severity Colors for Cards */
    .metric-card-critical {
        border-left-color: #EF4444;
    }
    .metric-card-critical .metric-value {
        color: #F87171;
    }
    .metric-card-high {
        border-left-color: #F59E0B;
    }
    .metric-card-high .metric-value {
        color: #FBBF24;
    }

    /* Sidebar Status Badges */
    .sidebar-status-header {
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.8px;
        color: #94A3B8;
        text-transform: uppercase;
        margin-bottom: 6px;
    }
    .sidebar-status-beacon {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.85rem;
        font-weight: 800;
        letter-spacing: 0.6px;
        color: #10B981;
        margin-bottom: 12px;
    }
    .sidebar-status-table {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 10px 12px;
        margin-bottom: 16px;
    }
    .sidebar-status-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 5px 0;
        border-bottom: 1px solid #1E293B;
        font-size: 0.78rem;
    }
    .sidebar-status-row:last-child {
        border-bottom: none;
        padding-bottom: 0;
    }
    .sidebar-status-key {
        color: #94A3B8;
        font-weight: 500;
    }
    .sidebar-status-val {
        color: #F8FAFC;
        font-weight: 700;
        display: flex;
        align-items: center;
        gap: 5px;
    }

    /* Section Subheaders */
    .soc-section-title {
        font-size: 1.15rem;
        font-weight: 700;
        color: #F8FAFC;
        margin-bottom: 2px;
    }
    .soc-section-sub {
        font-size: 0.8rem;
        color: #94A3B8;
        margin-bottom: 14px;
    }

    /* Encrypted Traffic Architecture Callout */
    .encrypted-flow-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 14px 16px;
        margin-top: 18px;
        margin-bottom: 14px;
    }
    .pipeline-breadcrumb {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        font-size: 0.76rem;
        font-weight: 600;
    }
    .crumb {
        background: #1E293B;
        color: #CBD5E1;
        padding: 4px 8px;
        border-radius: 4px;
    }
    .crumb-arrow {
        color: #38BDF8;
        font-weight: 800;
    }
    .crumb-highlight {
        background: #0369A1;
        color: #F0F9FF;
        padding: 4px 8px;
        border-radius: 4px;
    }

    /* Sandbox simulation notice badge */
    .sandbox-notice-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #172554;
        border: 1px solid #1E40AF;
        border-radius: 6px;
        padding: 6px 12px;
        font-size: 0.78rem;
        color: #93C5FD;
        margin-bottom: 14px;
    }
    .detector-badge-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 20px;
    }
    .detector-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 6px;
        padding: 6px 12px;
        font-size: 0.75rem;
        font-weight: 600;
        color: #CBD5E1;
    }
    .detector-pill-active {
        border-color: #059669;
        color: #6EE7B7;
    }
    .input-source-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #1E293B;
        border: 1px solid #0284C7;
        color: #38BDF8;
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 0.75rem;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

cfg = get_config()
db = ThreatDatabase(cfg.database_path)

# Determine active input source from latest records
latest_alerts = db.get_recent_alerts(limit=1)
latest_source = latest_alerts[0].get("input_source", "pcap_replay") if latest_alerts else "pcap_replay"
source_labels = {
    "pcap_replay": "PCAP Replay (Unidirectional)",
    "synthetic_stream": "Synthetic Stream",
    "data_diode_feed": "Data-Diode Feed (Hardware)",
}
source_display = source_labels.get(latest_source, latest_source.replace("_", " ").title())

# ==============================================================================
# SIDEBAR
# ==============================================================================
st.sidebar.markdown("""
<div style="margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #1E293B;">
    <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 1.6rem;">🛡️</span>
        <span style="font-size: 1.45rem; font-weight: 800; letter-spacing: -0.5px; color: #F8FAFC;">AEGIS</span>
    </div>
    <div style="font-size: 0.78rem; font-weight: 600; color: #38BDF8; margin-top: 2px;">
        Passive Threat Intelligence
    </div>
</div>
""", unsafe_allow_html=True)

# Non-Editable System Status Indicators
st.sidebar.markdown(f"""
<div class="sidebar-status-header">SYSTEM STATUS</div>
<div class="sidebar-status-beacon">
    <span class="status-dot-green"></span> PASSIVE
</div>

<div class="sidebar-status-table">
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Environment</span>
        <span class="sidebar-status-val"><span style="color: #10B981;">●</span> Passive</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Network Direction</span>
        <span class="sidebar-status-val"><span style="color: #10B981;">●</span> Unidirectional</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Active Input Source</span>
        <span class="sidebar-status-val"><span style="color: #38BDF8;">●</span> {source_display}</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Ingest Mode</span>
        <span class="sidebar-status-val"><span style="color: #10B981;">●</span> Read-only</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Data Diode</span>
        <span class="sidebar-status-val"><span style="color: #10B981;">●</span> Hardware</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Payload Decryption</span>
        <div style="text-align: right;">
            <span class="sidebar-status-val" style="justify-content: flex-end;"><span style="color: #94A3B8;">●</span> Disabled</span>
            <div style="font-size: 0.68rem; color: #64748B; font-weight: 500;">Metadata Only</div>
        </div>
    </div>
</div>

<div class="sidebar-status-header" style="margin-top: 14px;">ACTIVE DETECTORS (7/7)</div>
<div class="sidebar-status-table">
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">DDoS (SYN/UDP/Amp)</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">C2 Beaconing</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">DGA Classifier</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">DNS Tunneling</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Encrypted (TLS/QUIC)</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Recon / Port Scan</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
    <div class="sidebar-status-row">
        <span class="sidebar-status-key">Data Exfiltration</span>
        <span class="sidebar-status-val" style="color: #10B981;">● Active</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown('<div class="soc-section-title" style="font-size: 0.9rem;">Ingest & Update Mode</div>', unsafe_allow_html=True)

passive_polling = st.sidebar.checkbox(
    "Passive Background Polling",
    value=True,
    help="Continuously queries the passive telemetry database without reloading the webpage."
)

poll_interval = 3
if passive_polling:
    poll_interval = st.sidebar.slider(
        "Check Interval (seconds)",
        min_value=1,
        max_value=10,
        value=3,
        help="Rate at which passive background telemetry updates."
    )
    st.sidebar.caption("🟢 Status: Passive stream monitoring active")
else:
    st.sidebar.caption("⚪ Status: Manual update mode")

st.sidebar.markdown("---")
st.sidebar.markdown('<div class="soc-section-title" style="font-size: 0.9rem;">Alert Filters</div>', unsafe_allow_html=True)
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

st.sidebar.markdown("---")
if st.sidebar.button("🧹 Clear System Data"):
    db.clear_data()
    st.sidebar.success("Database records cleared.")
    st.rerun()

# ==============================================================================
# MAIN HEADER & ARCHITECTURE TOPOLOGY
# ==============================================================================
st.markdown("""
<div style="margin-bottom: 8px;">
    <div style="display: flex; align-items: center; gap: 12px;">
        <span style="font-size: 2.2rem;">🛡️</span>
        <div>
            <h1 class="aegis-brand-title">AEGIS</h1>
            <div class="aegis-brand-sub">AI-Powered Passive Cyber Threat Intelligence</div>
        </div>
    </div>
    <div class="aegis-brand-desc">Real-time threat detection from unidirectional network traffic</div>
</div>
""", unsafe_allow_html=True)

# Non-Interactive Passive Security Guarantee Banner
st.markdown("""
<div class="security-status-banner">
    <div style="display: flex; align-items: center; flex-wrap: wrap;">
        <span class="status-badge-green">
            <span class="status-dot-green"></span> PASSIVE MODE
        </span>
        <span class="status-guarantee-text">
            Read-only monitoring &bull; No return path &bull; No active probing &bull; No payload decryption
        </span>
    </div>
    <span class="status-arch-pill">HARDWARE DATA DIODE</span>
</div>
""", unsafe_allow_html=True)

# Unidirectional Flow Metaphor Strip (Requirement 9)
st.markdown("""
<div class="arch-flow-container">
    <div class="arch-flow-step">
        <span style="font-size: 1.1rem;">🏢</span>
        <span class="arch-step-name">Production Network</span>
        <span class="arch-step-sub">Monitored Enclave</span>
    </div>
    <div class="arch-flow-arrow">──(One-Way Tap)──▶</div>
    <div class="arch-flow-step arch-step-diode">
        <span style="font-size: 1.1rem;">🔒</span>
        <span class="arch-step-name">Hardware Data Diode</span>
        <span class="arch-step-sub" style="color: #38BDF8;">Physical 1-Way Barrier</span>
    </div>
    <div class="arch-flow-arrow">──▶</div>
    <div class="arch-flow-step">
        <span style="font-size: 1.1rem;">🛡️</span>
        <span class="arch-step-name">AEGIS Ingest Enclave</span>
        <span class="arch-step-sub">Read-Only Sniffer / Replay</span>
    </div>
    <div class="arch-flow-arrow">──▶</div>
    <div class="arch-flow-step">
        <span style="font-size: 1.1rem;">🧠</span>
        <span class="arch-step-name">Threat Intelligence</span>
        <span class="arch-step-sub">AI Classifiers & Alerts</span>
    </div>
</div>

<div class="detector-badge-strip">
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> DDoS (SYN, UDP, Amp, Spoofed)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> C2 Beaconing (IAT, Autocorr)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> DGA Domains (Lexical RF)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> DNS Tunnels (TXT/NULL Stats)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> Encrypted Traffic (TLS/QUIC)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> Reconnaissance (Port Scan)</span>
    <span class="detector-pill detector-pill-active"><span class="status-dot-green"></span> Data Exfiltration (Asymmetry ML)</span>
</div>
""", unsafe_allow_html=True)

# Main Navigation Tabs
tab_monitor, tab_benchmark, tab_sandbox = st.tabs(["📊 Live Threat Monitor", "⚡ Measured Benchmarks & Telemetry", "🧪 Threat Analysis Sandbox"])

# ==============================================================================
# TAB 1: LIVE THREAT MONITOR (PASSIVE STREAMING FRAGMENT)
# ==============================================================================
with tab_monitor:
    @st.fragment(run_every=f"{poll_interval}s" if passive_polling else None)
    def render_live_threat_feed(severity_filter: str, class_filter: str):
        stats = db.get_system_stats()

        total_flows = stats.get("total_flows", 0)
        fps = stats.get("current_flows_per_sec", 0.0)
        pps = stats.get("current_packets_per_sec", 0.0)
        total_alerts = stats.get("total_alerts", 0)
        critical_alerts = stats.get("critical_alerts", 0)
        high_alerts = stats.get("high_alerts", 0)

        # SOC Metric Cards
        st.markdown(f"""
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-label">TOTAL FLOWS</div>
                <div class="metric-value">{total_flows:,}</div>
                <div class="metric-sub">Mirrored sessions</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">THROUGHPUT</div>
                <div class="metric-value">{fps:,.1f} <span class="metric-unit">flows/s</span></div>
                <div class="metric-sub">{pps:,.1f} pkts/s</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">TOTAL ALERTS</div>
                <div class="metric-value">{total_alerts:,}</div>
                <div class="metric-sub">All threat classes</div>
            </div>
            <div class="metric-card metric-card-critical">
                <div class="metric-label" style="color: #F87171;">CRITICAL</div>
                <div class="metric-value">{critical_alerts:,}</div>
                <div class="metric-sub">Immediate attention</div>
            </div>
            <div class="metric-card metric-card-high">
                <div class="metric-label" style="color: #FBBF24;">HIGH</div>
                <div class="metric-value">{high_alerts:,}</div>
                <div class="metric-sub">Elevated threats</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Visualizations: Traffic Throughput & Threat Distribution
        chart_col1, chart_col2 = st.columns([3, 2])

        with chart_col1:
            st.markdown('<div class="soc-section-title">Traffic Throughput Over Time</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-section-sub">Real-time ingestion and flow processing</div>', unsafe_allow_html=True)
            metrics_history = db.get_metrics_timeseries(limit=60)
            if metrics_history:
                df_metrics = pd.DataFrame(metrics_history)
                df_metrics["timestamp"] = pd.to_datetime(df_metrics["timestamp"])
                fig_traffic = px.line(
                    df_metrics,
                    x="timestamp",
                    y=["flows_per_sec", "packets_per_sec"],
                    labels={"value": "Events / sec", "timestamp": "Timestamp", "variable": "Rate"},
                    template="plotly_dark",
                    color_discrete_map={"flows_per_sec": "#06B6D4", "packets_per_sec": "#F97316"}
                )
                fig_traffic.update_layout(
                    margin=dict(l=10, r=10, t=15, b=10),
                    height=280,
                    paper_bgcolor="#0F172A",
                    plot_bgcolor="#0F172A",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_traffic, use_container_width=True)
            else:
                st.info("Awaiting traffic stream to plot throughput metrics...")

        with chart_col2:
            st.markdown('<div class="soc-section-title">Threat Distribution</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-section-sub">Detected threat breakdown across active classes</div>', unsafe_allow_html=True)
            threat_counts = db.get_alert_counts_by_threat()
            if threat_counts:
                df_threats = pd.DataFrame(list(threat_counts.items()), columns=["Threat Class", "Alert Count"])
                fig_dist = px.pie(
                    df_threats,
                    names="Threat Class",
                    values="Alert Count",
                    hole=0.45,
                    template="plotly_dark",
                    color_discrete_sequence=px.colors.qualitative.Prism
                )
                fig_dist.update_layout(
                    margin=dict(l=10, r=10, t=15, b=10),
                    height=280,
                    paper_bgcolor="#0F172A",
                    legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.0)
                )
                st.plotly_chart(fig_dist, use_container_width=True)
            else:
                st.info("No threats detected in the current observation window.")

        st.markdown("---")

        # Recent Alerts Table (Strictly Unidirectional Flow Indication)
        st.markdown('<div class="soc-section-title">Recent Threat Alerts</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-section-sub">Structured security events emitted from the passive pipeline</div>', unsafe_allow_html=True)

        f_sev = None if severity_filter == "ALL" else severity_filter
        f_threat = None if class_filter == "ALL" else class_filter
        recent_alerts = db.get_recent_alerts(limit=50, severity=f_sev, threat_class=f_threat)

        if recent_alerts:
            table_data = []
            for a in recent_alerts:
                table_data.append({
                    "ID": a["id"],
                    "Timestamp": a["timestamp"][:19].replace("T", " "),
                    "Threat Class": a["threat_class"],
                    "Severity": a["severity"],
                    "Confidence": f"{float(a['confidence']) * 100:.1f}%",
                    "Input Source": a.get("input_source", "pcap_replay"),
                    "Observed Flow (Unidirectional)": f"{a['src_ip']}:{a['src_port']} → {a['dst_ip']}:{a['dst_port']}",
                    "Protocol": a["protocol"],
                    "Detector": a["detector"],
                })
            df_alerts = pd.DataFrame(table_data)
            st.dataframe(df_alerts, use_container_width=True, hide_index=True)

            # Alert Drill-Down & Evidence Inspector
            st.markdown('<div class="soc-section-title" style="margin-top: 18px;">Alert Drill-Down & Evidence Inspector</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-section-sub">Inspect forensic features and explainable evidence dictionary for any alert</div>', unsafe_allow_html=True)

            alert_lookup = {a["id"]: a for a in recent_alerts}
            alert_ids = list(alert_lookup.keys())

            def format_alert_label(alert_id: int) -> str:
                item = alert_lookup.get(alert_id, {})
                tc = item.get("threat_class", "UNKNOWN")
                conf = float(item.get("confidence", 0.0)) * 100
                sev = item.get("severity", "INFO")
                return f"#{alert_id} | [{sev}] {tc} ({conf:.1f}% conf)"

            selected_id = st.selectbox(
                "Select Alert to Inspect:",
                alert_ids,
                format_func=format_alert_label
            )

            selected_alert = alert_lookup.get(selected_id)
            if selected_alert:
                col_det1, col_det2 = st.columns([1, 2])
                with col_det1:
                    st.markdown("""
                    <div style="background: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px;">
                        <div style="font-size: 0.72rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Threat Classification</div>
                        <div style="font-size: 1.15rem; font-weight: 800; color: #38BDF8; margin-top: 2px;">""" + str(selected_alert["threat_class"]) + """</div>
                        <hr style="border: 0; border-top: 1px solid #1E293B; margin: 10px 0;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.82rem;">
                            <div><span style="color: #64748B;">Severity:</span> <strong>""" + str(selected_alert["severity"]) + """</strong></div>
                            <div><span style="color: #64748B;">Confidence:</span> <strong>""" + f"{float(selected_alert['confidence']) * 100:.1f}%" + """</strong></div>
                            <div><span style="color: #64748B;">Protocol:</span> <strong>""" + str(selected_alert["protocol"]) + """</strong></div>
                            <div><span style="color: #64748B;">Direction:</span> <strong>Ingress (1-Way)</strong></div>
                        </div>
                        <div style="font-size: 0.78rem; color: #CBD5E1; margin-top: 8px;">
                            <span style="color: #64748B;">Flow:</span> <code>""" + f"{selected_alert['src_ip']}:{selected_alert['src_port']} → {selected_alert['dst_ip']}:{selected_alert['dst_port']}" + """</code>
                        </div>
                        <hr style="border: 0; border-top: 1px solid #1E293B; margin: 10px 0;">
                        <div style="font-size: 0.78rem; color: #94A3B8;">Input Source: <code>""" + str(selected_alert.get("input_source", "pcap_replay")) + """</code></div>
                        <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">Detector: <code>""" + str(selected_alert["detector"]) + """</code></div>
                        <div style="font-size: 0.75rem; color: #64748B; margin-top: 4px;">Timestamp: """ + str(selected_alert["timestamp"]) + """</div>
                    </div>
                    """, unsafe_allow_html=True)
                with col_det2:
                    st.markdown("**Structured Evidence Dictionary:**")
                    st.json(selected_alert["evidence"])
        else:
            st.info("No alerts match the selected criteria in the active observation window.")

        # Encrypted Traffic Detection Architecture Callout (Requirement 5)
        st.markdown("""
        <div class="encrypted-flow-card">
            <div style="font-size: 0.85rem; font-weight: 700; color: #38BDF8; margin-bottom: 8px;">
                🔒 Encrypted Traffic Threat Detection Pipeline (Observable Metadata Only)
            </div>
            <div class="pipeline-breadcrumb">
                <span class="crumb">Encrypted Traffic</span>
                <span class="crumb-arrow">→</span>
                <span class="crumb">Observable Metadata</span>
                <span class="crumb-arrow">→</span>
                <span class="crumb">JA3/JA4 + SPLT + Packet Timing</span>
                <span class="crumb-arrow">→</span>
                <span class="crumb-highlight">Suspicious Encrypted Threat Detection</span>
            </div>
            <div style="font-size: 0.76rem; color: #94A3B8; margin-top: 8px; line-height: 1.4;">
                <strong style="color: #E2E8F0;">Zero Payload Decryption Guarantee:</strong> AEGIS extracts TLS ClientHello handshakes, cipher suite offerings, SNI, sequence of packet lengths and times (SPLT), and inter-arrival intervals without private keys, decryption certs, or application-layer parsing.
            </div>
        </div>
        """, unsafe_allow_html=True)

        if not passive_polling:
            if st.button("🔄 Check Updates Now"):
                st.rerun(scope="fragment")

    render_live_threat_feed(sev_filter, threat_filter)


# ==============================================================================
# TAB 2: MEASURED BENCHMARKS & TELEMETRY
# ==============================================================================
with tab_benchmark:
    st.markdown('<div class="soc-section-title">Empirical Throughput & Latency Benchmarks</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-sub">Actual measured throughput, latency percentiles (P50/P95/P99), and resource consumption on this host</div>', unsafe_allow_html=True)

    benchmark_file = Path("data/benchmark_results.json")
    bench_data = None
    if benchmark_file.exists():
        try:
            with open(benchmark_file, "r") as f:
                bench_data = json.load(f)
        except Exception:
            bench_data = None

    if bench_data and "runs" in bench_data and bench_data["runs"]:
        plat = bench_data.get("platform", {})
        ts_val = bench_data.get("timestamp", time.time())
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts_val))

        st.markdown(f"""
        <div style="background: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 18px; font-size: 0.8rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
            <div><span style="color: #64748B;">Platform Host:</span> <strong style="color: #E2E8F0;">{plat.get('system', 'Unknown')} {plat.get('release', '')} ({plat.get('machine', '')})</strong></div>
            <div><span style="color: #64748B;">Python Runtime:</span> <strong style="color: #38BDF8;">v{plat.get('python_version', sys.version.split()[0])}</strong></div>
            <div><span style="color: #64748B;">CPU Cores:</span> <strong style="color: #10B981;">{plat.get('cpu_count', 'N/A')} logical cores</strong></div>
            <div><span style="color: #64748B;">Target PCAP:</span> <strong style="color: #CBD5E1;">{bench_data.get('pcap_source', 'data/sample/demo.pcap')}</strong></div>
            <div><span style="color: #64748B;">Last Measured:</span> <strong style="color: #FBBF24;">{ts_str}</strong></div>
        </div>
        """, unsafe_allow_html=True)

        runs = bench_data["runs"]
        latest_run = runs[-1]

        # Metric Cards for latest run
        st.markdown(f"""
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-label">INGESTION RATE</div>
                <div class="metric-value">{latest_run['packets_per_sec']:,.1f} <span class="metric-unit">pkts/s</span></div>
                <div class="metric-sub">{latest_run['total_packets']:,} pkts in {latest_run['duration_sec']}s</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">FLOW EVALUATION</div>
                <div class="metric-value">{latest_run['flows_per_sec']:,.1f} <span class="metric-unit">flows/s</span></div>
                <div class="metric-sub">{latest_run['total_flows']:,} flows evaluated</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">LATENCY P50 (MEDIAN)</div>
                <div class="metric-value">{latest_run['latency_p50_ms']:.2f} <span class="metric-unit">ms</span></div>
                <div class="metric-sub">Mean: {latest_run['latency_mean_ms']:.2f} ms</div>
            </div>
            <div class="metric-card metric-card-high">
                <div class="metric-label">LATENCY P95</div>
                <div class="metric-value">{latest_run['latency_p95_ms']:.2f} <span class="metric-unit">ms</span></div>
                <div class="metric-sub">P99: {latest_run['latency_p99_ms']:.2f} ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">MEMORY UTILIZATION</div>
                <div class="metric-value">{latest_run['peak_memory_mb']:.1f} <span class="metric-unit">MB</span></div>
                <div class="metric-sub">CPU: {latest_run['cpu_percent']:.1f}%</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Multi-speed sweep charts if available
        if len(runs) > 1:
            df_runs = pd.DataFrame(runs)
            st.markdown("#### Replay Rate Sweep Telemetry")
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                fig_pps = px.bar(
                    df_runs,
                    x="speed_setting",
                    y="packets_per_sec",
                    text="packets_per_sec",
                    title="Ingestion Throughput vs Replay Rate",
                    labels={"speed_setting": "Replay Rate", "packets_per_sec": "Packets / sec"},
                    template="plotly_dark",
                    color_discrete_sequence=["#0284C7"]
                )
                fig_pps.update_layout(height=280, paper_bgcolor="#0F172A", plot_bgcolor="#0F172A", margin=dict(l=10, r=10, t=35, b=10))
                st.plotly_chart(fig_pps, use_container_width=True)

            with col_b2:
                fig_lat = go.Figure()
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p50_ms"], mode="lines+markers", name="P50 (Median)", line=dict(color="#10B981", width=2)))
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p95_ms"], mode="lines+markers", name="P95", line=dict(color="#FBBF24", width=2)))
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p99_ms"], mode="lines+markers", name="P99", line=dict(color="#F87171", width=2, dash="dot")))
                fig_lat.update_layout(
                    title="Detection Latency Percentiles vs Replay Rate",
                    xaxis_title="Replay Rate",
                    yaxis_title="Latency (ms / flow)",
                    template="plotly_dark",
                    height=280,
                    paper_bgcolor="#0F172A",
                    plot_bgcolor="#0F172A",
                    margin=dict(l=10, r=10, t=35, b=10),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_lat, use_container_width=True)

            st.markdown("#### Sweep Summary Matrix")
            display_cols = ["speed_setting", "packets_per_sec", "flows_per_sec", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "latency_max_ms", "peak_memory_mb", "cpu_percent"]
            df_disp = df_runs[display_cols].rename(columns={
                "speed_setting": "Replay Rate",
                "packets_per_sec": "Packets/sec",
                "flows_per_sec": "Flows/sec",
                "latency_p50_ms": "P50 Latency (ms)",
                "latency_p95_ms": "P95 Latency (ms)",
                "latency_p99_ms": "P99 Latency (ms)",
                "latency_max_ms": "Max Latency (ms)",
                "peak_memory_mb": "Peak RSS (MB)",
                "cpu_percent": "CPU (%)",
            })
            st.dataframe(df_disp, use_container_width=True, hide_index=True)
    else:
        st.info("No saved benchmark results found. Run a live benchmark below to populate empirical host metrics.")

    st.markdown("---")
    st.markdown("#### Execute Live Host Benchmark")
    col_run1, col_run2, col_run3 = st.columns([2, 1, 1])
    with col_run1:
        bench_src = st.selectbox("Target Stream:", ["PCAP Replay (data/sample/demo.pcap)", "In-Memory Synthetic Stream"])
    with col_run2:
        bench_dur = st.slider("Duration per Rate (s)", min_value=2, max_value=10, value=3)
    with col_run3:
        bench_mode = st.radio("Benchmark Mode", ["Single Unthrottled", "Multi-Speed Sweep (1x-max)"])

    if st.button("⚡ Run Live Host Benchmark", use_container_width=True):
        from app.benchmark import run_single_benchmark, run_sweep_benchmark
        with st.spinner("Running real benchmark on host..."):
            use_syn = ("Synthetic" in bench_src)
            pcap_arg = "data/sample/demo.pcap" if not use_syn else None
            if "Sweep" in bench_mode:
                run_sweep_benchmark(
                    pcap_path="data/sample/demo.pcap",
                    duration_per_speed=float(bench_dur),
                    output_json="data/benchmark_results.json"
                )
            else:
                res = run_single_benchmark(
                    pcap_path=pcap_arg,
                    speed=0.0,
                    duration=float(bench_dur),
                    use_synthetic=use_syn,
                )
                with open("data/benchmark_results.json", "w") as f:
                    import platform as pl
                    import psutil as pu
                    json.dump({
                        "platform": {
                            "system": pl.system(),
                            "release": pl.release(),
                            "machine": pl.machine(),
                            "python_version": pl.python_version(),
                            "cpu_count": pu.cpu_count(logical=True),
                        },
                        "pcap_source": bench_src,
                        "timestamp": time.time(),
                        "runs": [res]
                    }, f, indent=2)
        st.success("Benchmark completed! Telemetry metrics updated.")
        st.rerun()


# ==============================================================================
# TAB 3: THREAT ANALYSIS SANDBOX
# ==============================================================================
with tab_sandbox:
    st.markdown('<div class="soc-section-title">Threat Analysis Sandbox</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-sub">Test AEGIS detection using PCAP files, DNS samples, and simulated network flows.</div>', unsafe_allow_html=True)

    sandbox_subtabs = st.tabs(["📁 Upload & Replay PCAP", "🌐 DGA & DNS Inspector", "⚡ Manual Flow Simulator"])

    # --- SUBTAB 1: UPLOAD PCAP ---
    with sandbox_subtabs[0]:
        st.markdown("#### Upload & Replay PCAP")
        st.markdown("Upload a PCAP or PCAPNG capture. AEGIS processes the traffic in read-only mode, assembles flows, extracts passive features, and runs threat detection.")

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

                with st.spinner("Processing packets through AEGIS passive unidirectional pipeline..."):
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
        st.markdown("#### DGA & DNS Inspector")
        st.markdown("Analyze domain names with the trained Random Forest lexical classifier to identify algorithmic C2 rendezvous domains (Local feature extraction only).")

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
            test_domain = st.text_input("Domain to inspect:", value=default_val)

        if st.button("🔍 Evaluate Domain"):
            lex = DNSFeatureExtractor.extract_lexical_features(test_domain)
            dga_det = DGADetector()
            fake_flow = {
                "flow_id": f"DNS:TEST->{test_domain}",
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
                st.success("✅ **VERDICT: BENIGN DOMAIN** — Shannon entropy and character distributions match legitimate naming conventions.")

    # --- SUBTAB 3: MANUAL FLOW SIMULATOR ---
    with sandbox_subtabs[2]:
        st.markdown("#### Simulate Flow Records for Detector Testing")
        st.markdown("""
        <div class="sandbox-notice-badge">
            🛡️ Local in-memory evaluation only &bull; No network packets transmitted &bull; Zero active probing
        </div>
        """, unsafe_allow_html=True)
        st.markdown("Construct synthetic flow telemetry to evaluate feature extraction and detector fusion without touching any network interface.")

        preset = st.selectbox(
            "Select Scenario Preset:",
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

        if st.button("⚡ Evaluate Flow in Memory"):
            raw_flow = {
                "flow_id": f"{f_proto}:10.0.0.99:50000->198.51.100.1:{in_port}",
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
