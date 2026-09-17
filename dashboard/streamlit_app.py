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

# Professional SOC Dark Theme: Clean, flat, minimal visual noise
st.markdown("""
<style>
    /* Global Base */
    .stApp {
        background-color: #0B0F17;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Top Header Bar */
    .aegis-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        padding-bottom: 12px;
        border-bottom: 1px solid #1E293B;
        margin-bottom: 16px;
    }
    .aegis-title-group {
        display: flex;
        flex-direction: column;
    }
    .aegis-title {
        font-size: 1.55rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #F8FAFC;
        line-height: 1.1;
        margin: 0;
    }
    .aegis-subtitle {
        font-size: 0.82rem;
        font-weight: 500;
        color: #94A3B8;
        margin-top: 3px;
    }
    .aegis-status-strip {
        display: flex;
        align-items: center;
        gap: 14px;
        font-size: 0.76rem;
        color: #94A3B8;
    }
    .status-dot-green {
        width: 7px;
        height: 7px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        margin-right: 4px;
    }

    /* Compact Metric Cards */
    .metric-grid-4 {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
        margin-bottom: 16px;
    }
    .metric-grid-5 {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 10px;
        margin-bottom: 16px;
    }
    .metric-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-left: 3px solid #0284C7;
        border-radius: 6px;
        padding: 10px 14px;
    }
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
    .metric-label {
        font-size: 0.68rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #94A3B8;
        margin-bottom: 2px;
    }
    .metric-value {
        font-size: 1.55rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.2;
    }
    .metric-sub {
        font-size: 0.70rem;
        color: #64748B;
        margin-top: 2px;
    }

    /* Section Subheaders */
    .soc-header {
        font-size: 0.95rem;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.2px;
        margin-bottom: 2px;
    }
    .soc-sub {
        font-size: 0.75rem;
        color: #64748B;
        margin-bottom: 10px;
    }

    /* Detail / Evidence Panel */
    .detail-card {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 6px;
        padding: 14px 16px;
        font-size: 0.82rem;
    }
    .detail-row {
        display: flex;
        justify-content: space-between;
        padding: 4px 0;
        border-bottom: 1px solid #1E293B;
    }
    .detail-row:last-child {
        border-bottom: none;
    }
    .detail-key {
        color: #64748B;
        font-weight: 500;
    }
    .detail-val {
        color: #E2E8F0;
        font-weight: 600;
    }

    /* Sidebar Clean Styling */
    .sidebar-brand {
        font-size: 1.25rem;
        font-weight: 800;
        color: #F8FAFC;
        letter-spacing: -0.5px;
    }
    .sidebar-sub {
        font-size: 0.74rem;
        color: #94A3B8;
        margin-bottom: 14px;
        padding-bottom: 10px;
        border-bottom: 1px solid #1E293B;
    }
    .sidebar-sec-label {
        font-size: 0.68rem;
        font-weight: 700;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin-top: 10px;
        margin-bottom: 4px;
    }
    .sidebar-item {
        font-size: 0.80rem;
        color: #CBD5E1;
        display: flex;
        align-items: center;
        margin-bottom: 3px;
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
# SIDEBAR: MINIMAL & CLEAN
# ==============================================================================
st.sidebar.markdown("""
<div class="sidebar-brand">🛡️ AEGIS</div>
<div class="sidebar-sub">AI-Powered Passive Cyber Threat Intelligence</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-sec-label">SYSTEM</div>', unsafe_allow_html=True)
st.sidebar.markdown("""
<div class="sidebar-item"><span class="status-dot-green"></span> Passive</div>
<div class="sidebar-item"><span class="status-dot-green"></span> Unidirectional</div>
<div class="sidebar-item"><span class="status-dot-green"></span> Read-only</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-sec-label">INPUT</div>', unsafe_allow_html=True)
st.sidebar.markdown(f'<div class="sidebar-item" style="color: #38BDF8; font-weight: 600;">{source_display}</div>', unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-sec-label">ARCHITECTURE</div>', unsafe_allow_html=True)
st.sidebar.markdown('<div class="sidebar-item" style="color: #94A3B8;">Hardware Data Diode Ready</div>', unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-sec-label">DETECTORS</div>', unsafe_allow_html=True)
st.sidebar.markdown('<div class="sidebar-item"><span class="status-dot-green"></span> 7 Active</div>', unsafe_allow_html=True)

with st.sidebar.expander("View Detector Status", expanded=False):
    st.markdown("""
    <div style="font-size: 0.76rem; line-height: 1.8;">
        <div><span style="color: #10B981;">●</span> DDoS (SYN, UDP, Amp, Spoofed)</div>
        <div><span style="color: #10B981;">●</span> C2 Beaconing (IAT, Autocorr)</div>
        <div><span style="color: #10B981;">●</span> DGA Domains (Lexical RF)</div>
        <div><span style="color: #10B981;">●</span> DNS Tunnels (TXT/NULL Stats)</div>
        <div><span style="color: #10B981;">●</span> Encrypted Traffic (TLS/QUIC)</div>
        <div><span style="color: #10B981;">●</span> Reconnaissance (Port Scan)</div>
        <div><span style="color: #10B981;">●</span> Data Exfiltration (Bulk & Slow-Low)</div>
    </div>
    """, unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.markdown('<div class="sidebar-sec-label">INGEST & POLLING</div>', unsafe_allow_html=True)
passive_polling = st.sidebar.checkbox(
    "Passive Background Polling",
    value=True,
    help="Polls local passive telemetry database periodically without reloading the browser."
)

poll_interval = 3
if passive_polling:
    poll_interval = st.sidebar.slider(
        "Check Interval (seconds)",
        min_value=1,
        max_value=10,
        value=3,
        help="Polling interval in seconds."
    )
    st.sidebar.caption("● Stream polling active")
else:
    st.sidebar.caption("○ Manual update mode")

st.sidebar.markdown("---")
st.sidebar.markdown('<div class="sidebar-sec-label">FILTERS</div>', unsafe_allow_html=True)
sev_filter = st.sidebar.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
threat_filter = st.sidebar.selectbox(
    "Threat Class",
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

with st.sidebar.expander("Data Maintenance", expanded=False):
    if st.button("Clear System Data", use_container_width=True):
        db.clear_data()
        st.success("Database cleared.")
        st.rerun()

# ==============================================================================
# TOP HEADER & STATUS BAR
# ==============================================================================
st.markdown("""
<div class="aegis-header">
    <div class="aegis-title-group">
        <h1 class="aegis-title">AEGIS</h1>
        <div class="aegis-subtitle">AI-Powered Passive Cyber Threat Intelligence</div>
    </div>
    <div class="aegis-status-strip">
        <span><span class="status-dot-green"></span>PASSIVE</span>
        <span><span class="status-dot-green"></span>UNIDIRECTIONAL</span>
        <span><span class="status-dot-green"></span>READ-ONLY</span>
        <span style="color: #64748B;">|</span>
        <span>PAYLOAD DECRYPTION: <strong style="color: #CBD5E1;">OFF</strong> (Metadata Only)</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Collapsible Architecture Topology
with st.expander("System Architecture (Unidirectional Physical Path)", expanded=False):
    st.markdown("""
    <div style="background: #0B1120; border: 1px dashed #1E293B; border-radius: 6px; padding: 10px 16px; font-size: 0.78rem; display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
        <div style="text-align: center;">
            <div style="font-size: 1.1rem;">🏢</div>
            <strong style="color: #E2E8F0;">Production Network</strong><br>
            <span style="color: #64748B; font-size: 0.70rem;">Monitored Enclave</span>
        </div>
        <div style="color: #38BDF8; font-weight: 700; font-size: 0.85rem;">──(Passive Tap)──▶</div>
        <div style="text-align: center; background: #1E293B; border: 1px solid #0284C7; padding: 4px 10px; border-radius: 4px;">
            <div style="font-size: 1.1rem;">🔒</div>
            <strong style="color: #E2E8F0;">Hardware Data Diode</strong><br>
            <span style="color: #38BDF8; font-size: 0.70rem;">Physical 1-Way Fiber</span>
        </div>
        <div style="color: #38BDF8; font-weight: 700; font-size: 0.85rem;">──▶</div>
        <div style="text-align: center;">
            <div style="font-size: 1.1rem;">🛡️</div>
            <strong style="color: #E2E8F0;">AEGIS Enclave</strong><br>
            <span style="color: #64748B; font-size: 0.70rem;">Read-Only Sniffer / Replay</span>
        </div>
        <div style="color: #38BDF8; font-weight: 700; font-size: 0.85rem;">──▶</div>
        <div style="text-align: center;">
            <div style="font-size: 1.1rem;">🧠</div>
            <strong style="color: #E2E8F0;">Threat Intelligence</strong><br>
            <span style="color: #64748B; font-size: 0.70rem;">AI Models & Alerts</span>
        </div>
    </div>
    <div style="font-size: 0.72rem; color: #64748B; text-align: right;">
        Note: Current interactive demo input is <code>PCAP Replay</code>. Production architecture ingests from physical optical data diode.
    </div>
    """, unsafe_allow_html=True)

# Main Clean Navigation Tabs
tab_monitor, tab_benchmark, tab_sandbox = st.tabs(["Live Monitor", "Benchmarks", "Sandbox"])

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

        st.markdown('<div class="soc-header">LIVE THREAT MONITOR</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-sub">Live passive monitoring</div>', unsafe_allow_html=True)

        # 4 Primary Flat Metric Cards
        st.markdown(f"""
        <div class="metric-grid-4">
            <div class="metric-card">
                <div class="metric-label">FLOWS</div>
                <div class="metric-value">{total_flows:,}</div>
                <div class="metric-sub">Mirrored sessions</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">THROUGHPUT</div>
                <div class="metric-value">{fps:,.1f} <span style="font-size: 0.75rem; color: #64748B; font-weight: 500;">flows/s</span></div>
                <div class="metric-sub">{pps:,.1f} pkts/s</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">ALERTS</div>
                <div class="metric-value">{total_alerts:,}</div>
                <div class="metric-sub">Total detected events</div>
            </div>
            <div class="metric-card metric-card-critical">
                <div class="metric-label" style="color: #F87171;">CRITICAL</div>
                <div class="metric-value">{critical_alerts:,}</div>
                <div class="metric-sub">High: {high_alerts:,}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Charts: Throughput & Threat Distribution
        chart_col1, chart_col2 = st.columns([3, 2])

        with chart_col1:
            st.markdown('<div class="soc-header">THREAT ACTIVITY</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-sub">Traffic throughput over time</div>', unsafe_allow_html=True)
            metrics_history = db.get_metrics_timeseries(limit=60)
            if metrics_history:
                df_metrics = pd.DataFrame(metrics_history)
                df_metrics["timestamp"] = pd.to_datetime(df_metrics["timestamp"])
                fig_traffic = px.line(
                    df_metrics,
                    x="timestamp",
                    y=["flows_per_sec", "packets_per_sec"],
                    labels={"value": "Events / sec", "timestamp": "Time", "variable": "Metric"},
                    template="plotly_dark",
                    color_discrete_map={"flows_per_sec": "#0284C7", "packets_per_sec": "#F59E0B"}
                )
                fig_traffic.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=230,
                    paper_bgcolor="#0F172A",
                    plot_bgcolor="#0F172A",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_traffic, use_container_width=True)
            else:
                st.info("Awaiting traffic stream to plot throughput metrics...")

        with chart_col2:
            st.markdown('<div class="soc-header">THREAT DISTRIBUTION</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-sub">Detected threat breakdown</div>', unsafe_allow_html=True)
            threat_counts = db.get_alert_counts_by_threat()
            if threat_counts:
                df_threats = pd.DataFrame(list(threat_counts.items()), columns=["Threat Class", "Alert Count"])
                fig_dist = px.pie(
                    df_threats,
                    names="Threat Class",
                    values="Alert Count",
                    hole=0.50,
                    template="plotly_dark",
                    color_discrete_sequence=px.colors.qualitative.Prism
                )
                fig_dist.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=230,
                    paper_bgcolor="#0F172A",
                    legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.0)
                )
                st.plotly_chart(fig_dist, use_container_width=True)
            else:
                st.info("No threats detected in the current observation window.")

        st.markdown('<div class="soc-header" style="margin-top: 14px;">RECENT ALERTS</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-sub">Recent alerts</div>', unsafe_allow_html=True)

        f_sev = None if severity_filter == "ALL" else severity_filter
        f_threat = None if class_filter == "ALL" else class_filter
        recent_alerts = db.get_recent_alerts(limit=50, severity=f_sev, threat_class=f_threat)

        if recent_alerts:
            # Streamlined 5-column Table
            table_data = []
            for a in recent_alerts:
                t_str = a["timestamp"]
                time_disp = t_str[11:19] if len(t_str) >= 19 else t_str
                table_data.append({
                    "Time": time_disp,
                    "Threat": a["threat_class"],
                    "Severity": a["severity"],
                    "Confidence": f"{float(a['confidence']) * 100:.1f}%",
                    "Flow": f"{a['src_ip']}:{a['src_port']} → {a['dst_ip']}:{a['dst_port']}",
                })
            df_alerts = pd.DataFrame(table_data)
            st.dataframe(df_alerts, use_container_width=True, hide_index=True)

            # Alert Detail / Evidence Inspector
            st.markdown('<div class="soc-header" style="margin-top: 18px;">ALERT EVIDENCE INSPECTOR</div>', unsafe_allow_html=True)
            st.markdown('<div class="soc-sub">Forensic metadata and statistical indicators</div>', unsafe_allow_html=True)

            alert_lookup = {a["id"]: a for a in recent_alerts}
            alert_ids = list(alert_lookup.keys())

            def format_alert_label(alert_id: int) -> str:
                item = alert_lookup.get(alert_id, {})
                tc = item.get("threat_class", "UNKNOWN")
                sub = item.get("evidence", {}).get("subtype", "")
                sub_label = f" [{sub}]" if sub and sub != "-" else ""
                conf = float(item.get("confidence", 0.0)) * 100
                sev = item.get("severity", "INFO")
                return f"#{alert_id} | [{sev}] {tc}{sub_label} ({conf:.1f}%)"

            selected_id = st.selectbox(
                "Select Alert:",
                alert_ids,
                format_func=format_alert_label
            )

            selected_alert = alert_lookup.get(selected_id)
            if selected_alert:
                col_det1, col_det2 = st.columns([1, 1])
                alert_ev = selected_alert.get("evidence", {})
                alert_sub = alert_ev.get("subtype", alert_ev.get("threat_subtype", "STANDARD"))

                # Left Column: Classification & Flow Context
                with col_det1:
                    st.markdown(f"""
                    <div class="detail-card">
                        <div style="font-size: 0.70rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Threat Classification</div>
                        <div style="font-size: 1.15rem; font-weight: 800; color: #38BDF8; margin: 2px 0 6px 0;">{selected_alert['threat_class']}</div>
                        <div style="margin-bottom: 10px;">
                            <span style="background: #1E293B; color: #CBD5E1; border: 1px solid #334155; padding: 2px 6px; border-radius: 4px; font-size: 0.70rem; font-weight: 600;">SUBTYPE: {alert_sub}</span>
                        </div>
                        <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val">{selected_alert['severity']}</span></div>
                        <div class="detail-row"><span class="detail-key">Confidence</span><span class="detail-val">{float(selected_alert['confidence']) * 100:.1f}%</span></div>
                        <div class="detail-row"><span class="detail-key">Protocol</span><span class="detail-val">{selected_alert['protocol']}</span></div>
                        <div class="detail-row"><span class="detail-key">Direction</span><span class="detail-val">Ingress (1-Way)</span></div>
                        <div class="detail-row"><span class="detail-key">Flow</span><span class="detail-val"><code>{selected_alert['src_ip']}:{selected_alert['src_port']} → {selected_alert['dst_ip']}:{selected_alert['dst_port']}</code></span></div>
                        <div class="detail-row"><span class="detail-key">Input Source</span><span class="detail-val"><code>{selected_alert.get('input_source', 'pcap_replay')}</code></span></div>
                        <div class="detail-row"><span class="detail-key">Detector</span><span class="detail-val"><code>{selected_alert['detector']}</code></span></div>
                        <div class="detail-row"><span class="detail-key">Timestamp</span><span class="detail-val">{selected_alert['timestamp']}</span></div>
                    </div>
                    """, unsafe_allow_html=True)

                # Right Column: Formatted Evidence & Collapsible Raw JSON
                with col_det2:
                    st.markdown("""
                    <div class="detail-card">
                        <div style="font-size: 0.70rem; color: #94A3B8; font-weight: 700; text-transform: uppercase; margin-bottom: 8px;">Forensic Evidence Summary</div>
                    """, unsafe_allow_html=True)

                    if alert_sub == "SLOW_AND_LOW":
                        st.markdown(f"""
                        <div class="detail-row"><span class="detail-key">Transfer Count</span><span class="detail-val">{alert_ev.get('transfer_count', alert_ev.get('total_transfers_in_window', '-'))}</span></div>
                        <div class="detail-row"><span class="detail-key">Cumulative Outbound</span><span class="detail-val">{int(alert_ev.get('cumulative_outbound_bytes', 0)):,} B</span></div>
                        <div class="detail-row"><span class="detail-key">Cumulative Inbound</span><span class="detail-val">{int(alert_ev.get('cumulative_inbound_bytes', alert_ev.get('cumulative_bytes_in', 0))):,} B</span></div>
                        <div class="detail-row"><span class="detail-key">Out/In Ratio</span><span class="detail-val">{alert_ev.get('outbound_inbound_ratio', alert_ev.get('cumulative_asymmetric_ratio', '-'))}x</span></div>
                        <div class="detail-row"><span class="detail-key">Destination Persistence</span><span class="detail-val">{float(alert_ev.get('destination_persistence', alert_ev.get('destination_persistence_ratio', 0.0))) * 100:.0f}%</span></div>
                        <div class="detail-row"><span class="detail-key">Mean IAT</span><span class="detail-val">{float(alert_ev.get('mean_interarrival_seconds', alert_ev.get('mean_iat_sec', 0.0))):.1f}s</span></div>
                        <div class="detail-row"><span class="detail-key">IAT CV</span><span class="detail-val">{float(alert_ev.get('iat_cv', 0.0)):.2f}</span></div>
                        <div class="detail-row"><span class="detail-key">Slow-Low Score</span><span class="detail-val">{alert_ev.get('slow_exfiltration_score', '-')}</span></div>
                        """, unsafe_allow_html=True)
                    else:
                        diag = alert_ev.get("threat_diagnosis", alert_ev.get("reason", "Anomalous traffic characteristics observed."))
                        st.markdown(f'<div style="color: #CBD5E1; font-size: 0.78rem; margin-bottom: 8px; line-height: 1.4;">{diag}</div>', unsafe_allow_html=True)
                        for k, v in list(alert_ev.items())[:6]:
                            if k not in ["threat_diagnosis", "reason", "subtype", "threat_subtype"]:
                                v_disp = f"{v:.4f}" if isinstance(v, float) else str(v)
                                k_disp = k.replace("_", " ").title()
                                st.markdown(f'<div class="detail-row"><span class="detail-key">{k_disp}</span><span class="detail-val">{v_disp}</span></div>', unsafe_allow_html=True)

                    st.markdown("</div>", unsafe_allow_html=True)

                    with st.expander("Raw Evidence", expanded=False):
                        st.json(selected_alert["evidence"])
        else:
            st.info("No alerts match the selected criteria in the active observation window.")

        # Encrypted Traffic Architecture Note
        with st.expander("How Encrypted Traffic Is Analyzed (Metadata Only)", expanded=False):
            st.markdown("""
            <div style="font-size: 0.78rem; color: #94A3B8; line-height: 1.5;">
                <strong style="color: #E2E8F0;">Zero Payload Decryption Guarantee:</strong><br>
                AEGIS analyzes encrypted traffic (TLS 1.3 and QUIC over UDP 443) strictly via observable metadata:
                <ul style="margin: 6px 0 0 16px;">
                    <li>JA3 and JA4 fingerprint hashes extracted from unencrypted ClientHello handshakes</li>
                    <li>Sequence of Packet Lengths and Times (SPLT) and inter-arrival variances</li>
                    <li>RFC 9000 unencrypted QUIC header flags (Long vs. Short headers, CID lengths)</li>
                    <li>Upload/download byte directional asymmetries</li>
                </ul>
                Zero private keys, decryption certificates, or payload inspection are required or utilized.
            </div>
            """, unsafe_allow_html=True)

        if not passive_polling:
            if st.button("Check Updates Now"):
                st.rerun(scope="fragment")

    render_live_threat_feed(sev_filter, threat_filter)


# ==============================================================================
# TAB 2: BENCHMARKS
# ==============================================================================
with tab_benchmark:
    st.markdown('<div class="soc-header">BENCHMARKS</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-sub">Measured performance on this host (PCAP replay & synthetic streams)</div>', unsafe_allow_html=True)

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
        <div style="background: #0F172A; border: 1px solid #1E293B; border-radius: 6px; padding: 8px 14px; margin-bottom: 14px; font-size: 0.76rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
            <div><span style="color: #64748B;">Platform:</span> <strong style="color: #E2E8F0;">{plat.get('system', '')} {plat.get('release', '')} ({plat.get('machine', '')})</strong></div>
            <div><span style="color: #64748B;">Python:</span> <strong style="color: #38BDF8;">v{plat.get('python_version', '')}</strong></div>
            <div><span style="color: #64748B;">CPU:</span> <strong style="color: #10B981;">{plat.get('cpu_count', 'N/A')} cores</strong></div>
            <div><span style="color: #64748B;">PCAP:</span> <strong style="color: #CBD5E1;">{bench_data.get('pcap_source', 'data/sample/demo.pcap')}</strong></div>
            <div><span style="color: #64748B;">Measured:</span> <strong style="color: #FBBF24;">{ts_str}</strong></div>
        </div>
        """, unsafe_allow_html=True)

        runs = bench_data["runs"]
        latest_run = runs[-1]

        # Compact 5-metric Grid
        st.markdown(f"""
        <div class="metric-grid-5">
            <div class="metric-card">
                <div class="metric-label">PACKETS / SEC</div>
                <div class="metric-value">{latest_run['packets_per_sec']:,.1f}</div>
                <div class="metric-sub">{latest_run['total_packets']:,} pkts ({latest_run['duration_sec']}s)</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">FLOWS / SEC</div>
                <div class="metric-value">{latest_run['flows_per_sec']:,.1f}</div>
                <div class="metric-sub">{latest_run['total_flows']:,} flows</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">P50 (MEDIAN)</div>
                <div class="metric-value">{latest_run['latency_p50_ms']:.2f} <span style="font-size: 0.75rem; color: #64748B;">ms</span></div>
                <div class="metric-sub">Mean: {latest_run['latency_mean_ms']:.2f} ms</div>
            </div>
            <div class="metric-card metric-card-high">
                <div class="metric-label">P95 LATENCY</div>
                <div class="metric-value">{latest_run['latency_p95_ms']:.2f} <span style="font-size: 0.75rem; color: #64748B;">ms</span></div>
                <div class="metric-sub">P99: {latest_run['latency_p99_ms']:.2f} ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">PEAK MEMORY</div>
                <div class="metric-value">{latest_run['peak_memory_mb']:.1f} <span style="font-size: 0.75rem; color: #64748B;">MB</span></div>
                <div class="metric-sub">CPU: {latest_run['cpu_percent']:.1f}%</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Rate sweep charts
        if len(runs) > 1:
            df_runs = pd.DataFrame(runs)
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
                fig_pps.update_layout(height=240, paper_bgcolor="#0F172A", plot_bgcolor="#0F172A", margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_pps, use_container_width=True)

            with col_b2:
                fig_lat = go.Figure()
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p50_ms"], mode="lines+markers", name="P50", line=dict(color="#10B981", width=2)))
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p95_ms"], mode="lines+markers", name="P95", line=dict(color="#FBBF24", width=2)))
                fig_lat.add_trace(go.Scatter(x=df_runs["speed_setting"], y=df_runs["latency_p99_ms"], mode="lines+markers", name="P99", line=dict(color="#F87171", width=2, dash="dot")))
                fig_lat.update_layout(
                    title="Latency Percentiles (ms / flow)",
                    xaxis_title="Replay Rate",
                    yaxis_title="Latency (ms)",
                    template="plotly_dark",
                    height=240,
                    paper_bgcolor="#0F172A",
                    plot_bgcolor="#0F172A",
                    margin=dict(l=10, r=10, t=30, b=10),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_lat, use_container_width=True)

            display_cols = ["speed_setting", "packets_per_sec", "flows_per_sec", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "latency_max_ms", "peak_memory_mb", "cpu_percent"]
            df_disp = df_runs[display_cols].rename(columns={
                "speed_setting": "Replay Rate",
                "packets_per_sec": "Packets/s",
                "flows_per_sec": "Flows/s",
                "latency_p50_ms": "P50 (ms)",
                "latency_p95_ms": "P95 (ms)",
                "latency_p99_ms": "P99 (ms)",
                "latency_max_ms": "Max (ms)",
                "peak_memory_mb": "Peak RSS (MB)",
                "cpu_percent": "CPU (%)",
            })
        st.dataframe(df_disp, use_container_width=True, hide_index=True)
    else:
        st.info("No saved benchmark results found. Run a benchmark below to populate host metrics.")

<<<<<<< Updated upstream
    # ==============================================================================
    # BEACON ADVERSARIAL ROBUSTNESS & RED-TEAM VALIDATION PANEL (AEGIS v2.2)
    # ==============================================================================
    st.markdown("---")
    st.markdown('<div class="soc-section-title">AEGIS v2.2 — Red-Team Validation & Empirical Boundary Telemetry</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-sub">Comprehensive 38-scenario evaluation of label isolation, benign hard negatives, adversarial timing escalation, cross-seed statistics, and threshold tradeoffs</div>', unsafe_allow_html=True)

    adv_beacon_file = Path("data/adversarial_beacon_results.json")
    if adv_beacon_file.exists():
        try:
            with open(adv_beacon_file, "r") as f:
                adv_results = json.load(f)

            scens = adv_results.get("scenarios", {})
            cm = adv_results.get("confusion_matrix", {})
            grp = adv_results.get("grouped_summary", {})
            cs = adv_results.get("cross_seed_summary", {})
            th_sweep = adv_results.get("threshold_sensitivity", [])

            # High-Level Metrics Strip
            col_m1, col_m2, col_m3, col_m4, col_m5, col_m6 = st.columns(6)
            col_m1.metric("Overall Recall", f"{cm.get('recall', 0.0) * 100:.1f}%", "Sensitivity")
            col_m2.metric("Precision", f"{cm.get('precision', 0.0) * 100:.1f}%", "Positive Pred")
            col_m3.metric("F1-Score", f"{cm.get('f1_score', 0.0):.4f}", "Harmonic Mean")
            col_m4.metric("False Positive Rate", f"{cm.get('fpr', 0.0) * 100:.1f}%", "Hard Negatives Included")
            col_m5.metric("ROC-AUC", f"{cm.get('roc_auc', 0.0):.4f}", "Continuous Curve")
            col_m6.metric("PR-AUC", f"{cm.get('pr_auc', 0.0):.4f}", "Avg Precision")

            # Cross Seed Statistics Callout (if available)
            if cs:
                st.markdown(f"""
                <div style="background: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 10px 16px; margin: 12px 0; font-size: 0.8rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                    <div><span style="color: #64748B;">Cross-Seed Validation:</span> <strong style="color: #E2E8F0;">Seeds {cs.get('seeds_evaluated', [])}</strong></div>
                    <div><span style="color: #64748B;">Mean Recall:</span> <strong style="color: #38BDF8;">{cs.get('recall_mean', 0.0)*100:.1f}% &plusmn; {cs.get('recall_std', 0.0)*100:.2f}%</strong></div>
                    <div><span style="color: #64748B;">Mean Precision:</span> <strong style="color: #10B981;">{cs.get('precision_mean', 0.0)*100:.1f}% &plusmn; {cs.get('precision_std', 0.0)*100:.2f}%</strong></div>
                    <div><span style="color: #64748B;">Mean FPR:</span> <strong style="color: #F87171;">{cs.get('fpr_mean', 0.0)*100:.1f}% &plusmn; {cs.get('fpr_std', 0.0)*100:.2f}%</strong></div>
                    <div><span style="color: #64748B;">Mean ROC-AUC:</span> <strong style="color: #FBBF24;">{cs.get('roc_auc_mean', 0.0):.4f} &plusmn; {cs.get('roc_auc_std', 0.0):.4f}</strong></div>
                </div>
                """, unsafe_allow_html=True)

            # Grouped Architectural Breakdown Cards
            if grp:
                st.markdown("##### Grouped Architectural Subset Performance")
                col_g1, col_g2, col_g3, col_g4, col_g5 = st.columns(5)
                col_g1.metric("Pure Timing Baseline", f"{grp.get('pure_timing_mean_recall', 0.0) * 100:.1f}%", "Scenarios A-F")
                col_g2.metric("Low & Slow Fused", f"{grp.get('low_and_slow_fused_mean_recall', 0.0) * 100:.1f}%", "Scenarios L-P")
                col_g3.metric("Jitter + Multi-Signal", f"{grp.get('random_jitter_plus_independent_signals_mean_recall', 0.0) * 100:.1f}%", "Scenarios Q-T")
                col_g4.metric("Benign Hard Neg FPR", f"{grp.get('benign_hard_negatives_mean_fpr', 0.0) * 100:.1f}%", "Scenarios U-AD")
                col_g5.metric("Adversarial Escalation", f"{grp.get('adversarial_escalation_mean_recall', 0.0) * 100:.1f}%", "Scenarios AE-AL")

            # 38-Scenario Matrix Table
            if scens:
                st.markdown("##### All 38 Evaluated Scenarios (A - AL)")
                adv_rows = []
                for k, v in scens.items():
                    stype = "ATTACK" if v["is_attack"] else "BENIGN"
                    adv_rows.append({
                        "Scenario": v["label"],
                        "Type": stype,
                        "Outcome State": v.get("outcome_state", "Evaluated"),
                        "Timing Recall": f"{v['timing_detection_rate'] * 100:.1f}%",
                        "Fused Recall": f"{v['fused_detection_rate'] * 100:.1f}%",
                        "P50 Conf": f"{v.get('fused_median_confidence', 0.0):.4f}",
                        "P95 Conf": f"{v.get('fused_p95_confidence', 0.0):.4f}",
                        "Timing Qual": f"{v.get('timing_evidence_quality', 0.0):.2f}",
                        "Protocol Score": f"{v.get('protocol_evidence_score', 0.0):.2f}",
                        "Behavior Score": f"{v.get('behavior_evidence_score', 0.0):.2f}",
                    })

                df_adv = pd.DataFrame(adv_rows)
                st.dataframe(df_adv, use_container_width=True, hide_index=True)

            # Threshold Sensitivity Table
            if th_sweep:
                st.markdown("##### Classification Decision Threshold Tradeoff Sweep")
                df_th = pd.DataFrame(th_sweep)
                df_th_disp = df_th[["threshold", "precision", "recall", "f1_score", "fpr", "tp", "fp"]].rename(columns={
                    "threshold": "Decision Threshold",
                    "precision": "Precision",
                    "recall": "Recall",
                    "f1_score": "F1-Score",
                    "fpr": "FPR",
                    "tp": "TP Count",
                    "fp": "FP Count",
                })
                st.dataframe(df_th_disp, use_container_width=True, hide_index=True)

            st.info("ℹ️ **Scientific Integrity & Boundary Mapping:** AEGIS reports empirical detection limits under extreme randomized timing (&ge;60% jitter) and benign hard negatives. Periodic benign heartbeats (e.g. NTP, database keepalives) naturally share timing features with periodic C2 and are honestly captured in the FPR telemetry. Confidence scores represent bounded evidence vectors, not uncalibrated probabilities.")
        except Exception as e:
            st.warning(f"Could not load adversarial beacon benchmark results: {e}")
    else:
        st.info("Run `python -m training.adversarial_beacon_benchmark` to populate adversarial beacon robustness telemetry.")

    with st.expander("Execute Live Host Benchmark", expanded=False):
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
    st.markdown('<div class="soc-header">THREAT ANALYSIS SANDBOX</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-sub">Local in-memory evaluation · No network packets transmitted · Zero active probing</div>', unsafe_allow_html=True)

    sandbox_subtabs = st.tabs(["PCAP Analysis", "DNS Analysis", "Flow Simulation"])

    # --- SUBTAB 1: PCAP ANALYSIS ---
    with sandbox_subtabs[0]:
        uploaded_pcap = st.file_uploader("Upload PCAP capture for offline evaluation", type=["pcap", "pcapng"])
        replay_speed = st.select_slider(
            "Replay Speed",
            options=[0.0, 1.0, 2.0, 5.0, 10.0],
            value=0.0,
            format_func=lambda x: "Maximum Throughput (Fast)" if x == 0.0 else f"{x}x Real-time"
        )

        with st.expander("Advanced Options", expanded=False):
            reset_db_option = st.checkbox("Clear existing database before analyzing", value=False)

        if uploaded_pcap is not None:
            if st.button("Analyze PCAP", type="primary"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
                    tmp_file.write(uploaded_pcap.read())
                    tmp_pcap_path = tmp_file.name

                if reset_db_option:
                    db.clear_data()

                with st.spinner("Processing through passive unidirectional pipeline..."):
                    engine = PCAPReplayEngine(
                        pcap_path=tmp_pcap_path,
                        speed=replay_speed,
                        db_path=cfg.database_path
                    )
                    t0 = time.time()
                    engine.run()
                    elapsed = max(0.001, time.time() - t0)

                st.success(f"Complete ({elapsed:.2f}s): {engine.total_packets} packets, {engine.total_flows_processed} flows, {engine.total_alerts_emitted} alerts.")
                Path(tmp_pcap_path).unlink(missing_ok=True)
                st.rerun()

    # --- SUBTAB 2: DNS ANALYSIS ---
    with sandbox_subtabs[1]:
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
            quick_pick = st.selectbox("Sample Domains:", ["(Custom)"] + sample_domains)
        with col_inp:
            default_val = quick_pick if quick_pick != "(Custom)" else "x7k29a8d91b4mz09.biz"
            test_domain = st.text_input("Domain:", value=default_val)

        if st.button("Evaluate Domain"):
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
            mcol1.metric("Entropy", f"{lex['entropy']:.3f}")
            mcol2.metric("Length", f"{lex['length']}")
            mcol3.metric("Digit %", f"{lex['digit_ratio']*100:.1f}%")
            mcol4.metric("Vowel %", f"{lex['vowel_ratio']*100:.1f}%")

            if res:
                st.error(f"Threat Detected: {res.threat_class} (Confidence: {res.confidence * 100:.1f}%, Severity: {res.severity.value})")
                with st.expander("Evidence", expanded=True):
                    st.json(res.evidence)
            else:
                st.success("Benign Domain: Lexical structure matches legitimate naming conventions.")

    # --- SUBTAB 3: FLOW SIMULATION ---
    with sandbox_subtabs[2]:
        preset = st.selectbox(
            "Scenario Preset:",
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
            in_syn = st.number_input("SYN Flags", min_value=0, max_value=5000, value=f_syn)
            in_ack = st.number_input("ACK Flags", min_value=0, max_value=5000, value=f_ack)
        with col_f2:
            in_fwd = st.number_input("Outbound Bytes", min_value=0, max_value=100_000_000, value=f_fwd_bytes)
            in_bwd = st.number_input("Inbound Bytes", min_value=0, max_value=100_000_000, value=f_bwd_bytes)
        with col_f3:
            in_dur = st.number_input("Duration (s)", min_value=0.01, max_value=1000.0, value=f_duration)
            in_port = st.number_input("Port", min_value=1, max_value=65535, value=f_dst_port)

        if st.button("Evaluate Flow in Memory"):
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
                    st.error(f"Alert Emitted: {alt.threat_class} | Severity: {alt.severity.value} | Confidence: {alt.confidence * 100:.1f}%")
                    with st.expander("Evidence Details", expanded=True):
                        st.json(alt.evidence)
            else:
                st.success("Benign Flow: Normal baseline characteristics.")
