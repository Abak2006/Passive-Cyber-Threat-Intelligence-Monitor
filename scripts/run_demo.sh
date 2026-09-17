#!/usr/bin/env bash
set -e

echo "========================================================="
echo "   AEGIS PASSIVE CYBER THREAT DETECTION - LIVE DEMO"
echo "   Environment: Passive Monitoring Enclave (Data Diode)"
echo "========================================================="

echo "[1/3] Resetting database..."
python -c "from app.storage.database import ThreatDatabase; ThreatDatabase('data/threats.db').clear_data()"

echo "[2/3] Starting Streamlit Dashboard in background..."
streamlit run dashboard/streamlit_app.py --server.headless true &
STREAMLIT_PID=$!

sleep 3

echo "[3/3] Replaying demo PCAP into passive enclave..."
python -m app.replay --pcap data/sample/demo.pcap --speed 2.0

echo "========================================================="
echo "Demo replay finished! Press Ctrl+C to terminate dashboard."
echo "========================================================="
wait $STREAMLIT_PID
