@echo off
echo =========================================================
echo    NTRO PASSIVE CYBER THREAT DETECTION - LIVE DEMO
echo    Environment: Passive Monitoring Enclave (Data Diode)
echo =========================================================

echo [1/3] Resetting database...
python -c "from app.storage.database import ThreatDatabase; ThreatDatabase('data/threats.db').clear_data()"

echo [2/3] Starting Streamlit Dashboard in browser...
start cmd /k "streamlit run dashboard\streamlit_app.py"

timeout /t 3 /nobreak >nul

echo [3/3] Replaying demo PCAP (2x speed)...
echo Traffic is streaming into the passive enclave!
python -m app.replay --pcap data\sample\demo.pcap --speed 2.0

echo =========================================================
echo Demo finished. Keep dashboard open to inspect alerts.
echo =========================================================
pause
