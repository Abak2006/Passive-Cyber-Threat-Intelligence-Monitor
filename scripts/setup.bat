@echo off
echo =========================================================
echo    AEGIS Passive Threat Detection - Environment Setup
echo =========================================================

echo [1/3] Installing dependencies...
pip install -r requirements.txt

echo [2/3] Generating synthetic datasets and demo PCAP...
python -m training.generate_synthetic

echo [3/3] Training AI/ML threat detection models...
python -m training.train --detector all

echo =========================================================
echo    Setup completed successfully!
echo    Run 'scripts\run_demo.bat' to start the demo.
echo =========================================================
