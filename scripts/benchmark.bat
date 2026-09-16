@echo off
echo =========================================================
echo    NTRO Passive Threat Detection - Throughput Benchmark
echo =========================================================
python -m app.benchmark --pcap data\sample\demo.pcap --duration 30
