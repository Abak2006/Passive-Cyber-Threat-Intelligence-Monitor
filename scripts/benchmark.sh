#!/usr/bin/env bash
set -e

echo "========================================================="
echo "   AEGIS Passive Threat Detection - Throughput Benchmark"
echo "========================================================="
python -m app.benchmark --pcap data/sample/demo.pcap --duration 30
