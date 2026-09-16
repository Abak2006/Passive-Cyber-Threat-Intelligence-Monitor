"""
Replay CLI Entrypoint.
Enables running `python -m app.replay --pcap <path> --speed <float>`
"""

from app.ingest.replay import main

if __name__ == "__main__":
    main()
