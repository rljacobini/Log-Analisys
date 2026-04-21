#!/usr/bin/env python
"""Script para ejecutar el analyzer PCAP"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcap.pcap_analyzer import main

if __name__ == "__main__":
    main()