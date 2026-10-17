#!/bin/bash
# Benign web traffic: one request every 0.2-2 s
VICTIM=${1:-172.30.0.10}
while true; do
  curl -s -o /dev/null "http://$VICTIM/"
  sleep "$(python3 -c 'import random; print(random.uniform(0.2, 2))')"
done
