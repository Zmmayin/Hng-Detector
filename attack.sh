#!/bin/bash

for i in $(seq 1 2000); do
    curl -s http://hng-detector.duckdns.org/:80 > /dev/null &
done
wait
