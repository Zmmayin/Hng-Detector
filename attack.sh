#!/bin/bash

for i in $(seq 1 2000); do
    curl -s http://52.23.154.241:80 > /dev/null &
done
wait
