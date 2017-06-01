#!/bin/bash
ip="192.168.139.132"
port="80"
for i in {1..100}
do
    echo "exit" | nc ${ip} ${port}
    printf "hi"
done