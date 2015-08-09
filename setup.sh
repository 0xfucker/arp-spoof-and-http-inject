#!/bin/sh
ip=10.0.0.31

# flush iptables
iptables -t nat -F
iptables -t mangle -F
iptables -F

sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
iptables -t mangle -A FORWARD -d ${ip} -j NFQUEUE --queue-num 1
iptables -t mangle -A FORWARD -s ${ip} -j NFQUEUE --queue-num 1

echo '==== nat table ===='
iptables -t nat -L
echo '==== mangle table ===='
iptables -t mangle -L
