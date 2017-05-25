#!/bin/sh
ip=192.168.0.109

# flush iptables
echo 'flushing iptables...'
iptables -t nat -F
iptables -t mangle -F
iptables -F

if [ $# -eq 1 ]; then
	exit
fi

sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
iptables -t nat -A POSTROUTING -o wlp2s0b1 -j MASQUERADE

iptables -t nat -A POSTROUTING -o wlp2s0b1 -j MASQUERADE

# capture every TCP to Queue0
iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0

# capture forwarded packet (to/from specified IP) to Queue1
iptables -t mangle -A FORWARD -d ${ip} -j NFQUEUE --queue-num 1
iptables -t mangle -A FORWARD -s ${ip} -j NFQUEUE --queue-num 1

echo '==== output table ===='
iptables -L
echo '==== nat table ===='
iptables -t nat -L
echo '==== mangle table ===='
iptables -t mangle -L
