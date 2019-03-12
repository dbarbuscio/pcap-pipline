#!/usr/bin/python
import socket
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP

from kafka import KafkaConsumer
def print_pkt(pkt):
    eth=dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        print 'Non IP Packet type not supported'
    else:
        ip = eth.data
        do_not_fragment = bool(dpkt.ip.IP_DF)
        more_fragments = bool(dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        print 'IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

consumer = KafkaConsumer('pcap_test')
for msg in consumer:
    print msg.key
    print_pkt(msg.value)
