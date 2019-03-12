#!/usr/bin/python
import socket
import struct
from kafka import KafkaProducer
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP


HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50051              # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
producer = KafkaProducer()
while 1:
    conn, addr = s.accept()
    cf = conn.makefile("r",0)
    print 'Connected by', addr
    pcap=dpkt.pcap.Reader(cf)
    for ts,pkt in pcap:
        producer.send('pcap_test', key=b'%i' % ts, value=b'%s' % pkt)
        eth=dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported'
            continue

        ip = eth.data
        do_not_fragment = bool(dpkt.ip.IP_DF)
        more_fragments = bool(dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        print 'IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
    cf.close()

s.close()
