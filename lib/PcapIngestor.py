#!/usr/bin/python
import sys
sys.path.append('./lib')
import pcap,dpkt
from kafka import KafkaProducer
from optparse import OptionParser
import socket
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP


class PcapIngestor:
    def __init__(self,kafka_servers):
        #self.producer = KafkaProducer(bootstrap_servers='localhost:1234')
        self.producer = KafkaProducer()
        pass

    def __print_pkt(self,pkt):
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

    def __pkt_handler(self,ts,pkt):
        print ts
        self.__print_pkt(pkt)
        self.producer.send('pcap_test', key=b'%i' % ts, value=b'%s' % pkt)

    def ingest_file(self,pcap_file):
        pc = pcap.pcap(pcap_file)
        #pc.setfilter('tcp and dst port 80')
        pc.loop(self.__pkt_handler)
        #nrecv, ndrop, nifdrop = pc.stats()
        #print '\n%d packets received by filter' % nrecv
        #print '%d packets dropped by kernel' % ndrop
        pass

    def ingest_device(self,device_name,pkt_cnt=0,bpf=False):
        pc = pcap.pcap(device_name)
        if bpf:
            pc.setfilter(bpf)
        pc.loop(pkt_cnt,self.__pkt_handler)
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop
        pass

def main():
    parser = OptionParser()
    parser.add_option("-f", "--pcap_file", dest="pcap_file",
                              action="store", help = "pcap file")
    parser.add_option("-i", "--interface", dest="interface",
                              action="store", help = "interface device name")
    parser.add_option("-b", "--bpf", dest="bpf",
                              action="store", help = "berkley packet filter")
    parser.add_option("-c", "--count", dest="count",
                              action="store", help = "berkley packet filter")
    parser.add_option("-k", "--kafka-host", dest="kafka_host",
                              action="store", help = "kafka host")

    (options, args) = parser.parse_args()
    if options.kafka_host:
        if options.pcap_file:
            pi = PcapIngestor(options.kafka_host)
            pi.ingest_file(options.pcap_file)
        elif options.interface:
            pi = PcapIngestor(options.kafka_host)
            if options.count:
                count=int(options.count)
            if options.bpf:
                pi.ingest_device(options.interface,count,options.bpf)
            else:
                pi.ingest_device(options.interface,count)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

