#!/usr/bin/env python

from argparse import ArgumentParser
from time import localtime, strftime

from scapy.all import * # do not import from scapy.util, that rdpcap version has bugs
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import TCP, IP


class PacketSniffer():
    def __init__(self, interface, pcap_file, expression):
        self.bpf_filter = None
        self.interface = interface
        self.pcap_file = pcap_file
        self.expression = expression
        conf.resolve = []

    def read_pcap_file(self):
        packet_list = sniff(offline=self.pcap_file[0], filter=self.bpf_filter)
        for pkt in packet_list:
            if pkt.haslayer(HTTPRequest):
                print(f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} {pkt[IP].src}.{pkt[TCP].sport} -> {pkt[IP].dst}{pkt[TCP].dport} {pkt[HTTP].Host.decode("UTF-8")} {pkt[HTTP].Method.decode("UTF-8")} {pkt[HTTP].Path.decode("UTF-8")}')

    def prepare_expression(self):
        self.bpf_filter = ' '.join(self.expression)

    def sniff_interface(self):
        print("Sniffing interface " + self.interface)
        packet_list = sniff(iface=self.interface, filter=self.bpf_filter)
        print(packet_list[TCP].dst)

    def start(self):
        self.prepare_expression()
        if self.interface is not None:
            self.sniff_interface()
        elif self.pcap_file is not None:
            self.read_pcap_file()
        else:
            print('You must either provide the -i argument or -r argument. Exiting')


if __name__ == '__main__':
    parser = ArgumentParser(prog='Packet Sniffer',
                            description='Simple packet sniffer for HTTP and TLS traffic',
                            epilog="For more help contact Ameya Zope")
    # TODO: Add error handling for invalid input
    parser.add_argument('-i' , '--interface', dest='interface', nargs=1, type=str, action='store', default=None, help='Specify the network interface that needs to be sniffed')
    # TODO : Add error handling for file not found
    parser.add_argument('-r', '--read', dest='pcap_file', nargs=1, type=str, action='store', default=None, help='Specify the pcap file to read the packets from')
    parser.add_argument("expression", nargs='*', type=str, action="store", default=None, help='This is the bpf filter that will be applied to the packets captured')
    args = parser.parse_args()
    pktSniffer = PacketSniffer(args.interface, args.pcap_file, args.expression)
    pktSniffer.start()