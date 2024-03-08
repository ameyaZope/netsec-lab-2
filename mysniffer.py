#!/usr/bin/env python3

from argparse import ArgumentParser
from time import localtime, strftime

from scapy.all import *  # do not import from scapy.util, that rdpcap version has bugs
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.all import TLS, ServerName
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_SH, TLS_Ext_SupportedVersions, \
    TLS_Ext_SupportedVersion_CH
from scapy.layers.tls.handshake import TLSClientHello, TLS13ClientHello


def display_single_packet(pkt):
    TLS_VERSIONS = {
        # SSL
        0x0002: "SSL_2_0",  # 2
        0x0300: "SSL_3_0",  # 768
        # TLS:
        0x0301: "v1.0",  # 769
        0x0302: "v1.1",  # 770
        0x0303: "v1.2",  # 771
        0x0304: "v1.3",  # 772
        # DTLS
        0x0100: "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",  # 256
        0x7f10: "TLS_1_3_DRAFT_16",  # 32528
        0x7f12: "TLS_1_3_DRAFT_18",  # 32530
        0xfeff: "DTLS_1_0",  # 65279
        0xfefd: "DTLS_1_1",  # 65277
    }
    if pkt.haslayer(IP):
        if pkt.haslayer(HTTPRequest) and pkt[HTTPRequest].Method.decode() in ['GET', 'POST']:
            print()
            print(
                f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} HTTP {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {pkt[HTTP].Host.decode()} {pkt[HTTP].Method.decode()} {pkt[HTTP].Path.decode()}')
        elif pkt.haslayer(TLSClientHello) and pkt[TLSClientHello].version==771 and pkt.haslayer(TLS_Ext_SupportedVersion_CH) and 772 in pkt[TLS_Ext_SupportedVersion_CH].versions:
            if pkt.haslayer(ServerName):
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} TLS 1.3 {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {pkt[ServerName].servername.decode()}')
            else:
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} TLS 1.3 {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}')
        elif pkt.haslayer(TLSClientHello):
            if pkt.haslayer(ServerName):
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} TLS {TLS_VERSIONS[pkt[TLSClientHello].version]} {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {pkt[ServerName].servername.decode("UTF-8")}')
            else:
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(pkt.time))}.{pkt.time - int(pkt.time)} TLS {TLS_VERSIONS[pkt[TLSClientHello].version]} {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}')


def display_packets(packet_list: list):
    for pkt in packet_list:
        display_single_packet(pkt)


class PacketSniffer():
    def __init__(self, interface, pcap_file, expression):
        self.bpf_filter = None
        self.interface = interface
        self.pcap_file = pcap_file
        self.expression = expression
        conf.resolve = []

    def read_pcap_file(self):
        packet_list = sniff(offline=self.pcap_file[0], filter=self.bpf_filter)
        display_packets(packet_list)

    def prepare_expression(self):
        self.bpf_filter = ' '.join(self.expression)

    def sniff_interface(self):
        print("Sniffing interface " + self.interface[0])
        sniff(iface=self.interface[0], filter=self.bpf_filter, prn=lambda pkt: display_single_packet(pkt))

    def start(self):
        self.prepare_expression()
        if self.interface is not None:
            self.sniff_interface()
        elif self.pcap_file is not None:
            self.read_pcap_file()
        else:
            print('You must either provide the -i argument or -r argument. Check -h for help. Exiting')


if __name__ == '__main__':
    load_layer('tls')
    parser = ArgumentParser(prog='Packet Sniffer',
                            description='Simple packet sniffer for HTTP and TLS traffic',
                            epilog="You can choose either one of -i or -r options. At least one of the two options is "
                                   "compulsory. The program will terminate if both the arguments are not provided. "
                                   "For more help contact Ameya Zope")
    # TODO: Add error handling for invalid input
    parser.add_argument('-i', '--interface', dest='interface', nargs=1, type=str, action='store', default=None,
                        help='Specify the network interface that needs to be sniffed')
    # TODO : Add error handling for file not found
    parser.add_argument('-r', '--read', dest='pcap_file', nargs=1, type=str, action='store', default=None,
                        help='Specify the pcap file to read the packets from')
    parser.add_argument("expression", nargs='*', type=str, action="store", default=None,
                        help='This is the bpf filter that will be applied to the packets captured')
    args = parser.parse_args()
    pktSniffer = PacketSniffer(args.interface, args.pcap_file, args.expression)
    pktSniffer.start()
