#!/usr/bin/env python3

from argparse import ArgumentParser
from time import localtime, strftime

from scapy.all import *  # do not import from scapy.util, that rdpcap version has bugs
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.all import TLS, ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.all import conf


def get_interface(interface):
    if interface is not None:
        return interface[0]
    try:
        return conf.iface
    except AttributeError:
        print('Unable to use default interface. Exiting')


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
            print(
                f'{strftime("%Y-%m-%d %H:%M:%S", localtime(float(pkt.time)))}.{float(pkt.time) - int(float(pkt.time))} HTTP {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {pkt[HTTPRequest].Host.decode()} {pkt[HTTPRequest].Method.decode()} {pkt[HTTPRequest].Path.decode()}')
        elif pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = pkt[TCP][Raw].load.decode('utf-8', 'ignore')

            if payload.startswith('GET') or payload.startswith('POST'):
                # print(pkt[Raw].load.decode('utf-8', 'ignore'))  # This line works
                lines = payload.split('\r\n')

                first_line = lines[0].split()
                method = first_line[0]  # Method: GET or POST
                uri = first_line[1] if len(first_line) > 1 else 'Unknown URI'

                host = 'Unknown Host'
                for line in lines:
                    if line.startswith('Host:'):
                        host = line.split('Host: ')[1]
                        break
                if method in ['GET', 'POST'] and host != 'Unknown Host':
                    print(
                        f'{strftime("%Y-%m-%d %H:%M:%S", localtime(float(pkt.time)))}.{float(pkt.time) - int(float(pkt.time))} HTTP {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {host} {method} {uri}')
        if pkt.haslayer(TLSClientHello):
            if pkt.haslayer(ServerName):
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(float(pkt.time)))}.{float(pkt.time) - int(float(pkt.time))} TLS {TLS_VERSIONS[pkt[TLSClientHello].version]} {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {pkt[ServerName].servername.decode("UTF-8")}')
            else:
                print(
                    f'{strftime("%Y-%m-%d %H:%M:%S", localtime(float(pkt.time)))}.{float(pkt.time) - int(float(pkt.time))} TLS {TLS_VERSIONS[pkt[TLSClientHello].version]} {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}')
        elif pkt.haslayer(TCP) and pkt[TCP].payload and pkt.haslayer(Raw):
            tcp_payload = bytes(pkt[TCP].payload)
            if len(tcp_payload) > 10:
                # Extract the first byte for the Content Type
                content_type = tcp_payload[0]
                tls_version_major, tls_version_minor = tcp_payload[9], tcp_payload[10]
                # Map major.minor bytes to human-readable version
                version_mapping = {
                    (3, 0): "SSL 3.0",
                    (3, 1): "TLS 1.0",
                    (3, 2): "TLS 1.1",
                    (3, 3): "TLS 1.2",
                    (3, 4): "TLS 1.3",
                }
                readable_version = version_mapping.get((tls_version_major, tls_version_minor))
                if content_type == 22 and tcp_payload[5] == 1:
                    cipher_suites_length = int.from_bytes(tcp_payload[76:78], byteorder="big")
                    compression_methods_length = int.from_bytes(
                        tcp_payload[78 + cipher_suites_length:79 + cipher_suites_length],
                        byteorder="big")  # 80 = 77 + 2 + 1
                    extensions_length = int.from_bytes(tcp_payload[
                                                       79 + cipher_suites_length + compression_methods_length: 81 + cipher_suites_length + compression_methods_length],
                                                       byteorder="big")
                    sni_value = ""
                    curr_byte = 81 + cipher_suites_length + compression_methods_length
                    while curr_byte < 81 + cipher_suites_length + compression_methods_length + extensions_length:
                        ext_type = int.from_bytes(tcp_payload[curr_byte: curr_byte + 2], byteorder="big")
                        ext_len = int.from_bytes(tcp_payload[curr_byte + 2: curr_byte + 4], byteorder="big")
                        ext_val = tcp_payload[curr_byte + 4: curr_byte + 4 + ext_len]
                        if ext_type == 0 and ext_len > 5:
                            sni_len = ext_len
                            sni_value = ext_val[5:].decode()
                        curr_byte = curr_byte + 4 + ext_len
                    print(
                        f'{strftime("%Y-%m-%d %H:%M:%S", localtime(float(pkt.time)))}.{float(pkt.time) - int(float(pkt.time))} {readable_version} {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} {sni_value}')


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
        print("Sniffing interface " + self.interface)
        sniff(iface=self.interface, filter=self.bpf_filter, prn=lambda pkt: display_single_packet(pkt))

    def start(self):
        self.prepare_expression()
        if self.pcap_file is not None:
            self.read_pcap_file()
        elif self.interface is not None:
            self.sniff_interface()
        else:
            print('Could not load interface or pcap file.  Check -h for help. Exiting')


if __name__ == '__main__':
    load_layer('tls')
    parser = ArgumentParser(prog='Packet Sniffer',
                            description='Simple packet sniffer for HTTP and TLS traffic',
                            epilog="You can choose either one of -i or -r options. If both are not specified, "
                                   "this program will start sniffing on the default interface"
                                   "For more help contact Ameya Zope")
    # TODO: Add error handling for invalid input
    parser.add_argument('-i', '--interface', dest='interface', nargs=1, type=str, action='store', default=None,
                        help='Specify the network interface that needs to be sniffed, if not specified and the -r '
                             'option is also not specified, then it picks up the default interface')
    # TODO : Add error handling for file not found
    parser.add_argument('-r', '--read', dest='pcap_file', nargs=1, type=str, action='store', default=None,
                        help='Specify the pcap file to read the packets from')
    parser.add_argument("expression", nargs='*', type=str, action="store", default=None,
                        help='This is the bpf filter that will be applied to the packets captured')
    args = parser.parse_args()
    pktSniffer = PacketSniffer(get_interface(args.interface), args.pcap_file, args.expression)
    pktSniffer.start()
