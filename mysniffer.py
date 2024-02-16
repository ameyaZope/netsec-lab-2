from argparse import ArgumentParser
from scapy.utils import rdpcap


class PacketSniffer():
    def __init__(self, interface, pcap_file):
        self.interface = interface
        self.pcap_file = pcap_file

    def read_pcap_file(self):
        print("Reading file name : " + self.pcap_file[0])
        parsed_file = rdpcap(self.pcap_file[0])
        print(parsed_file)


if __name__ == '__main__':
    parser = ArgumentParser(prog='Packet Sniffer',
                            description='Simple packet sniffer for HTTP and TLS traffic',
                            epilog="For more help contact Ameya Zope")
    parser.add_argument('-i' , '--interface', dest='interface', nargs=1, type=str, action='store', default='NA', help='Specify the network interface that needs to be sniffed')
    parser.add_argument('-r', '--read', dest='pcap_file', nargs=1, type=str, action='store', default='NA', help='Specify the pcap file to read the packets from')
    args = parser.parse_args()
    print(args)
    pktSniffer = PacketSniffer(args.interface, args.pcap_file)
    pktSniffer.read_pcap_file()