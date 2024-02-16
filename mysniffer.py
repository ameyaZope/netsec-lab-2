from argparse import ArgumentParser
from scapy.all import * # do not import from scapy.util, that rdcap version has bugs


class PacketSniffer():
    def __init__(self, interface, pcap_file, expression):
        self.interface = interface
        self.pcap_file = pcap_file
        self.expression = expression

    def read_pcap_file(self):
        print("Reading file name : " + self.pcap_file[0])
        packet_list = sniff(offline=self.pcap_file[0], filter=self.bpf_filter)
        print(packet_list)

    def prepare_expression(self):
        self.bpf_filter = ' '.join(self.expression)

    def sniff_interface(self):
        print("Sniffing interface " + self.interface)

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
    print(args)
    pktSniffer = PacketSniffer(args.interface, args.pcap_file, args.expression)
    pktSniffer.start()