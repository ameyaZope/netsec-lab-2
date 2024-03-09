#!/usr/bin/env python3

import csv
import subprocess

from argparse import ArgumentParser
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.all import conf


def get_interface(interface):
    if interface is not None:
        return interface[0]
    try:
        return conf.iface
    except AttributeError:
        print('Unable to use default interface. Exiting')


def get_arp_table():
    """
        Get ARP table from /proc/net/arp
    """
    with open('/proc/net/arp') as arpt:
        names = [
            'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
        ]  # arp 1.88, net-tools 1.60
        reader = csv.DictReader(
            arpt, fieldnames=names, skipinitialspace=True, delimiter=' ')
        next(reader)
        return [block for block in reader]


class ArpWatch:
    def __init__(self, interface):
        self.interface = interface

    def detect_arp_poisoning(self, pkt):
        if ARP in pkt and pkt[ARP].op == 2:  # who-has or is-at
            for arp_entry in get_arp_table():
                if arp_entry['IP address'] == pkt[ARP].psrc and arp_entry['HW address'] != pkt[ARP].hwsrc:
                    return pkt.sprintf(f'[WARNING] {datetime.now().strftime("%d/%m/%Y %H:%M:%S")} ARP Cache Poisoning '
                                       'Detected ARP Changing from initialMac : ' + str(arp_entry['HW address'] +
                                                                                        ' newMac: ' + str(
                        pkt[ARP].hwsrc) + ' for ip: ' + arp_entry['IP address']))

    def start_arp_poisoning_detector(self):
        if self.interface is not None:
            print("Starting ARP-Watch for arp-cache-poisoning detection")
            sniff(iface=self.interface, prn=self.detect_arp_poisoning, filter="arp", store=0)
        else:
            sniff(iface=self.interface, prn=self.detect_arp_poisoning, filter="arp", store=0)


if __name__ == '__main__':
    parser = ArgumentParser(prog='ARP Cache Poisoning Detector',
                            description='Simple ARP Cache Poisoning Detector',
                            epilog='For more help contact Ameya Zope')

    # TODO: Add error handling for invalid input
    parser.add_argument('-i', '--interface', dest='interface', nargs=1, type=str, action='store', default=None,
                        help='Specify the network interface that needs to be sniffed, if not specified it will pick '
                             'the default interface')

    args = parser.parse_args()
    arpWatch = ArpWatch(interface=get_interface(args.interface))
    arpWatch.start_arp_poisoning_detector()
