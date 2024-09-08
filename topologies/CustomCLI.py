from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.node import OVSSwitch
from mininet.log import info, output, warn, setLogLevel
from _thread import start_new_thread
from TopologyTools import *
import os, stat
import json
import time
import csv
import requests
import sys

sys.path.append(".")
print(os.getcwd())
print(sys.path.__str__())

class MyCLI(CLI):
    def __init__(self, *args, **kwargs):
        super(MyCLI, self).__init__(*args, **kwargs)
        self.mn = self.mn

    def do_migrate(self, line):
        "Do host migration"
        args = line.split()
        if len(args) != 3:
            print("Usage: migrate <host> <oldSwitch> <newSwitch>")
            return

        host_name, old_switch_name, new_switch_name = args

        h, old = self.mn.get(host_name, old_switch_name)
        new = self.mn[new_switch_name]

        for ho in self.mn.hosts:
            print("terminate iperf on host" + str(ho))
            terminate_iperf_on_host(ho)

        time.sleep(2)

        print(f"**** MIGRATION PROCESS START for {host_name} ****")
        hintf, sintf = moveHost(h, old, new)
        print(f"**** MIGRATION PROCESS END for {host_name} ****")

        print(f'starting new Iperf servers...')

        h0 = self.mn.hosts[0]
        if h0 == h:
            h0 = self.mn.hosts[1]

        print(str(ho))
        for ho in self.mn.hosts:
            if h0 != ho:
                start_new_thread(startIperf, (ho, h0, 1.00, 5001, 20))
        

        print_topology(self.mn)


        
    
    def print_topology(net):
        """
        Print the Mininet topology.
        :param net: Mininet object representing the network.
        """
        print("Hosts:")
        for host in net.hosts:
            print(f"Host: {host.name}, IP: {host.IP()}")

        print("\nSwitches:")
        for switch in net.switches:
            print(f"Switch: {switch.name}")

        print("\nLinks:")
        for link in net.links:
            intf1 = link.intf1
            intf2 = link.intf2

            # Extracting the link parameters
            link_options = net.linksBetween(intf1.node, intf2.node)[0]
            bw = link_options.intf1.params.get('bw', 'N/A')
            delay = link_options.intf1.params.get('delay', 'N/A')
            print(f"Link: {intf1} <--> {intf2}, Bandwidth: {bw} Mbps, Latency: {delay}")

def moveHost( host, oldSwitch, newSwitch, newPort=None ):
    "Move a host from old switch to new switch"
    hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
    oldSwitch.moveIntf( sintf, newSwitch, port=newPort )
    return hintf, sintf