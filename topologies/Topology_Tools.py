from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.node import OVSSwitch
from mininet.log import info, output, warn, setLogLevel
from _thread import start_new_thread
from threading import Thread
import os, stat
import json
import time
import csv
import requests
import sys

sys.path.append(".")
print(os.getcwd())
print(sys.path.__str__())

def start_switch_thread(net, switch, controller):
    info(f"*** Starting switch {switch}\n")
    net.get(switch).start([controller])

def start_switches(net, switches, controller):
    threads = []
    for switch in switches:
        thread = Thread(target=start_switch_thread, args=(net, switch, controller))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def printConnections( switches ):
    "Compactly print connected nodes to each switch"
    for sw in switches:
        output( '%s: ' % sw )
        for intf in sw.intfList():
            link = intf.link
            if link:
                intf1, intf2 = link.intf1, link.intf2
                remote = intf1 if intf1.node != sw else intf2
                output( '%s(%s) ' % ( remote.node, sw.ports[ intf ] ) )
        output( '\n' )

def startIperf(host1, host2, bw, port, timeTotal):
    # host2.cmd("iperf -s -u -p {} &".format(port))
    print("Host {} to Host {} Bandwidth: {}".format(host1.name, host2.name, bw))
    command = "iperf -c {} -u -p {} -t {} -b {}M &".format(host2.IP(), port, timeTotal, bw)
    host1.cmd(command)

def pause_iperf(host):
    """
    Pause the iperf server running on the host.
    :param host: The Mininet host object.
    """
    host.cmd('pkill -STOP iperf')
    print(f"Paused iperf server on {host.name}")

def resume_iperf(host):
    """
    Resume the iperf server running on the host.
    :param host: The Mininet host object.
    """
    host.cmd('pkill -CONT iperf')
    print(f"Resumed iperf server on {host.name}")

def terminate_iperf_on_host(host):
    """
    Terminates the iperf command running on a given Mininet host.
    """
    host.cmd("pkill -f iperf")

def min_to_sec(min):
    return min * 60

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

class MobilitySwitch( OVSSwitch ):
    "Switch that can reattach and rename interfaces"

    def delIntf( self, intf ):
        "Remove (and detach) an interface"
        port = self.ports[ intf ]
        del self.ports[ intf ]
        del self.intfs[ port ]
        del self.nameToIntf[ intf.name ]

    # pylint: disable=arguments-differ
    def addIntf( self, intf, rename=False, **kwargs ):
        "Add (and reparent) an interface"
        OVSSwitch.addIntf( self, intf, **kwargs )
        intf.node = self
        if rename:
            self.renameIntf( intf )

    def attach( self, intf ):
        "Attach an interface and set its port"
        port = self.ports[ intf ]
        if port:
            if self.isOldOVS():
                self.cmd( 'ovs-vsctl add-port', self, intf )
            else:
                self.cmd( 'ovs-vsctl add-port', self, intf,
                          '-- set Interface', intf,
                          'ofport_request=%s' % port )
            self.validatePort( intf )

    def validatePort( self, intf ):
        "Validate intf's OF port number"
        ofport = int( self.cmd( 'ovs-vsctl get Interface', intf,
                                'ofport' ) )
        if ofport != self.ports[ intf ]:
            warn( 'WARNING: ofport for', intf, 'is actually', ofport,
                  '\n' )

    def renameIntf( self, intf, newname='' ):
        "Rename an interface (to its canonical name)"
        intf.ifconfig( 'down' )
        if not newname:
            newname = '%s-eth%d' % ( self.name, self.ports[ intf ] )
        intf.cmd( 'ip link set', intf, 'name', newname )
        del self.nameToIntf[ intf.name ]
        intf.name = newname
        self.nameToIntf[ intf.name ] = intf
        intf.ifconfig( 'up' )

    def moveIntf( self, intf, switch, port=None, rename=True ):
        "Move one of our interfaces to another switch"
        self.detach( intf )
        self.delIntf( intf )
        switch.addIntf( intf, port=port, rename=rename )
        switch.attach( intf )




