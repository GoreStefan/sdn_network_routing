from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from _thread import start_new_thread
import os, stat
import json
import time
import csv
import requests
import sys

sys.path.append(".")
print(os.getcwd())
print(sys.path.__str__())


#                s2
#  h1    10ms /     \ 10ms  h4
#  h2 --     s1       s3 -- h5
#  h3    14ms \     / 14ms  h6
#                s4

###################################################################
############### Scenario - 6 Hosts    #############################
###################################################################


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

def min_to_sec(min):
    return min * 60


def modify_link_properties(net, node1, node2, bw=None, delay=None, loss=None, max_queue_size=None):
    """
    Modify the properties of a link in a Mininet topology.

    :param net: Mininet object representing the network.
    :param node1: The name of the first node (e.g., 'h1', 's1').
    :param node2: The name of the second node (e.g., 'h2', 's2').
    :param bw: Bandwidth limit in Mbps (e.g., 10).
    :param delay: Link delay in milliseconds (e.g., '10ms').
    :param loss: Packet loss rate in percentage (e.g., 1).
    :param max_queue_size: Maximum queue size in packets (e.g., 1000).
    """
    # Find and remove the existing link between node1 and node2
    net.delLinkBetween(net.get(node1), net.get(node2))

    # Add a new link with updated properties
    net.addLink(net.get(node1), net.get(node2), bw=bw, delay=delay, loss=loss, max_queue_size=max_queue_size)

    print(f"Link between {node1} and {node2} updated with bw={bw}, delay={delay}, loss={loss}, max_queue_size={max_queue_size}")


def migrate_host(net, host_name, old_switch_name, new_switch_name):
    """
    Migrate a host from one switch to another in a Mininet topology.

    :param net: Mininet object representing the network.
    :param host_name: Name of the host to migrate (e.g., 'h1').
    :param old_switch_name: Name of the current switch (e.g., 's1').
    :param new_switch_name: Name of the target switch (e.g., 's2').
    """
    # Get the host and switches
    host = net.get(host_name)
    old_switch = net.get(old_switch_name)
    new_switch = net.get(new_switch_name)

    # Remove the link between the host and the old switch
    #while not host.waiting:
    net.delLinkBetween(host, old_switch)
    net.addLink(host, new_switch)

    # Add a new link between the host and the new switch
    print("fatto")
    print(f"Host {host_name} has been migrated from switch {old_switch_name} to switch {new_switch_name}.")
    print_topology(net)


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


def four_switches_network():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8', link=TCLink)

    #Da sistemare i Config Files
    queue_lenght = Config.queue_lenght
    timeTotal = min_to_sec(Config.duration_iperf_per_load_level_minutes)
    controllerIP = '127.0.0.1'
    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip=controllerIP,
                           protocol='tcp',
                           port=6633)

    info('*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    info('*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)

    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)

    info('*** Add links\n')
    net.addLink(s1, s2, delay='10ms', use_tbf=True, bw=3, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s2, s3, delay='10ms', use_tbf=True, bw=3, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s1, s4, delay='14ms', use_tbf=True, bw=4, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s4, s3, delay='14ms', use_tbf=True, bw=4, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.addLink(h4, s3)
    net.addLink(h5, s3)
    net.addLink(h6, s3)

    info('*** Starting network\n')
    net.build()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])

    time.sleep(15)

    
    #MIGRATION OF THE HOST
    """
    print("*****IPERF STEP*******")
    time.sleep(15)
    print("*****MIGRATION OF HOST 1*****")
    pause_iperf(net.get('h1'))
    time.sleep(5)
    migrate_host(net, 'h1', 's1', 's2')
    print("RESUMING IPERF")
    resume_iperf(net.get('h1'))
    """
    time.sleep(10)
    print("DETACHING PROCESS")
    s1.detach(h1)
    s2.attach(h1)
    time.sleep(5)
    print_topology(net)
    #time.sleep(15)
    #modify_link_properties(net, 's1', 's2', delay='30ms', bw=5)
    # non funziona modify_latency(net, 's1', 's2', 100)
    """
    #CHANGING THE BANDWIDTH OF NETWORK

    change_bandwidth(net, 's1', 's2', 10)
    time.sleep(5)
    print_topology(net)
    """
    time.sleep(10000)
    #stop_controller()
    #CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    four_switches_network()



def changeBandwith(node, bw, delay):
  for intf in node.intfList(): # loop on interfaces of node
    #info( ' %s:'%intf )
    if intf.link: # get link that connects to interface(if any)
        newBW = bw
        intfs = [ intf.link.intf1, intf.link.intf2 ] #intfs[0] is source of link and intfs[1] is dst of link
        intfs[0].config(bw=newBW, delay = delay)
        intfs[1].config(bw=newBW, delay = delay)
        print("changing bandwidth")