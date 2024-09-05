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
from Topology_Tools import *
from Custom_CLI import *
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

def moveHost( host, oldSwitch, newSwitch, newPort=None ):
    "Move a host from old switch to new switch"
    hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
    oldSwitch.moveIntf( sintf, newSwitch, port=newPort )
    return hintf, sintf

def four_switches_network():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8', link=TCLink, switch=MobilitySwitch)

    queue_lenght = 10
    timeTotal = min_to_sec(10)
    controllerIP = '127.0.0.1'
    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip=controllerIP,
                           protocol='tcp',
                           port=6633)

    info('*** Add switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    info('*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01',defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02',defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:03',defaultRoute=None)

    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', mac='00:00:00:00:00:04',defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', mac='00:00:00:00:00:05',defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', mac='00:00:00:00:00:06',defaultRoute=None)

    info('*** Add links switch\n')
    net.addLink(s1, s2, delay='10ms', use_tbf=True, bw=3, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s2, s3, delay='10ms', use_tbf=True, bw=3, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s1, s4, delay='14ms', use_tbf=True, bw=4, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    net.addLink(s4, s3, delay='14ms', use_tbf=True, bw=4, max_queue_size=queue_lenght, latency_ms=10000000,
                    burst=1000000)
    
    info('*** Add links host\n')
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
    start_switches(net, ['s1', 's2', 's3', 's4'], c0)

    time.sleep(5)

    '''
    print("Starting iperf ")
    start_new_thread(startIperf, (h1, h4, 2.75, 5001, timeTotal))
    start_new_thread(startIperf, (h2, h5, 1.75, 5001, timeTotal))
    start_new_thread(startIperf, (h3, h6, 1.75, 5001, timeTotal))
    '''

    #h1 is connected with bot s1 and s2, i want to shut 
    #h1.cmd('ifconfig h1-eth1 down')

    #printing topology AFTER changing
    print_topology(net)

    time.sleep(20)

    '''
    #MIGRATION FUNCTIONS, CHOOSE ONE
    print("**** MIGATRION PROCESS START ****")
    h1, old = net.get('h1', 's1')
    new = net['s2']
    hintf, sintf = moveHost(h1, old, new )
    print_topology(net)
    '''
    
    MyCLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    
four_switches_network()



