from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
import sys
import os
import random

sys.path.append("./controller")
sys.path.append(".")
print(os.getcwd())
print(sys.path.__str__())

class Topology(Topo):
    def __init__(self):
        Topo.__init__(self)

        """
        let's use topo dictionary to store the topology
        """
        topology = {}
        host_topology = {}
        """
        CONFIGURATION DICTIONARIES:
        dictionary is a set with parameters inside, otherwise S = (s1, s2 ... sn)
        Inside the set/dictionary we canfigure IP addresses, bandwidth, delay
        examples:
        link_config = dict(bw=10, delay='5ms', loss=0) 
        """


        #A more scalable approch
        link_configs = [
            {'bw' : 20},
            {'bw' : 50},
        ]

        """
        RANDOM TOPOLOGY:
        the user will provide the number of switch and the number of host/server
        """
        numSwitches = 10  #temp
        numHosts = 10    #temp

        """
        CREATION SWITCH NODE
        {"s1", "00...001"}
        {"s2", "00...002"}
        switches is an empty list, will be store all swithes
        ['s1','s2', 's3' ...]
        """
        switches = [] 
        for i in range(numSwitches):
            switches.append(s)

        """
        CREATION OF HOSTS
        We populate the topology dict
        """
        hosts = []
        for current_host in range(numHosts):
            #each host we attach to a random switch
            random_switch = random.choise(len.switches)
            host_topology[current_host] = random_switch

        """
        Creating a random topology linking random switch

        The outcome is the following dictionary
        example:
        {'s1': [], 's2': ['s1'], 's3': ['s2'], 's4': ['s1', 's2']}  
        """
        visited = [switches[0]]
        if len(switches) > 1:
            topology[switches[1]] = [switches[0]]
            topology[switches[1]][switches[0]] = random.choice(link_configs)
            visited.append(switches[1])
        # Skip 2 first switches
        for sw in switches[2:]:
            nlinks = random.randint(1, len(visited))
            for i in range(nlinks):
                s = random.choice(visited)
                if s not in topology[sw]:
                    topology[sw] = switches[s]
                    topology[sw][s] = random.choice(link_configs)

