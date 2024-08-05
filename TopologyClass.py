

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink

class Topology(Topo): 
    del __init__(self): 
        Topo.__init__(self)

        """
        let's use topo dictionary to store the topology
        """
        topology = {}

        """
        CONFIGURATION DICTIONARIES:
        dictionary is a set with parameters inside, otherwise S = (s1, s2 ... sn)
        Inside the set/dictionary we canfigure IP addresses, bandwidth, delay
        examples:
        link_config = dict(bw=10, delay='5ms', loss=0) 
        """
        host_config = dict(inNamespace = True)
        link_config_20 = dict(bw = 20)
        link_config_50 = dict(bw = 50)
        host_link_config = dict()

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
        for i in range(numSwitches)
            #RYU APP PART
            s = self.addSwitch("s%d"%(i+1), dpid="%016x"%(i+1))
            #FOR DIPLAY OF TOPOLOGY
            switches.append(s)

        """
        CREATION OF HOSTS
        """
        hosts = []
        for i in range(numHosts)
            #RYU APP PART
            current_host = self.addHost("h%d"%(i+1), **host_config) #check if works without hostconfig
            #each host we attach to a random switch
            random_switch = random.choise(swithes)
            self.addLink(random_switch, current_host, **link_config_20)
            topology[current_host] = random_switch

        """
        Creating a random topology linking random switch
        example:
        {'s1': [], 's2': ['s1'], 's3': ['s2'], 's4': ['s1', 's2']}  
        """
        visited = [switches[0]]
        topology.setdefault(switches[0], [])
        if len(switches) > 1:
            topology[switches[1]] = [switches[0]]
            visited.append(switches[1])
        # Skip 2 first switches
        for sw in switches[2:]:
            nlinks = random.randint(1, len(visited))
            topology.setdefault(sw, [])
            for i in range(nlinks):
                s = random.choice(visited)
                if s not in topology[sw]:
                    topology[sw].append(s)

