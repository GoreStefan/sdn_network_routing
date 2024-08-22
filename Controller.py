from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset  
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ipv4, ipv6, ether_types, icmp
from ryu.lib import hub

from ryu.app import simple_switch_13
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication

from ryu.topology import event                                          
from ryu.topology import switches                                       

from pprint import pprint
from enum import Enum
from collections import defaultdict

import random
import time
import copy
import json
import sys

import logging
logging.basicConfig(level=logging.DEBUG)  # Default level for root logg>

# Create individual loggers for different categories
logger_statistics = logging.getLogger('statistics')
logger_arp = logging.getLogger('arp')

#setting level of logger
logger_statistics.setLevel(logging.DEBUG)
logger_arp.setLevel(logging.DEBUG)

sys.path.append("..")

#TO DO: creating a JSON configuration file
interval_update_latency = 10 
interval_controller_switch_latency = 10 
wait_till_Start = 4

class ControllerMain(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ControllerMain, self).__init__(*args, **kwargs)
        MAX_PATH = 100 

        #FLAGS AND SEMAPHORS
        self.latency_measurement_flag = False

        #DICTIONARY ARP
        self.arp_table = {}
        self.routing_arp = {}

        #DICTIONARY ROUTING
        self.already_routed = []
        self.already_routed_ip = []

        #DICTIONARIES TOPOLOGY
        self.mac_to_port = {} 
        self.swithes = []
        self.datapath_list = {}
        self.hosts = {}
        self.dpidToDatapath = {}

        #DICTIONARY FLOW 
        self.paths_per_flow = {} 
        self.chosen_path_per_flow = {}

        #STATISTICS DICTIONARIES
        self.data_map = {}
        #-->LANTECY STATS
        self.latency_dict = {}
        #-->BANDWIDTH STATS
        self.temp_bw_map_ports = {}
        self.temp_bw_map_flows = {}
        self.bandwith_port_dict = {}
        self.bandwith_flow_dict = {}

        #-->RTT STATS
        self.last_arrived_package = {}
        self.rtt_portStats_to_dpid = {}
        self.rtt_stats_sent = {}

        #CONFIG VAR
        self.waitTillStart = 5

        #NEW THREAD
        hub.spawn(self.checking_update)

    def checking_update(self):
        """
        FIRST STATE : waiting the FLAG controlled by monitor latency
        SECOND STATE: creating latency dict
        THIRD STATE: 
        """
        
        """
        while not self.latency_measurement_flag:
            self.logger.info("Waiting for latency measurement")
            hub.sleep(1)
        hub.sleep(5)    
        """
        while True: 
            self.latency_dict = self.convert_data_map_to_dict(self.data_map, 'latencyRTT')
            hub.sleep(2)

    def convert_data_map_to_dict(self, dataMap, choice):
        """
        Creates dictionary of data_map
        :param dataMap:
        :param choice:
        :return:
        """
        dictBuild = {}
        for key1 in dataMap.keys():
            dictBuild[key1] = {}
            for key2 in dataMap[key1].keys():
                #if key2 not in dictBuild[key1].keys():
                #    dictBuild[key1] = {}
                dictBuild[key1][key2] = dataMap[key1][key2][choice][-1]['value']
        return dictBuild
        
    """
    @set_ev_cls(event.EventHostAdd)    
    def _event_host_add_handler(self, ev):                                                                              
        msg = ev.host.to_dict()
        print_with_timestamp("Nuovo host aggiunto")    
    """

    """
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev):
        print("======== PORT MODIFIED =======")
    """

    """
    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        #Host add event handler
        host = ev.host.to_dict()  # Get host details as a dictionary
        print_with_timestamp(f"Host details: {host}")  # Print the whole dictionary to inspect its structure
    """
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a new switch is connected to the controller.
        We istall a table-miss entry
        the second add-flow it's used for packet transmitted
        by the icmp protoll used by the iperf command

        dpidToDatapath is a dictanary from id of a switch and datapath

        important are the two threads which are spawned with the command
        hub.spawn()
        -> minitor_sw_controller_latency 
        -> monitor_latency
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # register datapaths
        dpid = datapath.id
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1,
            icmpv4_type=3
        )
        actions = []
        self.add_flow(datapath, 1, match, actions)

        self.dpidToDatapath[dpid] = datapath
        self.last_arrived_package[dpid] = {}

        # Sending Echo packet to monitor flow and port stats
        hub.spawn(self.monitor_sw_controller_latency, datapath)
        # Starting flooding thread for flooding monitoring package
        hub.spawn(self.monitor_latency, datapath, ofproto)

    """
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev):
        print("PORT MODIFY")
        port = ev.port
        dp = ev.dp
        port_no = port.port_no

        #removing host from already_routed
        self.already_routed = [
            (h1, h2) for (h1, h2) in self.already_routed
            if not ((h1.dpid == dp and h1.port == port_no) or
                (h2.dpid == dp and h2.port == port_no))
        ]

        #To find the mac given (dpid, port_no)
        for mac, (dpid, port) in self.hosts.items():
            if dpid == dp and port == port_no:
                found_mac = mac
                break  # Exit the loop once the MAC address is foun

        #Given the arp table, to remove a entry, given the mac use the following code
        ip_to_remove = None
        for ip, mac in self.arp_table.items():
            if mac == found_mac:
                ip_to_remove = ip
                break  # Exit the loop once the IP address is found

        # Remove the entry if the IP address was found
        if ip_to_remove:
            del self.arp_table[ip_to_remove]

        #now i can retrive witch host was
        keys_to_remove = [mac for mac, (dpid, port) in self.hosts.items() if dpid == target_dpid and port == target_port]

        # Remove the hosts
        for key in keys_to_remove:
            del self.hosts[key]

        print("QUI")
    """
    
    def monitor_latency(self, datapath, ofproto):
        """
        monitor_latency will run while true. 
        The function send custom packet to each switch in the topology
        at a regular frequency. The packets will be held
        by the _packet_in_handler_
    
        NOTES: 
        the data inside the packet will be the time when it was build 
        and sent to the switch. 
        """
        hub.sleep(5)
        #self.waitTillStart += 0.1
        print("MONITORING LATENCY STARTED dpid: {}".format(datapath.id))
        self.latency_measurement_flag = True
        while True:
            #preparing the OverFlow message
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
            #custom packet creation
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=0x07c3,
                                            dst='ff:ff:ff:ff:ff:ff',
                                            src='00:00:00:00:00:09'))
            whole_data = str(time.time()) + '#' + str(datapath.id) + '#'
            pkt.add_protocol(bytes(whole_data, "utf-8"))
            pkt.serialize()
            data = pkt.data
            #building and sending the message
            req = ofp_parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                        ofproto.OFPP_CONTROLLER, actions, data)
            datapath.send_msg(req)
            hub.sleep(interval_update_latency)


    #self.send_packet_out(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER)

    def send_packet_out(self, datapath, buffer_id, in_port):
        """
        The controller will send this packet to the switch 
        that was activated. 

        The packet that arrived to the particular switch will 
        be floaded to all the ports. 
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        pck = self.create_packet(datapath.id)
        data = pck.data
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                    in_port, actions, data)
        datapath.send_msg(req)

    def monitor_sw_controller_latency(self, datapath):
        """
        The function calculate the RTT between switch
        and controller. 
        This is done with two additional functions: 
        send_port_stats_request = port-level statistics 
        send_flow_stats_request = flow-level statistics

        """
        hub.sleep(1)
        # self.waitTillStart += 0.25
        iterator = 0
        while True:
            # data = ''
            # self.send_echo_request(datapath, data)
            if iterator % 2 == 0:
                self.send_port_stats_request(datapath)
                print("Sent")
            else:
                self.send_flow_stats_request(datapath)
            iterator += 1
            hub.sleep(1)

    def send_port_stats_request(self, datapath):
        """
        SENDS a message to SWITCH to obtain port-level stats. 
        Indeed we have OFPPortStatsRequest made by the controller. 
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        self.rtt_stats_sent[datapath.id] = time.time()
        datapath.send_msg(req)
        # save timeStamp for RTT

    def send_flow_stats_request(self, datapath):
        """
        Sends a message to switch to obtain flow-level stats
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # only the ones with layer 4
        match = ofp_parser.OFPMatch(eth_type=2048)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL,
                                            ofp.OFPP_ANY, ofp.OFPG_ANY, 0, 0, match)
        self.rtt_stats_sent[datapath.id] = time.time()
        datapath.send_msg(req)
    


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """

        """
        current_time = time.time()
        dpid_rec = ev.msg.datapath.id
        # updating switch controller latency
        old_time = self.rtt_stats_sent[dpid_rec]
        total_rtt = current_time - old_time
        self.rtt_portStats_to_dpid[dpid_rec] = total_rtt
        body = ev.msg.body
        # parsing the answer
        for statistic in body:
            # get port id
            port_no = int(statistic.port_no)
            # self.rtt_port_stats_sent[dpid_rec] = 0
            if dpid_rec in self.data_map.keys():
                for dpid_sent_element in self.data_map[dpid_rec]:
                    in_port = self.data_map[dpid_rec][dpid_sent_element]["in_port"]
                    if in_port == port_no:
                        # found the right connection
                        # check if bw-map is built, first time!
                        if dpid_rec not in self.temp_bw_map_ports.keys():
                            self.temp_bw_map_ports[dpid_rec] = {}
                            self.bandwith_port_dict[dpid_rec] = {}
                        if port_no not in self.temp_bw_map_ports[dpid_rec].keys():
                            self.temp_bw_map_ports[dpid_rec][port_no] = {}
                            bytes_now = statistic.rx_bytes
                            # bytes_now = stat.tx_bytes
                            ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                            # overwriting tempMap
                            self.temp_bw_map_ports[dpid_rec][port_no]['ts'] = ts_now
                            self.temp_bw_map_ports[dpid_rec][port_no]['bytes'] = bytes_now
                        else:
                            ts_before = self.temp_bw_map_ports[dpid_rec][port_no]['ts']
                            bytes_before = self.temp_bw_map_ports[dpid_rec][port_no]['bytes']
                            # ts_now = time.time()
                            bytes_now = statistic.tx_bytes
                            ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                            byte_diff = bytes_now - bytes_before
                            ts_diff = ts_now - ts_before
                            # overwriting tempMap
                            self.temp_bw_map_ports[dpid_rec][port_no]['ts'] = ts_now
                            self.temp_bw_map_ports[dpid_rec][port_no]['bytes'] = bytes_now
                            # bw (bytes/sec)
                            bw = byte_diff / ts_diff
                            self.bandwith_port_dict[dpid_rec][port_no] = bw

    # for getting flow stats
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        When the controller will recevive a response to flow-stats request
        will execute the following line. 
        The aim of the code is to create and populate two important dictionaries: 

        --> temp_bw_map_flows, temporary value needed to calculate the bandwidth
        --> bandwith_flow_dict, here will store the bandwidth

        NOTES: 
        when received the FLOW STATS RESPONSE, it will contain different statictics
        also based on different type of packets, we need to filtrate the icmpv4 type 
        that are used for diagnostic manly purpose. 

        NOTES 2: 
        why we update the portStats if we receiving the Flow stats
        """
        dpid_rec = ev.msg.datapath.id
        # updating switch controller latency
        self.rtt_portStats_to_dpid[dpid_rec] = time.time() - self.rtt_stats_sent[dpid_rec]

        for statistic in ev.msg.body:
            if 'icmpv4_type' not in statistic.match:
                ip_src = statistic.match['ipv4_src']
                ip_dst = statistic.match['ipv4_dst']
                number_bytes = statistic.byte_count
                if dpid_rec not in list(self.temp_bw_map_flows):
                    self.temp_bw_map_flows[dpid_rec] = {}
                if ip_src not in list(self.temp_bw_map_flows[dpid_rec]):
                    self.temp_bw_map_flows[dpid_rec][ip_src] = {}
                if ip_dst not in list(self.temp_bw_map_flows[dpid_rec][ip_src]):
                    self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst] = {}
                    ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                    self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['ts'] = ts_now
                    self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['bytes'] = statistic.byte_count
                # the temp_bw_map_flow has every parameters needed to compute bandwidth
                else:
                    ts_now = (statistic.duration_sec + statistic.duration_nsec / (10 ** 9))
                    time_diff = ts_now - self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['ts']
                    bytes_diff = number_bytes - self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['bytes']
                    if time_diff > 0.0:
                        try:
                            #calculation of the bandwidth
                            bw = bytes_diff / time_diff
                        except ZeroDivisionError:
                            self.logger.info(
                                "Saved_ts: {} ts_now: {} diff: {}".format(
                                    self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['ts'],
                                    ts_now, time_diff))
                        if dpid_rec not in list(self.bandwith_flow_dict.keys()):
                            self.bandwith_flow_dict[dpid_rec] = {}
                        if ip_src not in list(self.bandwith_flow_dict[dpid_rec].keys()):
                            self.bandwith_flow_dict[dpid_rec][ip_src] = {}
                        self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['ts'] = ts_now
                        self.temp_bw_map_flows[dpid_rec][ip_src][ip_dst]['bytes'] = statistic.byte_count
                        self.bandwith_flow_dict[dpid_rec][ip_src][ip_dst] = bw            

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """ 
        Every time a switch handle a packet will redirect to the
        controller and will analyze the packet based on some 
        variables
        """
        timestamp_recieve = time.time()
        
        #retrive all the information from the packet that we received
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})       #???
        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src
        dpid_rec = datapath.id
        in_port = msg.match['in_port']

        #If the arrived the custom packet we compute these instructions
        if eth_pkt.ethertype == 0x07c3:
            pkt_header_list = pkt[-1].decode("utf-8").split('#')
            #inside the custom packet we have two info: timestamp and switch id
            timestamp_sent = float(pkt_header_list[0])
            dpid_sent = int(pkt_header_list[1])
            if dpid_sent not in self.last_arrived_package[dpid_rec].keys():
                self.last_arrived_package[dpid_rec][dpid_sent] = 0.0
                # createLink
            # timedifference
            time_difference = timestamp_recieve - timestamp_sent
            # if package is newest
            if timestamp_sent > self.last_arrived_package[dpid_rec][dpid_sent]:
                # creating dictionaries and arrays
                if dpid_rec not in self.data_map.keys():
                    self.data_map[dpid_rec] = {}
                if dpid_sent not in self.data_map[dpid_rec].keys():
                    self.data_map[dpid_rec][dpid_sent] = {}
                    self.data_map[dpid_rec][dpid_sent]['in_port'] = in_port
                    self.data_map[dpid_rec][dpid_sent]['bw'] = []
                    self.data_map[dpid_rec][dpid_sent]['latencyRTT'] = []
                latency_link_echo_rtt = time_difference - (float(self.rtt_portStats_to_dpid[dpid_sent]) / 2) - (
                        float(self.rtt_portStats_to_dpid[dpid_rec]) / 2)
                # latency object echo RTT
                latency_obj_rtt = {'timestamp': timestamp_sent, 'value': latency_link_echo_rtt * 1000}
                self.data_map[dpid_rec][dpid_sent]['latencyRTT'].append(latency_obj_rtt)
                self.last_arrived_package[dpid_rec][dpid_sent] = time.time()
            else:
                self.logger.info("Packet arrived earlier")
            return

        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid_rec, in_port)
        # filter packets
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            # -------------------
            # avoid broadcast from LLDP
        if eth_pkt.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth_pkt.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        # -------------------


        """
        The controller here will manage the ARP packets, due to the ARP 
        PROTOCOL.
        The ARP PROTOCOL are needed to resolve the MAC-IP of each host in 
        the network and then to create the ARP table, that will be inside 
        the the OPENFLOW TABLE. 

        HOW THE PROTOCOL ARP IN SDN WORKS:
        The Host A that want to resolve a MAC-IP send a ARP packet. 
        At the first Swich the message will be intercepted by the 
        switch and sent to the controller. 

        The controller see if it's present in arp_table
        and if it's routed. 

        If it's not presente in Universal ARP TABLE, will tell to the 
        switch to perfom a broadcasting with OFPPacketOut, packets that
        will not be intercepted by the controller. 

        The interessted Host will respond with an ARP_REPLAY
        """
        if arp_pkt:
            print("Handling ARP packet")
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src_mac
                h1 = self.hosts[src_mac]
                h2 = self.hosts[dst_mac]
                if (h1, h2) not in self.already_routed:
                    #same here
                    hub.spawn(self.routing, h1, h2, src_ip, dst_ip, 'arp')
                return
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src_mac]
                    h2 = self.hosts[dst_mac]
                    if (h1, h2) not in self.already_routed:
                        self.arp_table[src_ip] = src_mac
                        dst_mac = self.arp_table[dst_ip]
                        h1 = self.hosts[src_mac]
                        h2 = self.hosts[dst_mac]
                        #we cannot put a wainting here, so we need to spawn a thread
                        hub.spawn(self.routing, h1, h2, src_ip, dst_ip, 'arp')
                        self.logger.info("Calc needed for DFS routing between h1: {} and h2: {}".format(src_ip, dst_ip))
                        self.already_routed.append((h1, h2))
                    return
                else:
                    # flooding ARP request
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

        """
        Managing the IPV4 packets. 
        IPV4 and ARP are different protocols, but both of them are inside a
        a ETHERNET packet. 


        """

        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            if dst_ip in self.arp_table and src_ip in self.arp_table:
                src_mac = self.arp_table[src_ip]
                dst_mac = self.arp_table[dst_ip]
                h1 = self.hosts[src_mac]
                h2 = self.hosts[dst_mac]
                if (h1, h2) not in self.already_routed_ip:
                    self.routing(h1, h2, src_ip, dst_ip, 'ipv4')
                    self.already_routed_ip.append((h1, h2))

    def routing(self, h1, h2, src_ip, dst_ip, typep):
        """
        Routing of ARP requests
        :param h1:  derived from h1 = self.hosts[src_mac] 
        :param h2:  
        :param src_ip:  it's the source's ip
        :param dst_ip:
        """
        #should i put here hun or time
        hub.sleep(5)
        #where h[0] and h[1] are the dpid of the switches
        optimal_path = self.get_optimal_path(self.latency_dict, h1[0], h2[0])

        if src_ip not in self.flow_path_cost:
            self.flow_path_cost[src_ip] = {}
        
        self.flow_path_cost[src_ip][dst_ip] = (optimal_path, self.get_path_cost(self.latency_dict, path_optimal))
        pprint(self.flow_path_cost)
        
        self.install_path(optimal_path, h1[1], h2[1], src_ip, dst_ip, typep)
        
        #TESTING. 
        #self.chosen_path_per_flow[src_ip][dst_ip] = {optimal_path, self.get_path_cost(optimal_path)}

    def get_optimal_path (self, latency_dict, src, dst, typep):
        #get all paths from a src ip to dst ip 
        paths = self.get_paths(latency_dict, src, dst)
        best_path = sorted(paths, key=lambda x: self.get_path_cost(latency_dict, x))[0]
        return best_path


    """
    This function is laverage to sort base, we sort with respect the 
    value of this function. 
    """
    def get_path_cost(self, latency_dict, path):
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(latency_dict, path[i], path[i+1])
        return cost


    # given a the two switches, i obtain the latency between them. 
    def get_link_cost(self, latency_dict, s1, s2):
        # only latency:
        ew = latency_dict[s2][s1]
        return ew

    def get_paths(self, latency_dict, src, dst):
        '''
        Get all paths from src to dst using DFS
        '''
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(latency_dict[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        return paths



    def get_match(self, type, ofp_parser, ip_src, ip_dst):
        """
        Support function for install path,
        match is a field in 
        """
        if type == 'ipv4':
            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )
            return match_ip
        if type == 'arp':
            match_arp = ofp_parser.OFPMatch(
                eth_type=0x0806,
                arp_spa=ip_src,
                arp_tpa=ip_dst
            )
            return match_arp
    
    def install_path(self, chosenPath, first_port, last_port, ip_src, ip_dst, type):
        """
        Given the best_path to we need to insert into the OpenFlow 
        tables the entrys to create the path from the src ip to 
        dst ip.

        The paths will have the following structure ["dpid1" ,"dpid2" , ...]
        The first and last port is the ports that connects the 2 hosts to the first
        and last switches. 

        """

        #here we add to the path also the ports that will handles the flow
        path = self.add_ports_to_path(chosenPath, first_port, last_port)
        #switches_in_paths = set().union(*chosenPath)

        """
        Given the structure of path after add_port_to_path
        path = {
            dpid: (int_port, out_port)
        }
        Create an action to populate the OpenFlow Table
        """
        #da verificare
        #for node in chosenPath:
        for node in path.keys(): 
            dp = self.dpidToDatapath[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            actions = [ofp_parser.OFPActionOutput(path[node][1])]
            #32768 è il numero di priorità del pacchetto
            self.add_flow(dp, self.get_match(type), self.get_match(type, ofp_parser, ip_src, ip_dst), actions)


    # Add the ports that connects the switches for all paths
    def add_ports_to_path(self, path, first_port, last_port):
        p = {}
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.data_map[s1][s2]['in_port']
            p[s1] = (in_port, out_port)
            in_port = self.data_map[s2][s1]['in_port']
        p[path[-1]] = (in_port, last_port)
        return p

    # prev: self, src_ip, dst_ip, newPath
    def reroute(self, src_ip, dst_ip, new_path):
        """
        rerouting the flow on a different path
        :param id_forward: flow id
        :param new_path: new pathm the flow should be routed on
        """
        chosenflow_prev = copy.deepcopy(self.chosen_path_per_flow[src_ip][dst_ip])
        self.chosen_path_per_flow[src_ip][dst_ip] = new_path

        # first and last are same
        i = 0
        flow_add_list = []
        flow_mod_list = []
        flow_delete_list = []

        difference_set = set(chosenflow_prev).difference(new_path)
        # check if things deleted
        if len(difference_set) > 0:
            flow_delete_list = list(difference_set)

        for switch in new_path:
            if switch in chosenflow_prev:
                # check prev
                index_prev = chosenflow_prev.index(switch)
                if i > 0:
                    if new_path[i - 1] == chosenflow_prev[index_prev - 1]:
                        i += 1
                        continue
                    # have to change index before
                    else:
                        if (new_path[i - 1] not in flow_add_list) \
                                and ((new_path[i - 1] not in flow_delete_list)
                                     and chosenflow_prev[index_prev] not in flow_delete_list):
                            print("Not same: {}".format(switch))
                            flow_mod_list.append(new_path[i - 1])
            else:
                flow_add_list.append(switch)
                index_prev = new_path.index(switch)
                # check here ob schon in add-list
                flow_mod_list.append(new_path[index_prev - 1])
            i += 1
        for j in range(0, len(flow_delete_list), 1):
            switch_old_index = chosenflow_prev.index(flow_delete_list[j])
            switch_old_index_prev = switch_old_index - 1
            if chosenflow_prev[switch_old_index_prev] not in flow_delete_list:
                flow_mod_list.append(chosenflow_prev[switch_old_index_prev])
            j += 1
        # delete duplicates from modlist
        flow_mod_list = list(dict.fromkeys(flow_mod_list))
        flow_mod_list.reverse()
        # first addFlows
        for switch in flow_add_list:
            # get index of next switch
            index = new_path.index(switch)
            next_index = index + 1
            if next_index < len(new_path):
                following_switch = new_path[next_index]
                self.add_flow_specific_switch(switch, src_ip, dst_ip,
                                              self.data_map[switch][following_switch]['in_port'])#output port
        hub.sleep(0.1)
        # second: mod flows
        for switch in flow_mod_list:
            index = new_path.index(switch)
            next_index = index + 1
            if next_index < len(new_path):
                following_switch = new_path[next_index]
                self.mod_flow_specific_switch(switch, src_ip, dst_ip,
                                              self.data_map[switch][following_switch]['in_port'])#output port
        # third: delete flows
        for switch in flow_delete_list:
            # clean up bw flow list
            try:
                self.bandwith_flow_dict[switch][src_ip].pop(dst_ip, None)
            except KeyError:
                print("Key {} not found".format(dst_ip))
            self.del_flow_specific_switch(switch, src_ip, dst_ip)

    def add_flow_specific_switch(self, switch, ip_src, ip_dst, out_port):
        dp = self.dpidToDatapath[switch]
        ofp_parser = dp.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(out_port)]
        match_ip = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst
        )
        self.add_flow(dp, 1, match_ip, actions)

    def mod_flow_specific_switch(self, switch, ip_src, ip_dst, out_port):
        dp = self.dpidToDatapath[switch]
        ofp_parser = dp.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(out_port)]
        match_ip = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst
        )
        self.mod_flow(dp, 1, match_ip, actions)

    def del_flow_specific_switch(self, switch, ip_src, ip_dst):
        dp = self.dpidToDatapath[switch]
        ofp_parser = dp.ofproto_parser
        match_ip = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst
        )
        self.del_flow(dp, match_ip)


    def add_flow(self, datapath, priority, match, actions):
        """
        Add flow entry
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                flags=ofproto.OFPFC_ADD,
                                priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def mod_flow(self, datapath, priority, match, actions):
        """
        Modify flow entry
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, flags=ofproto.OFPFC_MODIFY, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        """
        Delete flow entry
        :param datapath:
        :param match:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)


def print_with_timestamp(message):
    """
    Prints a message with the current time in minutes, seconds, and milliseconds.
    :param message: The message to print
    """
    # Get the current time
    current_time = time.time()

    # Calculate minutes, seconds, and milliseconds
    minutes = int(current_time // 60) % 60
    seconds = int(current_time % 60)
    milliseconds = int((current_time % 1) * 1000)

    # Print the message with the timestamp
    print(f"{minutes:02}:{seconds:02}.{milliseconds:03} - {message}")

