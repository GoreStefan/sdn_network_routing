"""
INSERT ALL IMPORTS
"""

class ControllerMain(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ControllerMain, self).__init__(*args, **kwargs)


        MAX_PATH = 100 
        """

        """
        self.mac_to_port = {} 
        """
        In the arp table we will have the following association: 
        Association ip = mac
        arp_table = 
            { 
            10.0.0.24 : 00.00.00.01
            11.0.0.24 : 00.00.00.02
            ip : mac
            }
        """
        self.arp_table = {}
        
        """
        dic = {id_forward = paths}
        dove: 
            id_forward   <- build_connection_between_hosts_id
            paths        <- get_optimal_path
        """
        self.paths_per_flow = {} 
        """
        """
        self.chosen_path_per_flow = {}

        self.datapath_list = {}
        self.arp_table = {}
        self.swithes = []

        """
        Data structure with following example structure: 
        self.hosts = {
            "00:1A:2B:3C:4D:5E": ("dpid_1", 1), 
            "11:22:33:44:55:66": ("dpid_2", 2),
            }
        
        The association is the following:

        mac --> (id switch, port number)
        """
        self.hosts = {}


        self.data_map = {}
        """
        Example of how data_map dictonary will be structured.

        self.data_map = {
            1: {  # dpid_rec
                2212: {  # dpid_sent
                    'in_port': 21,
                    'bw': [],
                    'latencyRTT': [
                        {'timestamp': 1627356123.123, 'value': 15.6},  # Example latencyRTT data
                        {'timestamp': 1627356187.456, 'value': 16.2}
                    ]
                    }
                }
        }
        """

        self.latency_dict = {}
        """
        Data la funzione convert_data_map_to_dict possiamo convertire 
        data_map in latenvy dict la quale avrà quest'ultima forma

        latency_dict = {
                    1: {    #dpif_rec
                        2212:{      #dpic_sent
                            15.6            #last value latencyRTT or bw
                        }
                    }    
        }
        """

        self.last_arrived_package = {}



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
            #hub.sleep(self.waitTillStart + 5)
            #self.waitTillStart += 0.1
            print("MONITORING LATENCY STARTED dpid: {}".format(datapath.id))
            #self.latency_measurement_flag = True
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
                whole_data = str(time.time()) + '#' + str(dpid) + '#'
                pkt.add_protocol(bytes(whole_data, "utf-8"))
                pkt.serialize()
                data = pck.data
                #building and sending the message
                req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                            in_port, actions, data)
                datapath.send_msg(req)
                hub.sleep(interval_update_latency)


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
            hub.sleep(0.5 + self.waitTillStart)
            # self.waitTillStart += 0.25
            iterator = 0
            while True:
                # data = ''
                # self.send_echo_request(datapath, data)
                if iterator % 2 == 0:
                    self.send_port_stats_request(datapath)
                else:
                    self.send_flow_stats_request(datapath)
                iterator += 1
                hub.sleep(interval_controller_switch_latency)

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
                # print dpid, pkt
                src_ip = arp_pkt.src_ip
                dst_ip = arp_pkt.dst_ip

                if arp_pkt.opcode == arp.ARP_REPLY:
                    self.arp_table[src_ip] = src_mac
                    h1 = self.hosts[src_mac]
                    h2 = self.hosts[dst_mac]
                    if (h1, h2) not in self.already_routed:
                        self.routing_arp(h1, h2, src_ip, dst_ip)
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
                            self.routing(h1, h2, src_ip, dst_ip)
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
                        self.routing(h1, h2, src_ip, dst_ip)
                        self.already_routed_ip.append((h1, h2))

        def routing(self, h1, h2, src_ip, dst_ip):
            """
            Routing of ARP requests
            :param h1:  derived from h1 = self.hosts[src_mac] 
            :param h2:  
            :param src_ip:  it's the source's ip
            :param dst_ip:
            """
            #where h[0] and h[1] are the dpid of the switches
            path_optimal, paths = self.get_optimal_path(self.latency_dict, h1[0], h2[0])
            self.install_path(self, path_optimal, h1[1], h2[1], src_ip, dst_ip, 'arp')

        def get_optimal_path (self, latency_dict, src, dst):
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
        
        def install_path(self, controller, chosenPath, first_port, last_port, ip_src, ip_dst, type):
            """
            Given the best_path to we need to insert into the OpenFlow 
            tables the entrys to create the path from the src ip to 
            dst ip.

            The paths will have the following structure ["dpid1" ,"dpid2" , ...]
            The first and last port is the ports that connects the 2 hosts to the first
            and last switches. 

            """

            #here we add to the path also the ports that will handles the flow
            path = self.add_ports_to_path(controller, chosenPath, first_port, last_port)
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
            for node in path.key(): 
                dp = controller.dpidToDatapath[node]
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser
                actions = []
                in_port = path[node][0]

                actions = [ofp_parser.OFPActionOutput(path[node][1])]
                #32768 è il numero di priorità del pacchetto
                controller.add_flow(dp, 32768, self.get_match(type, ofp_parser, ip_src, ip_dst), actions)






