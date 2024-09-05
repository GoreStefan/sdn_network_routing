"""
    # Link hosts to switch s1
    net.addLink(h1, s1, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)
    net.addLink(h2, s1, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)
    net.addLink(h3, s1, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)

    # Link hosts to switch s3
    net.addLink(h4, s3, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)
    net.addLink(h5, s3, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)
    net.addLink(h6, s3, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)
    """
    # Additional link from h1 to s2 for migration
    #net.addLink(h1, s2, delay='14ms', use_tbf=True, bw=4, max_queue_size=1000, burst=1000000)


@set_ev_cls(event.EventHostAdd)
def _event_host_add_handler(self, ev):
    msg = ev.host.to_dict()
    host = ev.host
    host_info = {
        'MAC Address': host.mac,
        'IP Addresses': list(host.ipv4),
        'Switch DPID': host.port.dpid if host.port else 'N/A',
        'Port Number': host.port.port_no if host.port else 'N/A',
    }
    print_with_timestamp("New host added:")
    for key, value in host_info.items():
        print(f"{key}: {value}")


def isLinkHostSwitch(self, dpid, port_no):
        links = get_link(self, None)
        for l in links:
            if (l.src.dpid == dpid and l.src.port_no == port_no) or (l.dst.dpid == dpid and l.dst.port_no == port_no):
                return False
        return True


@set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
def port_modify_handler(self, ev):
    """
    When the host will migrate, it will pop up this function. 
    The purpose of this function is to get all the 
    switches in the topology. And to get the host of a 
    particular switch. 
    """
    print("PORT MODIFY")
    port = ev.port
    dp = ev.dp
    pprint(self.hosts)
    switches = get_switch(self, None)
    for l in switches:
        print (" \t\t" + str(l))
    hosts = get_host(self, dpid=dp.id)
    for l in hosts:
        print (" \t\t" + str(l))


def host_adding(self, datapath, port_no):
    hub.sleep(10)
    print("inside host migration: return host")
    #it means the new host was added to switch
    #We can retrive the new host with RYU TOPOLOGY API
    hosts_tmp = get_host(self, dpid=datapath.id)
    #while not hosts_tmp:
        #hosts_tmp = get_host(self, dpid=datapath.id)
        #print("waiting")
    #print("*************************************")
    for host in hosts_tmp:
        print (" \t\t" + str(host))
    for host in hosts_tmp:
        print (" \t\t" + str(host))
        if host.port.port_no == port_no:
            host_tmp = host
            self.hosts[host_tmp.mac] = (datapath.id, port_no)
            print("Aggiunto")
    #we insert this new host inside the self.hosts
    print("***********************************")

def install_path(self, chosenPath, first_port, last_port, ip_src, ip_dst, type):

    path = self.add_ports_to_path(chosenPath, first_port, last_port)
    #switches_in_paths = set().union(*chosenPath)

    for node in chosenPath:
        dp = self.dpidToDatapath[node]
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        ports = defaultdict(list)
        actions = []

        if node in path:
            in_port = path[node][0]
            out_port = path[node][1]
            if out_port not in ports[in_port]:
                ports[in_port].append(out_port)

        for in_port in ports:
            out_ports = ports[in_port]
            actions = [ofp_parser.OFPActionOutput(out_ports[0])]
            #self.add_flow_with_timer(dp, self.get_priority(type), self.get_match(type, ofp_parser, ip_src, ip_dst), actions, idle_timeout=15)
            self.add_flow(dp, self.get_priority(type), self.get_match(type, ofp_parser, ip_src, ip_dst), actions)


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
            self.add_flow_specific_switch(switch, src_ip, dst_ip, self.data_map[switch][following_switch]['in_port'])#output port
            self.add_arp_flow_specific_switch(switch, src_ip, dst_ip, self.data_map[switch][following_switch]['in_port'])
    hub.sleep(0.1)
    # second: mod flows
    for switch in flow_mod_list:
        index = new_path.index(switch)
        next_index = index + 1
        if next_index < len(new_path):
            following_switch = new_path[next_index]
            self.mod_flow_specific_switch(switch, src_ip, dst_ip,
                                            self.data_map[switch][following_switch]['in_port'])#output port
            self.mod_arp_flow_specific_switch(switch, src_ip, dst_ip,
                                            self.data_map[switch][following_switch]['in_port'])#output port
    # third: delete flows
    for switch in flow_delete_list:
        # clean up bw flow list
        try:
            self.bandwith_flow_dict[switch][src_ip].pop(dst_ip, None)
        except KeyError:
            print("Key {} not found".format(dst_ip))
        self.del_flow_specific_switch(switch, src_ip, dst_ip)
        self.del_arp_flow_specific_switch(switch, src_ip, dst_ip)
    #self.add_flow_specific_switch(new_path[0], src_ip, dst_ip, self.hosts[self.arp_table[src_ip]][1])
    #self.add_flow_specific_switch(new_path[-1], src_ip, dst_ip, self.hosts[self.arp_table[dst_ip]][1])
    #self.add_arp_flow_specific_switch(new_path[-1], src_ip, dst_ip, self.hosts[self.arp_table[dst_ip]][1])

def add_arp_flow_specific_switch(self, switch, arp_spa, arp_tpa, out_port):
    """
    Add a flow entry for ARP packets on a specific switch based on ARP sender and target IP addresses.

    :param switch: The switch identifier.
    :param arp_spa: ARP Sender Protocol Address (source IP in ARP).
    :param arp_tpa: ARP Target Protocol Address (destination IP in ARP).
    :param out_port: The output port where the packets should be forwarded.
    """
    dp = self.dpidToDatapath[switch]  # Get the datapath object for the switch
    ofp_parser = dp.ofproto_parser    # Get the OpenFlow parser

    # Define the action to output the packet to the specified port
    actions = [ofp_parser.OFPActionOutput(out_port)]

    # Create a match for ARP packets with specific sender and target protocol addresses
    match_arp = ofp_parser.OFPMatch(
        eth_type=0x0806,  # Ethernet type for ARP
        arp_spa=arp_spa,  # ARP Sender Protocol Address (source IP in ARP)
        arp_tpa=arp_tpa   # ARP Target Protocol Address (destination IP in ARP)
    )

    # Add the flow with a specified priority (e.g., 1)
    self.add_flow(dp, 32768, match_arp, actions)

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

def mod_arp_flow_specific_switch(self, switch, ip_src, ip_dst, out_port):
    dp = self.dpidToDatapath[switch]
    ofp_parser = dp.ofproto_parser
    actions = [ofp_parser.OFPActionOutput(out_port)]
    match_ip = ofp_parser.OFPMatch(
        eth_type=0x0806,
        arp_spa=ip_src,
        arp_tpa=ip_dst
    )
    self.mod_flow(dp, 32768, match_ip, actions)


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

def del_arp_flow_specific_switch(self, switch, arp_spa, arp_tpa):
    """
    Delete flow entry for ARP packets on a specific switch based on ARP sender and target IP addresses.

    :param switch: The switch identifier.
    :param arp_spa: ARP Sender Protocol Address (source IP address in ARP).
    :param arp_tpa: ARP Target Protocol Address (destination IP address in ARP).
    """
    dp = self.dpidToDatapath[switch]  # Get the datapath for the switch
    ofp_parser = dp.ofproto_parser  # Get the OpenFlow parser

    # Create a match for ARP packets with specific sender and target protocol addresses
    match_arp = ofp_parser.OFPMatch(
        eth_type=0x0806,  # Ethernet type for ARP
        arp_spa=arp_spa,  # ARP Sender Protocol Address (source IP in ARP)
        arp_tpa=arp_tpa   # ARP Target Protocol Address (destination IP in ARP)
    )

    # Delete the flow with the specified ARP match
    self.del_flow(dp, match_arp)

def delete_flows_for_path(self, path, src_ip, dst_ip):
    """
    Delete flow entries on all switches in the path based on src_ip and dst_ip.

    :param path: List of switches representing the path.
    :param src_ip: Source IP address.
    :param dst_ip: Destination IP address.
    """
    for switch in path:
        self.del_flow_specific_switch(switch, src_ip, dst_ip)
        self.del_arp_flow_specific_switch(switch, src_ip, dst_ip)


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
