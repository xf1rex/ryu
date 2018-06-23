# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import copy
import networkx as nx
import random
from collections import defaultdict

class Ecmp13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Ecmp13, self).__init__(*args, **kwargs)
        self.mac_to_port = dict()
        self.arp_table = dict()
        self.net=nx.DiGraph()
        self.topology_api_app = self
        self.group_ids = []
        self.multipath_group_ids = {}
    	self.datapath_list = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def generate_openflow_gid(self):
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        self.group_ids.append(n)
        return n

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            p[path[0]] = (first_port,first_port)
            s1 = path[1]
            s2 = path[2]
            while s2 != path[len(path)-1]:
            	#print s1
            	#print s2
            	out_port = self.net[s1][s2]['port']
                p[s1] = (in_port, out_port)
                in_port = self.net[s2][s1]['port']
                s1 = s2
                s2 = path[path.index(s1)+1]
            p[s1] = (in_port, last_port)
            p[s2] = (last_port, last_port)
            paths_p.append(p)
            #print paths_p
        return paths_p

    def find_switches(self, paths, src, dst):
        """
        Find switches into the paths
        """
        switches_list = []
        for path in paths:
        	for s in path:
        		if s != src and s != dst and s not in switches_list:
        			switches_list.append(s)
        return switches_list

	
    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        paths = nx.all_shortest_paths(self.net, source=src, target=dst)
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        paths = nx.all_shortest_paths(self.net, source=src, target=dst)
        switches_in_paths = self.find_switches(paths, src, dst)
        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if out_port not in ports[in_port]:
                        ports[in_port].append(out_port)
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                # print out_ports 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (src, dst) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[src, dst] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[src, dst]
                    print group_id
                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port in out_ports:
                        bucket_weight = int(round((1/i) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        return paths_with_ports[0][src][1]


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        dpid = datapath.id

        buckets = []


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        print "Packet from " + "\033[92m" + "Eth src: " + "\033[0m" + src + " to " + "\033[92m" + "Eth dst: " + "\033[0m" + dst
        #print "Packet from " + "\033[92m" + "IP src: " + "\033[0m" + arp_pkt.src_ip + " to " + "\033[92m" + "IP dst: " + "\033[0m" + arp_pkt.dst_ip

        self.mac_to_port.setdefault(dpid, {})
        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edges_from([(dpid,src,{'port':msg.match['in_port']})]) 
            self.net.add_edge(src,dpid)
                
        out_port = ofproto.OFPP_FLOOD

        if arp_pkt==None and ip_pkt==None:
            print "\033[91m"+"exit Nonetype"+"\033[0m"
            return
        
        elif pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            print "\033[91m"+"IPv6"+"\033[0m"
            return None


        elif isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_table.setdefault(arp_pkt.src_ip, {})
            if not eth.src in self.arp_table[arp_pkt.src_ip]:
                print "\033[93m"+"ip src not in arp table"+"\033[0m"
                self.arp_table[arp_pkt.src_ip] = eth.src
                print "\033[92m"+"IP: "+"\033[0m"+arp_pkt.src_ip+"\033[92m"+" Eth: "+"\033[0m"+self.arp_table[arp_pkt.src_ip]+"\033[92m"+" added"+"\033[0m"
            if not arp_pkt.dst_ip in self.arp_table:
                print "\033[93m"+"ip dst not in arp table"+"\033[0m"             
                return
            else:
                mod = False
                dst = self.arp_table[arp_pkt.dst_ip]
                if dst == None:
                    return
                if dst in self.net:
                    print "\033[94m"+"Eth dst in net"+"\033[0m"
                    for pid in self.mac_to_port:
                        if dst in self.mac_to_port[pid]:
                            dst_dpid = pid
                    out_port = self.install_paths(src, self.mac_to_port[dpid][src], dst, self.mac_to_port[dst_dpid][dst], arp_pkt.src_ip, arp_pkt.dst_ip)
                    self.install_paths(dst, self.mac_to_port[dst_dpid][dst], src, self.mac_to_port[dpid][src], arp_pkt.dst_ip, arp_pkt.src_ip) # reverse
                    

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)  
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        self.datapath_list[ev.switch.dp.id] = ev.switch.dp
