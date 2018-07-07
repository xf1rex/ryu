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

import networkx as nx


class ShortestPath13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShortestPath13, self).__init__(*args, **kwargs)
        self.mac_to_port = dict()
        self.arp_table = dict()
        self.net=nx.DiGraph()
        self.topology_api_app = self
    
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

        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

    

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
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edges_from([(dpid,src,{'port':msg.match['in_port']})]) 
            self.net.add_edge(src,dpid)

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            print "\033[91m"+"IPv6"+"\033[0m"
            return None

        elif isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

        elif isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

        else:
            print "\033[91m"+"exit Nonetype"+"\033[0m"
            return
            
        print "Packet from " + "\033[92m" + "Eth src: " + "\033[0m" + src + " to " + "\033[92m" + "Eth dst: " + "\033[0m" + dst
        print "Packet from " + "\033[92m" + "IP src: " + "\033[0m" + src_ip + " to " + "\033[92m" + "IP dst: " + "\033[0m" + dst_ip

        self.arp_table.setdefault(src_ip, {})
        if not eth.src in self.arp_table[src_ip]:
            print "\033[93m"+"ip src not in arp table"+"\033[0m"
            self.arp_table[src_ip] = src
            print "\033[92m"+"IP: "+"\033[0m"+src_ip+"\033[92m"+" Eth: "+"\033[0m"+self.arp_table[src_ip]+"\033[92m"+" added"+"\033[0m"
        if not dst_ip in self.arp_table:
            print "\033[93m"+"ip dst not in arp table"+"\033[0m"             
            return
        else:
            self.arp_table.setdefault(dst_ip, {})
            dst = self.arp_table[dst_ip]
            if dst == None:
                return
            if dst in self.net:
                print "\033[94m"+"Eth dst in net"+"\033[0m"
                path=nx.shortest_path(self.net, source=src, target=dst)
                print "\033[95m"+"Path"+"\033[0m"
                print path
                next=path[path.index(dpid)+1]
                out_port=self.net[dpid][next]['port']
            else:
                print "\033[91m"+"exit"+"\033[0m"
                return

        actions = [parser.OFPActionOutput(out_port)]


        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        # verify if we have a valid buffer_id, if yes avoid to send both
        # flow_mod & packet_out
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
