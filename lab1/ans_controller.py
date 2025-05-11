"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import arp, ipv4, ether_types
from ipaddress import ip_address, ip_network

# Router’s own MAC / IP per port
PORT_TO_MAC = {1: '00:00:00:00:01:01',
               2: '00:00:00:00:01:02',
               3: '00:00:00:00:01:03'}
PORT_TO_IP  = {1: '10.0.1.1',
               2: '10.0.2.1',
               3: '192.168.1.1'}

# Convenient subnet objects
SUBNETS = {1: ip_network('10.0.1.0/24'),
           2: ip_network('10.0.2.0/24'),
           3: ip_network('192.168.1.0/24')}

ROUTER_DPID = 3          # The datapath‑id of s3
EXT_PORT    = 3          # On s3: port 3 connects to 'ext'
SER_PORT    = 2          # On s3: port 2 connects to 'ser'

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        # { datapath_id : { mac : port } }
        self.mac_to_port = {}
        self.arp_table   = {}    # ip → mac (learned from ARP replies)
        self.port_for_ip = {}    # ip → out_port (learned dynamically)
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg       = ev.msg
        datapath  = msg.datapath
        dpid      = datapath.id
        ofproto   = datapath.ofproto
        parser    = datapath.ofproto_parser
        in_port   = msg.match['in_port']

        # Parse Ethernet header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return                       # not an Ethernet packet

        dst = eth.dst
        src = eth.src
        if dpid != ROUTER_DPID:
            # --- 1) Learn ---------------------------------------------------- #
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            # --- 2) Decide output port -------------------------------------- #
            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port)]

            # --- 3) Install flow rule (without buffer_id) ------------------- #
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)   # ← only 4 args

            # --- 4) Send packet back to the switch -------------------------- #
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            else:
                data = None

            out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
            datapath.send_msg(out)
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)

            # a) We learn hosts' MACs from *any* ARP that is not ours
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
                self.port_for_ip[arp_pkt.src_ip] = in_port

            # b) Answer ARP‑Requests for the router’s own IPs
            if (arp_pkt.opcode == arp.ARP_REQUEST and
                    arp_pkt.dst_ip in PORT_TO_IP.values()):
                out_mac = PORT_TO_MAC[in_port]        # MAC of the incoming subnet
                arp_reply = packet.Packet()
                arp_reply.add_protocol(
                    ethernet.ethernet(ethertype=eth.ethertype,
                                      src=out_mac, dst=eth.src))
                arp_reply.add_protocol(
                    arp.arp(opcode=arp.ARP_REPLY,
                            src_mac=out_mac, src_ip=arp_pkt.dst_ip,
                            dst_mac=eth.src, dst_ip=arp_pkt.src_ip))
                arp_reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions,
                                          data=arp_reply.data)
                datapath.send_msg(out)
                return   # done with this ARP packet
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)

            dst_ip = ip_address(ip_pkt.dst)
            src_ip = ip_address(ip_pkt.src)

            # Which subnet is the destination in?
            dst_port = None
            for port, subnet in SUBNETS.items():
                if dst_ip in subnet:
                    dst_port = port
                    break
            if dst_port is None:
                return  # we don't route outside the known subnets

            # -- Security policies ------------------------------------------------ #
            if ((in_port == EXT_PORT and dst_port == SER_PORT) or
                (in_port == SER_PORT and dst_port == EXT_PORT)):
                if ip_pkt.proto in (6, 17):      # TCP or UDP
                    return
            if in_port == EXT_PORT and dst_port != EXT_PORT:
                if ip_pkt.proto == 1:            # ICMP echo from ext to internal
                    return

            # -- Normal forwarding ------------------------------------------------ #
            if dst_ip not in self.arp_table:
                # No MAC yet – send an ARP‑Request (gratuitous) and buffer packet
                arp_req = packet.Packet()
                arp_req.add_protocol(
                    ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                      src=PORT_TO_MAC[dst_port],
                                      dst='ff:ff:ff:ff:ff:ff'))
                arp_req.add_protocol(
                    arp.arp(opcode=arp.ARP_REQUEST,
                            src_mac=PORT_TO_MAC[dst_port],
                            src_ip=str(PORT_TO_IP[dst_port]),
                            dst_mac='00:00:00:00:00:00',
                            dst_ip=str(dst_ip)))
                arp_req.serialize()
                datapath.send_msg(
                    parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER,
                                        actions=[parser.OFPActionOutput(dst_port)],
                                        data=arp_req.data))
                return                      # wait for ARP reply

            dst_mac = self.arp_table[str(dst_ip)]
            src_mac = PORT_TO_MAC[dst_port]

            actions = [parser.OFPActionSetField(eth_src=src_mac),
                       parser.OFPActionSetField(eth_dst=dst_mac),
                       parser.OFPActionOutput(dst_port)]

            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_dst=str(dst_ip))
            self.add_flow(datapath, 10, match, actions)

            # send the original packet along the new actions path
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # Use the buffer if available
                datapath.send_msg(
                    parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=msg.buffer_id,
                                        in_port=in_port,
                                        actions=actions))
            else:
                # No buffer available, include the data
                datapath.send_msg(
                    parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=in_port,
                                        actions=actions,
                                        data=msg.data))
            return