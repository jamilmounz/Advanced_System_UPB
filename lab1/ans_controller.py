"""
ans_controller.py

SDN Controller for Lab 1 (Advanced Networked Systems SS25).
Implements switch learning logic for s1 and s2, and routing logic for s3.
Handles ARP requests, IP forwarding, flow rule management, and basic firewall policies.
Also handles ICMP Echo Requests (ping) to the router's own IPs.
"""

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
#!/usr/bin/env python3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import arp, ipv4, icmp, ether_types
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

ROUTER_DPID = 3          # The datapath‑id of router - s3
EXT_PORT    = 3          # On s3: port 3 connects to external host 'ext'
SER_PORT    = 2          # On s3: port 2 connects to internal server 'ser'

class LearningSwitch(app_manager.RyuApp):
    """
    Ryu controller that implements both learning switch and router behavior.
    Handles ARP requests for its own IPs correctly.
    Handles ICMP Echo Requests directed to its own IPs.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initializes controller data structures for MAC learning, ARP handling and buffering.
        """
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Data structures for controller state
        self.mac_to_port = {}    # dpid -> { mac -> port } : For L2 switches (s1, s2)
        self.arp_table   = {}    # ip_str -> mac_str : Learned IP-MAC mappings for router (s3)
        self.port_for_ip = {}    # ip_str -> in_port : Port where an IP was last seen by router (s3)
        self.arp_pending = {}    # dst_ip_str -> list[(orig_msg, in_port)] : Packets waiting for ARP resolution by router (s3)
        # self.ARP_TIMEOUT = 2     # Placeholder for potential future timeout logic


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a switch connects. Installs a default table-miss rule.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Installed table-miss flow rule for switch %d", datapath.id)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Helper method to install flow rules on switches/routers.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handles packets sent to the controller. Implements logic for both
        L2 learning switch (s1, s2) and L3 router (s3).
        """
        # --- Basic packet parsing ------------------------------------------- #
        msg       = ev.msg
        datapath  = msg.datapath
        dpid      = datapath.id
        ofproto   = datapath.ofproto
        parser    = datapath.ofproto_parser
        in_port   = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            self.logger.debug("Ignoring non-Ethernet packet")
            return
        if eth.src.startswith('01:') or eth.src.startswith('33:33:') or eth.src == 'ff:ff:ff:ff:ff:ff':
             self.logger.debug("Ignoring packet with multicast/broadcast source MAC: %s", eth.src)
             return

        dst = eth.dst
        src = eth.src

        # --- L2 Learning Switch Logic (for s1 and s2) ----------------------- #
        if dpid != ROUTER_DPID:
            self.mac_to_port.setdefault(dpid, {})
            if src not in self.mac_to_port[dpid] or self.mac_to_port[dpid][src] != in_port:
                 self.logger.info("Switch %d: Learned MAC %s on port %d", dpid, src, in_port)
                 self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
                self.logger.debug("Switch %d: Sending packet %s -> %s to known port %d", dpid, src, dst, out_port)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            else:
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                self.logger.debug("Switch %d: Flooding packet %s -> %s from port %d", dpid, src, dst, in_port)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return # End of L2 switch logic

        # --- L3 Router Logic (for s3) --------------------------------------- #
        # Check if the packet is ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None: return

            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            src_mac = arp_pkt.src_mac

            # Learn IP-to-MAC mapping
            is_router_ip = any(src_ip == port_ip for port_ip in PORT_TO_IP.values())
            if not is_router_ip:
                 if str(src_ip) not in self.arp_table or self.arp_table[str(src_ip)] != src_mac:
                     self.arp_table[str(src_ip)] = src_mac
                     self.port_for_ip[str(src_ip)] = in_port
                     self.logger.info("Router %d: Learned ARP %s -> %s on port %d", dpid, src_ip, src_mac, in_port)

                 # Process pending packets
                 pending = self.arp_pending.pop(str(src_ip), [])
                 if pending:
                     self.logger.info("Router %d: Processing %d pending packets for %s", dpid, len(pending), src_ip)
                 for orig_msg, orig_in_port in pending:
                     orig_pkt = packet.Packet(orig_msg.data)
                     orig_ip_pkt = orig_pkt.get_protocol(ipv4.ipv4)
                     if orig_ip_pkt:
                         orig_dst_ip_addr = ip_address(orig_ip_pkt.dst)
                         orig_dst_port = next((port for port, subnet in SUBNETS.items() if orig_dst_ip_addr in subnet), None)
                         if orig_dst_port is not None:
                             self._forward_ipv4(datapath, orig_msg, orig_in_port, orig_dst_port, src_mac)
                     else:
                         self.logger.warning("Router %d: Pending packet for %s was not IPv4?", dpid, src_ip)

            # Respond to ARP Requests for the router's own IPs
            if arp_pkt.opcode == arp.ARP_REQUEST and dst_ip in PORT_TO_IP.values():
                self.logger.info("Router %d: Received ARP request for own IP %s from %s (%s) on port %d",
                                 dpid, dst_ip, src_ip, src_mac, in_port)
                reply_port = next((port for port, ip in PORT_TO_IP.items() if ip == dst_ip), None)
                if reply_port is None:
                    self.logger.error("Router %d: Could not find port for router IP %s requested by %s", dpid, dst_ip, src_ip)
                    return
                reply_src_mac = PORT_TO_MAC[reply_port]
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=src_mac, src=reply_src_mac))
                arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_src_mac, src_ip=dst_ip,
                                               dst_mac=src_mac, dst_ip=src_ip))
                arp_reply.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_reply.data)
                datapath.send_msg(out)
                self.logger.info("Router %d: Sent ARP reply %s is-at %s to %s via port %d",
                                 dpid, dst_ip, reply_src_mac, src_ip, in_port)
                return # Done handling this ARP request

            elif arp_pkt.opcode == arp.ARP_REPLY:
                 self.logger.debug("Router %d: Received ARP reply: %s is at %s", dpid, src_ip, src_mac)
                 return # Done handling this ARP reply
            else:
                 self.logger.warning("Router %d: Received unknown ARP opcode %d", dpid, arp_pkt.opcode)
                 return

        # Check if the packet is IP
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt is None: return

            dst_ip_str = ip_pkt.dst
            src_ip_str = ip_pkt.src
            dst_ip_addr = ip_address(dst_ip_str)

            self.logger.debug("Router %d: Received IPv4 packet in_port=%d, %s -> %s, proto=%d",
                             dpid, in_port, src_ip_str, dst_ip_str, ip_pkt.proto)

            # Determine the "target port" for the destination IP's subnet.
            target_port_for_dst_ip_subnet = next((port for port, subnet in SUBNETS.items() if dst_ip_addr in subnet), None)

            # --- Apply Security Policies for ALL IP packets -------------------- #

            if ip_pkt.proto == 1 and dst_ip_str in PORT_TO_IP.values(): # It's an ICMP ping to a router's own IP
                # Find the router's own port associated with the destination IP
                router_gateway_port_for_dst_ip = next((port for port, ip in PORT_TO_IP.items() if ip == dst_ip_str), None)
                
                # If the packet arrived on a port different from the gateway's port, drop it.
                if router_gateway_port_for_dst_ip is not None and in_port != router_gateway_port_for_dst_ip:
                    self.logger.info("Router %d: Policy (Ping Other Gateways) - Dropping ICMP from %s (port %d) to another gateway %s (port %d)",
                                     dpid, src_ip_str, in_port, dst_ip_str, router_gateway_port_for_dst_ip)
                    return # Drop the packet


            # Policy 2.2: Dropping ICMP involving ext (EXT_PORT)
            if ip_pkt.proto == 1: # ICMP protocol
                if (in_port == EXT_PORT or target_port_for_dst_ip_subnet == EXT_PORT):
                    self.logger.info("Router %d: Policy 2.2 - Dropping ICMP involving ext (%d). InPort=%d, DstIP=%s (target_subnet_port=%s)",
                                     dpid, EXT_PORT, in_port, dst_ip_str, target_port_for_dst_ip_subnet)
                    return # Drop the packet

            # --- Check if packet is destined FOR THE ROUTER itself (after global policy checks) ---
            if dst_ip_str in PORT_TO_IP.values():
                self.logger.debug("Router %d: Packet is destined for the router itself (%s)", dpid, dst_ip_str)
                # Handle ICMP Echo Requests (Pings) to the router
                # This part will only be reached if the above policies didn't drop the packet.
                if ip_pkt.proto == 1: # ICMP protocol
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self.logger.info("Router %d: Received ICMP Echo Request from %s for %s on port %d",
                                         dpid, src_ip_str, dst_ip_str, in_port)
                        # Construct ICMP Echo Reply
                        echo_reply = packet.Packet()
                        reply_eth_src = PORT_TO_MAC[in_port]
                        echo_reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                                                  dst=eth.src, src=reply_eth_src))
                        # Set TTL to 64
                        echo_reply.add_protocol(ipv4.ipv4(dst=ip_pkt.src, src=ip_pkt.dst, proto=1, ttl=64))
                        echo_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=icmp_pkt.data))
                        echo_reply.serialize()

                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=echo_reply.data)
                        datapath.send_msg(out)
                        self.logger.info("Router %d: Sent ICMP Echo Reply to %s from %s via port %d",
                                         dpid, src_ip_str, dst_ip_str, in_port)
                        return
                    else:
                        # Handle other ICMP types directed to the router if needed (e.g., Destination Unreachable)
                        self.logger.debug("Router %d: Received other ICMP type %d for router IP. Ignoring.", dpid, icmp_pkt.type if icmp_pkt else "Unknown")
                        return
                else:
                    # Handle other protocols (TCP, UDP) directed to the router IP if needed
                    self.logger.debug("Router %d: Received non-ICMP packet (proto %d) for router IP. Ignoring.", dpid, ip_pkt.proto)
                    return

            # --- Packet is NOT for the router, proceed with FORWARDING logic ---
            dst_port = target_port_for_dst_ip_subnet # Reuse the determined target port for forwarding

            if dst_port is None:
                self.logger.warning("Router %d: No route found for destination %s. Dropping packet.", dpid, dst_ip_str)
                return

            # Policy 2.1: Dropping TCP/UDP between ser and ext (Applies to forwarded packets)
            if ({in_port, dst_port} == {SER_PORT, EXT_PORT}) and ip_pkt.proto in (6, 17):
                self.logger.info("Router %d: Policy 2.1 - Dropping TCP/UDP between ser (%d) and ext (%d). Proto=%d",
                                 dpid, SER_PORT, EXT_PORT, ip_pkt.proto)
                return

            # Normal IP Forwarding
            if dst_ip_str in self.arp_table:
                dst_mac = self.arp_table[dst_ip_str]
                self.logger.debug("Router %d: Forwarding IP %s -> %s to MAC %s via port %d",
                                 dpid, src_ip_str, dst_ip_str, dst_mac, dst_port)
                self._forward_ipv4(datapath, msg, in_port, dst_port, dst_mac)
            else:
                self.logger.info("Router %d: No ARP entry for %s. Buffering packet and sending ARP request via port %d.",
                                 dpid, dst_ip_str, dst_port)
                self.arp_pending.setdefault(dst_ip_str, []).append((msg, in_port))
                arp_req = self._build_arp_request(datapath, dst_port, dst_ip_addr)
                datapath.send_msg(arp_req)
                self.logger.debug("Router %d: Sent ARP request for %s via port %d", dpid, dst_ip_str, dst_port)


    def _build_arp_request(self, datapath, out_port, dst_ip_addr):
        """
        Helper: craft an ARP request for a given IP address out a specific port,
        wrapped in an OFPPacketOut message.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        src_ip_for_arp = PORT_TO_IP[out_port]
        src_mac_for_arp = PORT_TO_MAC[out_port]
        dst_ip_str = str(dst_ip_addr)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype = ether_types.ETH_TYPE_ARP,
                                           src = src_mac_for_arp, dst = 'ff:ff:ff:ff:ff:ff'))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=src_mac_for_arp, src_ip=src_ip_for_arp,
                                 dst_mac='00:00:00:00:00:00', dst_ip=dst_ip_str))
        pkt.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        return parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                   in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)

    def _forward_ipv4(self, datapath, msg, in_port, dst_port, dst_mac):
        """
        Helper: Installs an L3 flow rule and forwards a specific IPv4 packet.
        Assumes destination MAC (dst_mac) is known.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        src_mac = PORT_TO_MAC[dst_port]

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(dst_port)
        ]

        ip_pkt = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            self.logger.error("Router %d: _forward_ipv4 called with non-IPv4 packet?", datapath.id)
            return
        match  = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst = ip_pkt.dst)

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
            self.logger.debug("Router %d: Installed L3 flow for %s -> %s (via buffer_id %d)",
                             datapath.id, ip_pkt.src, ip_pkt.dst, msg.buffer_id)
        else:
            self.add_flow(datapath, 10, match, actions)
            self.logger.debug("Router %d: Installed L3 flow for %s -> %s",
                             datapath.id, ip_pkt.src, ip_pkt.dst)
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            self.logger.debug("Router %d: Sent PacketOut for %s -> %s",
                             datapath.id, ip_pkt.src, ip_pkt.dst)