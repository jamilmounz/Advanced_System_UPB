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

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

                # ---------- 1. OpenFlow datapaths (2 access switches + 1 “router”) ----------
        s1 = self.addSwitch('s1')     # internal‑hosts switch
        s2 = self.addSwitch('s2')     # internal‑server switch
        s3 = self.addSwitch('s3')     # plays the role of a router

        # ---------- 2. Hosts with IP config and default gateway ----------
        h1  = self.addHost('h1',ip='10.0.1.2/24',defaultRoute='via 10.0.1.1')
        h2  = self.addHost('h2',ip='10.0.1.3/24',defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser',ip='10.0.2.2/24',defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext',ip='192.168.1.123/24',defaultRoute='via 192.168.1.1')

        # ---------- 3. Common link parameters ----------
        linkopts = dict(cls=TCLink, bw=15, delay='10ms')

        # ---------- 4. Wire up the topology exactly as in the figure ----------
        # Subnet 10.0.1.0/24
        self.addLink(h1, s1, **linkopts)
        self.addLink(h2, s1, **linkopts)

        # Subnet 10.0.2.0/24
        self.addLink(ser, s2, **linkopts)

        # “Internet” side
        self.addLink(ext, s3, **linkopts)

        # Switch–router interconnects
        self.addLink(s1, s3, **linkopts)   # s1 ↔ s3
        self.addLink(s2, s3, **linkopts)   # s2 ↔ s3

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()