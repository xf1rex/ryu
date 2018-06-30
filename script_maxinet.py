#!/usr/bin/env python2
""" Launch Maxinet with fat tree, container docker hadoop, and routing for external access.
"""

import time
import subprocess
from MaxiNet.Frontend import maxinet
from MaxiNet.Frontend.container import Docker
from mininet.topo import Topo
from mininet.node import OVSSwitch
from MaxiNet.tools import Tools

if __name__ == '__main__':

    topo = Topo()

    # Add Host
    h1 = topo.addHost("master1", cls=Docker, ip="10.0.0.1", dimage="claudio/maxhadoop:1.0")
    h2 = topo.addHost("slave1", cls=Docker, ip="10.0.0.2", dimage="claudio/maxhadoop:1.0")
    h3 = topo.addHost("slave2", cls=Docker, ip="10.0.0.3", dimage="claudio/maxhadoop:1.0")
    h4 = topo.addHost("slave3", cls=Docker, ip="10.0.0.4", dimage="claudio/maxhadoop:1.0")
    h5 = topo.addHost("slave4", cls=Docker, ip="10.0.0.5", dimage="claudio/maxhadoop:1.0")
    h6 = topo.addHost("slave5", cls=Docker, ip="10.0.0.6", dimage="claudio/maxhadoop:1.0")
    h7 = topo.addHost("slave6", cls=Docker, ip="10.0.0.7", dimage="claudio/maxhadoop:1.0")
    h8 = topo.addHost("slave7", cls=Docker, ip="10.0.0.8", dimage="claudio/maxhadoop:1.0")

    h9 = topo.addHost("root", inNamespace=False, ip="10.0.0.100")

    # Add Switch
    s1 = topo.addSwitch("s1")
    s2 = topo.addSwitch("s2")
    s3 = topo.addSwitch("s3")
    s4 = topo.addSwitch("s4")

    s5 = topo.addSwitch("s5")
    s6 = topo.addSwitch("s6")
    s7 = topo.addSwitch("s7")
    s8 = topo.addSwitch("s8")

    s9 = topo.addSwitch("s9")
    s10 = topo.addSwitch("s10")

    s11 = topo.addSwitch("s11")

    # Add Link
    # Edge
    topo.addLink(h1, s7, bw=100)
    topo.addLink(h2, s7, bw=100)
    topo.addLink(h3, s8, bw=100)
    topo.addLink(h4, s8, bw=100)
    topo.addLink(h5, s9, bw=100)
    topo.addLink(h6, s9, bw=100)
    topo.addLink(h7, s10, bw=100)
    topo.addLink(h8, s10, bw=100)

    # Aggregation
    topo.addLink(s7, s3, bw=100)
    topo.addLink(s7, s4, bw=100)

    topo.addLink(s8, s3, bw=100)
    topo.addLink(s8, s4, bw=100)

    topo.addLink(s9, s5, bw=100)
    topo.addLink(s9, s6, bw=100)

    topo.addLink(s10, s5, bw=100)
    topo.addLink(s10, s6, bw=100)

    # Core
    topo.addLink(s3, s1, bw=100)
    topo.addLink(s5, s1, bw=100)
    topo.addLink(s4, s2, bw=100)
    topo.addLink(s6, s2, bw=100)

    # Others
    topo.addLink("s11", "root", autoconf=True)
    topo.addLink("s11", "s1", autoconf=True)

    mapping = {"s1": 0,
               "s2": 1,
               "s3": 0,
               "s4": 0,
               "s5": 1,
               "s6": 1,
               "s7": 0,
               "s8": 0,
               "s9": 1,
               "s10": 1,
               "s11": 0
               }

    cluster = maxinet.Cluster(minWorkers=2, maxWorkers=2)
    hnmap = {"wubuntu1": 0, "wubuntu2": 1}
    exp = maxinet.Experiment(cluster, topo, switch=OVSSwitch, nodemapping=mapping, hostnamemapping=hnmap)
    #   exp = maxinet.Experiment(cluster, topo, switch=OVSSwitch, nodemapping=mapping)
    exp.setup()

    print "waiting 5 seconds for routing algorithms on the controller to converge"
    time.sleep(5)







    exp.CLI(locals(), globals())

    exp.stop()
