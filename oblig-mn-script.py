#!/usr/bin/env python

""" Mininet script to test IN3230/IN4230-H25 Oblig assignment
    Enkel versjon uten xterm/vnc. Kjører programmer direkte i hostene.
"""

from mininet.topo import Topo
from mininet.cli import CLI
import time
import os

class Oblig(Topo):
    "Simple topology for Oblig."

    def __init__(self):
        Topo.__init__(self)

        # Lag 3 hosts: A, B og C
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')

        # Linker: A-B og B-C
        self.addLink(A, B, bw=10, delay='10ms', loss=0.0, use_tbf=False)
        self.addLink(B, C, bw=10, delay='10ms', loss=0.0, use_tbf=False)


def init_oblig(self, line):
    "Starter MIP-daemoner, server og klienter"
    net = self.mn
    A = net.get('A')
    B = net.get('B')
    C = net.get('C')

    print("*** Starter mipd på A, B, C")
    A.cmd("./bin/mipd -d usockA 10 &")
    B.cmd("./bin/mipd -d usockB 20 &")
    C.cmd("./bin/mipd -d usockC 30 &")

    time.sleep(1)

    print("*** Starter ping_server på B")
    B.cmd("./bin/ping_server usockB &")

    time.sleep(1)

    print("*** Kjører ping_client fra A → B (20)")
    print(A.cmd("./bin/ping_client usockA \"Hello IN3230\" 20"))

    print("*** Kjører ping_client fra C → B (20)")
    print(C.cmd("./bin/ping_client usockC \"Hello IN4230\" 20"))

    print("*** Kjører ping_client fra A → C (30) (skal gi timeout)")
    print(A.cmd("./bin/ping_client usockA \"Hello IN4230\" 30"))

    print("*** Kjører ping_client fra A → B (20) igjen (cache, lavere RTT)")
    print(A.cmd("./bin/ping_client usockA \"Hello again IN4230\" 20"))


# Koble custom kommando inn i Mininet CLI
CLI.do_init_oblig = init_oblig

# Topology
topos = {
    'oblig': (lambda: Oblig()),
}

!/usr/bin/env python

