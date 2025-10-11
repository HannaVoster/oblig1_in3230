#!/usr/bin/env python3
"""
Mininet script for testing MIP routing (Home Exam 1)
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
import time
import os


class H1Topo(Topo):
    "Larger topology for Home Exam 1."

    def __init__(self):
        Topo.__init__(self)

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')
        D = self.addHost('D')
        E = self.addHost('E')

        # Add links (samme som oppgaveteksten)
        self.addLink(A, B, bw=10, delay='10ms', loss=0.0, use_tbf=False)
        self.addLink(B, C, bw=10, delay='10ms', loss=0.0, use_tbf=False)
        self.addLink(B, D, bw=10, delay='10ms', loss=0.0, use_tbf=False)
        self.addLink(C, D, bw=10, delay='10ms', loss=0.0, use_tbf=False)
        self.addLink(D, E, bw=10, delay='10ms', loss=0.0, use_tbf=False)


def init_he1(self, line):
    """Starter MIP-daemoner og routingd på alle noder"""
    net = self.mn

    print("\n=== Starter MIP-daemoner ===")
    nodes = {'A': 10, 'B': 20, 'C': 30, 'D': 40, 'E': 50}

    # Start mipd på alle
    for n, mip in nodes.items():
        node = net.get(n)
        sock = f"/tmp/usock{n}"
        node.cmd(f"rm -f {sock}")
        node.cmd(f"./bin/mipd -d {sock} {mip} &")
        print(f"Started mipd on {n} (MIP={mip})")

    time.sleep(2)

    print("\n=== Starter routingd på alle noder ===")
    for n in nodes.keys():
        node = net.get(n)
        sock = f"/tmp/usock{n}"
        node.cmd(f"./bin/routingd {sock} > routingd_{n}.log 2>&1 &")
        print(f"Started routingd on {n}")

    time.sleep(3)

    print("\n=== Starter ping-server på E ===")
    E = net.get('E')
    E.cmd("./bin/ping_server /tmp/usockE &")
    time.sleep(2)

    print("\n=== Kjører test-ping fra A → E ===")
    A = net.get('A')
    result = A.cmd("./bin/ping_client /tmp/usockA \"Hello from A\" 50")
    print(result)

    print("\n=== Test ferdig. Du kan inspisere logger med: ===")
    print("cat routingd_A.log, cat routingd_B.log osv.")
    print("\n=== Åpner Mininet CLI (du kan kjøre kommandoer selv) ===")
    CLI(self.mn)


# Koble funksjonen inn i Mininet CLI
CLI.do_init_he1 = init_he1

topos = {'he1': (lambda: H1Topo())}
