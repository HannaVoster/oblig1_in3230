#!/usr/bin/env python3
"""
Mininet script to test MIPTP over MIP daemons
IN3230/IN4230 — Hanna’s Go-Back-N Test
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import os
import time
import signal

terms = []


# ===== Topology Definition =====
class MIPTPTestTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # To noder koblet direkte (A <-> B)
        A = self.addHost('A')
        B = self.addHost('B')
        self.addLink(A, B, bw=10, delay='10ms')


# ===== Helper: open XTerm on node =====
def openTerm(self, node, title, geometry, cmd="bash"):
    display, tunnel = tunnelX11(node)
    return node.popen([
        "xterm", "-hold",
        "-title", title,
        "-geometry", geometry,
        "-display", display,
        "-e", cmd
    ])


# ===== Custom Init Command =====
def init_miptp(self, line):
    """
    Starts:
      - 2x MIP daemons (A,B)
      - 2x MIPTP daemons (A,B)
      - test_server on B
      - test_app on A
    """

    net = self.mn
    A = net.get('A')
    B = net.get('B')

    print("\n=== Starting MIP daemons ===")
    terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0", "./mipd -d usockA 42"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPD [B]", "80x14+555+0", "./mipd -d usockB 99"))
    time.sleep(2)

    print("\n=== Starting MIPTP daemons ===")
    # MIPTP kobles til MIP sin socket + lager egen app-socket
    terms.append(openTerm(self, A, "MIPTPD [A]", "80x14+0+220", "./miptpd usockA miptp_appA.sock"))
    terms.append(openTerm(self, B, "MIPTPD [B]", "80x14+555+220", "./miptpd usockB miptp_appB.sock"))
    time.sleep(2)

    print("\n=== Launching test applications ===")
    # Start server (port 99) på node B
    terms.append(openTerm(self, B, "SERVER [B:99]", "80x20+1110+220", "./bin/test_server miptp_appB.sock"))
    time.sleep(2)

    # Start client (port 42) på node A
    terms.append(openTerm(self, A, "CLIENT [A:42]", "80x20+0+440", "./bin/test_app miptp_appA.sock"))

    print("\n✅ MIPTP test setup complete.")
    print("Use the Mininet CLI to monitor logs or type 'exit' to stop.")


# ===== Clean Exit =====
orig_EOF = CLI.do_EOF


def do_EOF(self, line):
    for t in terms:
        try:
            os.kill(t.pid, signal.SIGKILL)
        except Exception:
            pass
    return orig_EOF(self, line)


CLI.do_EOF = do_EOF


# Register custom Mininet command
CLI.do_init_miptp = init_miptp


# ===== Topology Mapping =====
topos = {"miptp": (lambda: MIPTPTestTopo())}
