#!/usr/bin/env python
"""
Mininet script for IN3230/IN4230 – MIPTP test
Struktur og rekkefølge følger hjemmeeksamen 1-oppsettet (mipd → routingd → miptpd → apper).
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import os, time, signal

terms = []


# ===== TOPOLOGY =====
class MIPTPTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        A = self.addHost('A')
        B = self.addHost('B')
        self.addLink(A, B, bw=10, delay='10ms')


# ===== OPEN TERMINAL =====
def openTerm(self, node, title, geometry, cmd="bash"):
    display, tunnel = tunnelX11(node)
    return node.popen([
        "xterm", "-hold",
        "-title", title,
        "-geometry", geometry,
        "-display", display,
        "-e", cmd
    ])


# ===== INIT COMMAND =====
def init_miptp(self, line):
    net = self.mn
    A = net.get('A')
    B = net.get('B')

    print("\n=== Starting MIP daemons ===")
    terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0", "./mipd -d usockA 42"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPD [B]", "80x14+555+0", "./mipd -d usockB 99"))
    time.sleep(3)

    print("\n=== Starting routing daemons ===")
    terms.append(openTerm(self, A, "ROUTING [A]", "80x14+0+220", "./routingd -d usockA"))
    time.sleep(1)
    terms.append(openTerm(self, B, "ROUTING [B]", "80x14+555+220", "./routingd -d usockB"))
    time.sleep(3)

    print("\n=== Starting MIPTP daemons ===")
    terms.append(openTerm(self, A, "MIPTPD [A]", "80x14+0+440", "./miptpd usockA miptp_appA.sock"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPTPD [B]", "80x14+555+440", "./miptpd usockB miptp_appB.sock"))
    time.sleep(3)

    print("\n=== Launching applications ===")

    print("\n=== Launching file transfer test ===")

    # Start server (port 99) på B – lagrer mottatte filer i /tmp
    terms.append(openTerm(self, B, "MIPTP SERVER [B:99]", "80x20+1110+440",
                        "cd bin && sudo ./miptpd_server 99 miptp_appB.sock /tmp"))
    time.sleep(3)

    # Lag testfil på A
    terms.append(openTerm(self, A, "PREPARE FILE [A]", "80x10+0+660",
                        "cd bin && dd if=/dev/urandom of=testfile.dat bs=1K count=32 && echo 'File ready on A'"))
    time.sleep(2)

    # Start klienten som sender filen
    terms.append(openTerm(self, A, "MIPTP CLIENT [A]", "80x20+0+880",
                        "cd bin && sudo ./miptpd_client testfile.dat 2 99 miptp_appA.sock"))

    # # Start server (port 99) på B
    # terms.append(openTerm(self, B, "SERVER [B:99]", "80x20+1110+440",
    #                       "./test_server miptp_appB.sock"))
    # time.sleep(2)
    # # Start klient (port 42) på A – sender til MIP 99
    # terms.append(openTerm(self, A, "CLIENT [A:42]", "80x20+0+660",
    #                       "./test_app miptp_appA.sock 'Hello from A' 99"))

    print("\n✅ MIPTP test setup complete.")
    print("Use the Mininet CLI to monitor logs or type 'exit' to stop.")


# ===== CLEAN EXIT =====
orig_EOF = CLI.do_EOF
def do_EOF(self, line):
    for t in terms:
        try:
            os.kill(t.pid, signal.SIGKILL)
        except Exception:
            pass
    return orig_EOF(self, line)

CLI.do_EOF = do_EOF
CLI.do_init_miptp = init_miptp

topos = {"miptp": (lambda: MIPTPTopo())}

