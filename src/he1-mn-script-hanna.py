#!/usr/bin/env python

""" mininet script to test IN3230/IN4230 HE1 assignments"""

#!/usr/bin/env python

"""
Mininet-script for IN3230/IN4230 HE1
— Oppdatert for ikke-grafisk kjøring (ingen X11/xterm)
— Kjører alle prosesser i bakgrunnen med logging til /tmp/
"""

from mininet.topo import Topo
from mininet.cli import CLI
import os
import signal
import time


# ---------------------------
#  TOPOLOGI
# ---------------------------

class HE1Topo(Topo):
    "Larger topology for home exams."

    def __init__(self):
        Topo.__init__(self)

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')
        D = self.addHost('D')
        E = self.addHost('E')

        # Add links (1% loss)
        self.addLink(A, B, bw=10, delay='10ms', loss=1.0, use_tbf=False)
        self.addLink(B, C, bw=10, delay='10ms', loss=1.0, use_tbf=False)
        self.addLink(B, D, bw=10, delay='10ms', loss=1.0, use_tbf=False)
        self.addLink(C, D, bw=10, delay='10ms', loss=1.0, use_tbf=False)
        self.addLink(D, E, bw=10, delay='10ms', loss=1.0, use_tbf=False)


# ---------------------------
#  HJELPEFUNKSJONER
# ---------------------------

HE1_DIR = os.getcwd()  # hvor dine ./mipd, ./routingd osv ligger


def run_in_bg(node, title, cmd):
    """
    Kjør kommando i bakgrunnen på gitt node.
    Logger stdout/stderr til /tmp/<title>.log
    """
    log_path = f"/tmp/{title.replace(' ', '_')}.log"
    full_cmd = f"cd {HE1_DIR} && {cmd} > {log_path} 2>&1 &"
    node.cmd(full_cmd)
    print(f"[INFO] Started {title} on {node.name}, logging to {log_path}")


# ---------------------------
#  INIT-HE1 KOMMANDO
# ---------------------------

def init_he1(self, line):
    "Starter MIP- og routing-daemoner og ping-testene."
    net = self.mn
    A, B, C, D, E = [net.get(x) for x in ('A', 'B', 'C', 'D', 'E')]

    # --- MIP Daemons ---
    run_in_bg(A, "mipd_A", "./mipd -d usockA 10")
    run_in_bg(B, "mipd_B", "./mipd -d usockB 20")
    run_in_bg(C, "mipd_C", "./mipd -d usockC 30")
    run_in_bg(D, "mipd_D", "./mipd -d usockD 40")
    run_in_bg(E, "mipd_E", "./mipd -d usockE 50")

    print("[INFO] Waiting for MIP daemons to stabilize...")
    time.sleep(3)

    # --- Routing Daemons ---
    run_in_bg(A, "routingd_A", "./routingd -d usockA")
    run_in_bg(B, "routingd_B", "./routingd -d usockB")
    run_in_bg(C, "routingd_C", "./routingd -d usockC")
    run_in_bg(D, "routingd_D", "./routingd -d usockD")
    run_in_bg(E, "routingd_E", "./routingd -d usockE")

    print("[INFO] Waiting for routing to converge...")
    time.sleep(5)

    # --- Server ---
    run_in_bg(E, "ping_server_E", "./ping_server usockE")
    time.sleep(2)

    # --- Clients (flere tester) ---
    run_in_bg(A, "ping_client_A_TTL8", './ping_client usockA "Hello from A" 50 8')
    run_in_bg(C, "ping_client_C_TTL8", './ping_client usockC "Hello from C" 50 8')
    run_in_bg(A, "ping_client_A_TTL1", './ping_client usockA "Hello with TTL 1" 50 1')
    run_in_bg(C, "ping_client_C_TTL3", './ping_client usockC "Hello with TTL 3" 50 3')

    # --- Link-failure test ---
    print("[INFO] Simulating link failure B-D for 20 seconds...")
    net.configLinkStatus('B', 'D', 'down')
    time.sleep(10)

    run_in_bg(A, "ping_client_A_after_fail", './ping_client usockA "After fail" 50 8')

    net.configLinkStatus('B', 'D', 'up')
    print("[INFO] Link B-D restored, waiting for reconvergence...")
    time.sleep(5)

    run_in_bg(A, "ping_client_A_after_recover", './ping_client usockA "After recover" 50 8')

    print("[INFO] All background processes started. Check /tmp/*.log for output.")


# ---------------------------
#  MININET CLI-KOMMANDOER
# ---------------------------

CLI.do_init_he1 = init_he1

orig_EOF = CLI.do_EOF


def do_EOF(self, line):
    """Kill all running daemons when exiting Mininet."""
    net = self.mn
    for name in ('A', 'B', 'C', 'D', 'E'):
        h = net.get(name)
        h.cmd("pkill -f mipd || true")
        h.cmd("pkill -f routingd || true")
        h.cmd("pkill -f ping_server || true")
        h.cmd("pkill -f ping_client || true")
    print("[INFO] All background processes terminated.")
    return orig_EOF(self, line)


CLI.do_EOF = do_EOF


# ---------------------------
#  TOPOLOGI-REGISTER
# ---------------------------

topos = {'he1': (lambda: HE1Topo())}
