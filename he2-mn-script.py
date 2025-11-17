#!/usr/bin/env python3

""" mininet script to test IN4230 HE2 assignments"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import time
import os
import signal

# Usage example:
#
# 1. First, run the following command to start mininet with this script:
#    sudo -E mn --mac --custom he2-mn-script.py --topo he2 --link tc
#
# 2. Second, inside the mininet console run 'init_he2'
#
# 3. Third, inside the mininet console run 'EOF' to gracefully kill
#    the mininet console


class TopologyManager:
    """Manages multiple topologies and their associated terminals."""

    def __init__(self):
        self.terms = []

    def openTerm(self, node, title, geometry, cmd="bash", hold=True):
        """
        Open an xterm window for a node.
        Args:
            node: Mininet node
            title: Window title
            geometry: Window geometry string (e.g., "80x14+0+0")
            cmd: Command to execute in the terminal
            hold: Keep window open after command finishes (default: True)
        """
        display, tunnel = tunnelX11(node)

        # Build xterm arguments
        xterm_args = [
            "xterm",
            "-title", "'%s'" % title,
            "-geometry", geometry,
            "-display", display,
        ]

        # Add -hold flag only if hold is True
        if hold:
            xterm_args.append("-hold")

        # Add command
        xterm_args.extend(["-e", cmd])

        term = node.popen(xterm_args)
        self.terms.append(term)
        return term

    def cleanup(self):
        """Kill all opened terminal windows."""
        for term in self.terms:
            try:
                os.kill(term.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # Process already terminated
        self.terms.clear()


class HE2Topo(Topo):
    """Simple topology for home exam 2."""

    def __init__(self):
        Topo.__init__(self)

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')

        # Add links
        self.addLink(A, B, bw=10, delay='10ms', loss=1.0, use_tbf=False)
        self.addLink(B, C, bw=10, delay='10ms', loss=1.0, use_tbf=False)

    def init(self, net, manager):
        """Initialize topology-specific daemons and terminals."""
        A = net.get('A')
        B = net.get('B')
        C = net.get('C')

        ### Launch MIP daemons at the hosts. ###
        manager.openTerm(
            node=A,
            title="MIPd A",
            geometry="80x14+0+0",
            cmd="./mipd -d mipSockA 10"
        )

        time.sleep(3)

        manager.openTerm(
            node=B,
            title="MIPd B",
            geometry="80x14+512+0",
            cmd="./mipd -d mipSockB 20"
        )

        time.sleep(3)

        manager.openTerm(
            node=C,
            title="MIPd C",
            geometry="80x14+1024+0",
            cmd="./mipd -d mipSockC 30"
        )

        time.sleep(3)

        ### Launch MIPTP daemons at the hosts. ###

        manager.openTerm(
            node=A,
            title="MIPTPd A",
            geometry="80x14+0+216",
            cmd="./miptpd -d mipSockA appSockA"
        )

        time.sleep(3)

        manager.openTerm(
            node=B,
            title="MIPTPd B",
            geometry="80x14+512+216",
            cmd="./miptpd -d mipSockB appSockB"
        )

        time.sleep(3)

        manager.openTerm(
            node=C,
            title="MIPTPd C",
            geometry="80x14+1024+216",
            cmd="./miptpd -d mipSockC appSockC"
        )

        time.sleep(3)

        ### Launch File Transfer application at the server. ###

        manager.openTerm(
            node=B,
            title="Server B",
            geometry="80x14+512+432",
            cmd="./ft_server appSockB 8852"
        )

        time.sleep(1)

        # Test 1: Send file from A to B.
        # FT_Client arguments: appSockA, srcPort, dstMIP, dstPort, filename
        manager.openTerm(
            node=A,
            title="Client A",
            geometry="80x14+0+432",
            cmd="dd if=/dev/urandom of=32M bs=1M count=32 && ./ft_client appSockA 1024 20 8852 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        # Test 2: Send file from C to B.
        # FT_Client arguments: appSockC, srcPort, dstMIP, dstPort, filename
        manager.openTerm(
            node=C,
            title="Client C",
            geometry="80x14+1024+432",
            cmd="dd if=/dev/urandom of=32M bs=1M count=32 && ./ft_client appSockC 1025 20 8852 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        # Check md5sum
        manager.openTerm(
            node=A,
            title="MD5Sum AB",
            geometry="80x14+0+432",
            hold=False,
            cmd="md5sum 32M; sleep 10; exit"
        )

        manager.openTerm(
            node=B,
            title="MD5Sum BA",
            geometry="80x14+512+432",
            hold=False,
            cmd="md5sum incoming_30_1024; sleep 10; exit"
        )

        time.sleep(1)

        # Check md5sum
        manager.openTerm(
            node=C,
            title="MD5Sum CB",
            geometry="80x14+1024+432",
            hold=False,
            cmd="md5sum 32M; sleep 10; exit"
        )

        manager.openTerm(
            node=B,
            title="MD5Sum BC",
            geometry="80x14+512+632",
            hold=False,
            cmd="md5sum incoming_30_1025; sleep 10; exit"
        )

        time.sleep(10)

        # Test 3: Send file from A to B and C to B simultaneously.
        # FT_Client arguments: appSockA, srcPort, dstMIP, dstPort, filename
        manager.openTerm(
            node=A,
            title="Client A",
            geometry="80x14+0+445",
            cmd="./ft_client appSockA 1026 20 8852 32M"
        )

        time.sleep(1)

        manager.openTerm(
            node=C,
            title="Client C",
            geometry="80x14+1024+445",
            cmd="./ft_client appSockC 1027 20 8852 32M"
        )

        # FIXME: Increase sleep time if transfers are not completed before md5sum checks.
        time.sleep(10)

        # Check md5sum
        manager.openTerm(
            node=A,
            title="MD5Sum AB",
            geometry="80x14+0+445",
            hold=False,
            cmd="md5sum 32M; sleep 10; exit"
        )
        manager.openTerm(
            node=B,
            title="MD5Sum BA",
            geometry="80x14+512+440",
            hold=False,
            cmd="md5sum incoming_30_1026; sleep 10; exit"
        )
        manager.openTerm(
            node=C,
            title="MD5Sum CB",
            geometry="80x14+1024+445",
            hold=False,
            cmd="md5sum 32M; sleep 10; exit"
        )
        manager.openTerm(
            node=B,
            title="MD5Sum BC",
            geometry="80x14+512+645",
            hold=False,
            cmd="md5sum incoming_30_1027; sleep 10; exit"
        )

        time.sleep(10)

        # Test 4: Send file from B to B.
        # FT_Client arguments: appSockA, srcPort, dstMIP, dstPort, filename
        manager.openTerm(
            node=B,
            title="Client B",
            geometry="80x14+512+650",
            cmd="dd if=/dev/urandom of=32M bs=1M count=32 && ./ft_client appSockB 1028 20 8852 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        # Check md5sum
        manager.openTerm(
            node=B,
            title="MD5Sum B",
            geometry="80x14+0+650",
            hold=False,
            cmd="md5sum 32M; sleep 10; exit"
        )
        manager.openTerm(
            node=B,
            title="MD5Sum BB",
            geometry="80x14+1024+650",
            hold=False,
            cmd="md5sum incoming_20_1028; sleep 10; exit"
        )


def register_topology(topo_class):
    """Register a topology class with the CLI."""

    topo_name = topo_class.__name__.replace('Topo', '').lower()
    manager = TopologyManager()

    def init_command(self, line):
        """Initialize the topology with its specific configuration."""
        net = self.mn
        topo = net.topo
        if hasattr(topo, 'init'):
            topo.init(net, manager)
        else:
            print(f"Topology {type(topo).__name__} has no init method")

    # Register init command
    setattr(CLI, f'do_init_{topo_name}', init_command)

    # Override EOF to cleanup terminals
    orig_EOF = CLI.do_EOF

    def do_EOF(self, line):
        manager.cleanup()
        return orig_EOF(self, line)

    CLI.do_EOF = do_EOF

    return topo_class


def run():
    """
    Main function to register the topology.
    This is called when the script is imported by Mininet.
    """
    # Register topology class
    register_topology(HE2Topo)

    # Export topologies dictionary for Mininet
    global topos
    topos = {
        'he2': HE2Topo,
    }


# Execute run() when imported
run()
