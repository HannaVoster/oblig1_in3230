#!/usr/bin/env python3

# Thanks to: @aasmuos for inspiration and OFC Copilot for code assistance


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
#    Set routing to False to test without Routing Daemon:
#    'init_he2 routing=False'
#
# 3. Third, inside the mininet console run 'EOF' to gracefully kill
#    the mininet console


MIP_DAEMON = "mipd"
ROUTING_DAEMON = "routingd"
TRANSPORT_DAEMON = "miptpd"
FTS = "ft_server"
FTC = "ft_client"
PORT = 254
OUT = "incoming"


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

    def check_md5sum(self, src_mip):
        """
        Check MD5 checksums between original file and incoming files.

        Args:
            src_mip: Source MIP address (e.g., 10 for node A, 30 for node C)
        """
        print(f"\n=== MD5Sum Check for MIP {src_mip} ===")

        # Get original file checksum
        print("Original file (32M):")
        result = os.popen('md5sum 32M').read()
        print(result)
        original_hash = result.split()[0]

        # Get incoming files from this source
        print(f"Received files from MIP {src_mip}:")
        incoming_files = os.popen(f'ls -lh {OUT}/incoming_{src_mip}_* 2>/dev/null').read()
        print(incoming_files)

        # Get checksum of received files
        result_incoming = os.popen(f'md5sum {OUT}/incoming_{src_mip}_* 2>/dev/null').read()
        print(result_incoming)

        # Verify checksums match
        all_match = True
        if result_incoming.strip():
            for line in result_incoming.strip().split('\n'):
                if line:
                    parts = line.split()
                    file_hash = parts[0]
                    filename = parts[1]

                    if file_hash == original_hash:
                        print(f"✓ {filename}: checksums match!")
                    else:
                        print(f"✗ {filename}: checksums don't match!")
                        all_match = False
        else:
            print(f"✗ No incoming files found from MIP {src_mip}")
            all_match = False

        if all_match:
            print(f"✓ File transfer from MIP {src_mip} successful!")
        else:
            print(f"✗ File transfer from MIP {src_mip} failed!")

        print(f"Cleaning up incoming files from MIP {src_mip}...")
        os.system(f'rm -f {OUT}/incoming_{src_mip}_*')

        return all_match

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

    def init(self, net, manager, routing=True):
        """Initialize topology-specific daemons and terminals."""
        A = net.get('A')
        B = net.get('B')
        C = net.get('C')

        # Set geometry offset based on routing
        GEOMETRY_OFFSET = 216 if routing else 0

        ### Launch MIP daemons at the hosts. ###
        manager.openTerm(
            node=A,
            title="MIPd A",
            geometry="80x14+0+0",
            cmd=f"./{MIP_DAEMON} -d mipSockA 10"
        )
        time.sleep(1)

        manager.openTerm(
            node=B,
            title="MIPd B",
            geometry="80x14+512+0",
            cmd=f"./{MIP_DAEMON} -d mipSockB 20"
        )
        time.sleep(1)

        manager.openTerm(
            node=C,
            title="MIPd C",
            geometry="80x14+1024+0",
            cmd=f"./{MIP_DAEMON} -d mipSockC 30"
        )
        time.sleep(1)

        ### Launch routing daemons if enabled. ###
        if routing:
            
            manager.openTerm(
                node=A,
                title="ROUTINGd A",
                geometry="80x14+0+216",
                cmd=f"./{ROUTING_DAEMON} -d mipSockA"
            )
            time.sleep(1)

            manager.openTerm(
                node=B,
                title="ROUTINGd B",
                geometry="80x14+512+216",
                cmd=f"./{ROUTING_DAEMON} -d mipSockB"
            )
            time.sleep(1)

            manager.openTerm(
                node=C,
                title="ROUTINGd C",
                geometry="80x14+1024+216",
                cmd=f"./{ROUTING_DAEMON} -d mipSockC"
            )

            # Sleep ~10s to allow routing tables to converge
            time.sleep(10)

        ### Launch MIPTP daemons at the hosts. ###

        manager.openTerm(
            node=A,
            title="MIPTPd A",
            geometry=f"80x14+0+{216 + GEOMETRY_OFFSET}",
            cmd=f"./{TRANSPORT_DAEMON} -d mipSockA appSockA"
        )
        time.sleep(1)

        manager.openTerm(
            node=B,
            title="MIPTPd B",
            geometry=f"80x14+512+{216 + GEOMETRY_OFFSET}",
            cmd=f"./{TRANSPORT_DAEMON} -d mipSockA appSockA"
        )
        time.sleep(1)

        manager.openTerm(
            node=C,
            title="MIPTPd C",
            geometry=f"80x14+1024+{216 + GEOMETRY_OFFSET}",
            cmd=f"./{TRANSPORT_DAEMON} -d mipSockA appSockA"
        )
        time.sleep(1)

        ### Launch File Transfer Server at node B ###

        manager.openTerm(
            node=B,
            title="Server B",
            geometry=f"80x14+512+{432 + GEOMETRY_OFFSET}",
            cmd=f"rm -r {OUT} && mkdir {OUT} && ./{FTS} appSockB {PORT} {OUT}"
        )

        print(f"Started File Transfer Server on B at port {PORT}")
        time.sleep(1)

        # Create test file once (shared across all hosts since Mininet
        # hosts share the same filesystem) and delete previous incoming files.
        A.cmd('rm -f 32M && dd if=/dev/urandom of=32M bs=1M count=32')
        print("Created test file 32M")

        time.sleep(3)

        print("Starting File Transfer from A to B")
        # Test 1: Send file from A to B.
        # FT_Client arguments: appSockA, dstMIP, dstPort, filename
        manager.openTerm(
            node=A,
            title="Client A",
            geometry=f"80x14+0+{432 + GEOMETRY_OFFSET}",
            cmd=f"./{FTC} appSockA 20 {PORT} 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        print("Starting File Transfer from C to B")
        # Test 2: Send file from C to B.
        # FT_Client arguments: appSockC, dstMIP, dstPort, filename
        manager.openTerm(
            node=C,
            title="Client C",
            geometry=f"80x14+1024+{432 + GEOMETRY_OFFSET}",
            cmd=f"./{FTC} appSockC 20 {PORT} 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        # Check md5sum
        manager.check_md5sum(src_mip=10)  # Check for files from A
        manager.check_md5sum(src_mip=30)  # Check for files from C

        time.sleep(10)

        print("Starting File Transfer from A to B and C to B simultaneously")
        # Test 3: Send file from A to B and C to B simultaneously.
        # FTC arguments: appSockA, dstMIP, dstPort, filename
        manager.openTerm(
            node=A,
            title="Client A",
            geometry=f"80x14+0+{445+GEOMETRY_OFFSET}",
            cmd=f"./{FTC} appSockA 20 {PORT} 32M"
        )

        time.sleep(1)

        manager.openTerm(
            node=C,
            title="Client C",
            geometry=f"80x14+1024+{445+GEOMETRY_OFFSET}",
            cmd=f"./{FTC} appSockC 20 {PORT} 32M"
        )

        # FIXME: Increase sleep time if transfers are not completed before md5sum checks.
        time.sleep(20)

        # Check md5sum
        manager.check_md5sum(src_mip=10)  # Check for files from A
        manager.check_md5sum(src_mip=30)  # Check for files from C

        print("Starting File Transfer from B to B")
        # Test 4: Send file from B to B.
        # FTC arguments: appSockA, dstMIP, dstPort, filename
        manager.openTerm(
            node=B,
            title="Client B",
            geometry=f"80x14+0+{460+GEOMETRY_OFFSET}",
            cmd=f"./{FTC} appSockB 20 {PORT} 32M"
        )

        # FIXME: Increase sleep time if transfer is not completed before md5sum checks.
        time.sleep(10)

        # Check md5sum for files from B itself
        manager.check_md5sum(src_mip=20)


def register_topology(topo_class):
    """Register a topology class with the CLI."""

    topo_name = topo_class.__name__.replace('Topo', '').lower()
    manager = TopologyManager()

    def do_init_he2(self, line):
        """Initialize the topology with its specific configuration.

        Usage: init_<topo> [routing=True|False]
        Example: init_he2 routing=False
        """
        net = self.mn
        topo = net.topo

        # Parse routing parameter from command line
        routing = True  # default

        if line:
            args = line.split()
            for arg in args:
                if arg.startswith('routing='):
                    value = arg.split('=')[1].lower()
                    routing = value == 'true'

        if hasattr(topo, 'init'):
            topo.init(net, manager, routing=routing)
        else:
            print(f"Topology {type(topo).__name__} has no init method")

   # Register init command
    CLI.do_init_he2 = do_init_he2

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
