import glob
import hashlib
import os
import signal
import time

from mininet.cli import CLI
from mininet.term import tunnelX11
from mininet.topo import Topo

# Usage example:
# sudo mn --mac --custom he2-mn-topo.py --topo he2 --link tc

SEND_FILE_PATH = './to_send.dat'  # Path to the file
OUTPUT_DIR = "./out"
FILE_SIZE = 1 * 1024 * 1024
FLAG = "-d"
LOSS = 10  # Percent


class H2Topo(Topo):
    "Simple topology for Home Exam 2."

    def __init__(self):
        "Set up our custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')

        # Add links
        self.addLink(A, B, bw=10, delay='10ms', loss=LOSS, use_tbf=False)


terms = []


def openTerm(self, node, title, geometry, cmd="bash"):
    "Open xterm window."

    display, tunnel = tunnelX11(node)

    return node.popen(["xterm",
                       "-hold",
                       "-sl", "10000",
                       "-title", "'%s'" % title,
                       "-geometry", geometry,
                       "-display", display,
                       "-e", cmd])


def init_he2(self, line):
    "init is an example command to extend the Mininet CLI"

    net = self.mn
    A = net.get('A')
    B = net.get('B')

    # Start MIP daemons
    terms.append(openTerm(self,
                          node=A,
                          title="MIP A",
                          geometry="80x20+0+0",
                          cmd="./mipd usockA 1"))

    terms.append(openTerm(self,
                          node=B,
                          title="MIP B",
                          geometry="80x20+550+0",
                          cmd="./mipd usockB 2"))

    time.sleep(2)

    # Start routing daemons
    terms.append(openTerm(self,
                          node=A,
                          title="rout A",
                          geometry="80x20+0+300",
                          cmd="./routingd usockA"))

    terms.append(openTerm(self,
                          node=B,
                          title="rout B",
                          geometry="80x20+550+300",
                          cmd="./routingd usockB"))

    time.sleep(1)

    # Start transfer protocols
    terms.append(openTerm(self,
                          node=A,
                          title="MIP TP A",
                          geometry="80x20+0+600",
                          cmd=f"valgrind --track-origins=yes -s ./miptp {FLAG} usockA tsockA"))

    terms.append(openTerm(self,
                          node=B,
                          title="MIP TP B",
                          geometry="80x20+550+600",
                          cmd=f"valgrind --track-origins=yes -s ./miptp {FLAG} usockB tsockB"))

    time.sleep(1)

    # Run server on B
    terms.append(openTerm(self,
                          node=B,
                          title="File transfer server B",
                          geometry="80x20+1100+300",
                          cmd="./fts 100 tsockB out"))

    time.sleep(1)

    start_transfer(self, line)


def start_transfer(self, line):
    net = self.mn
    A = net.get('A')
    B = net.get('B')

    # Remove any old transfer files
    for file in glob.glob(os.path.join(OUTPUT_DIR, '*')):
        os.remove(file)

    if not os.path.exists(SEND_FILE_PATH):
        # Create a file with 1MB of random data
        with open(SEND_FILE_PATH, 'wb') as f:
            # Generate 1MB of random bytes
            f.write(os.urandom(FILE_SIZE))  # 1024 * 1024 bytes = 1MB

    terms.append(openTerm(self,
                          node=A,
                          title="File transfer client A",
                          geometry="80x20+1100+0",
                          cmd="./ftc ./to_send.dat 2 100 tsockA"))


def check_success(self, line):
    transferred_file_pattern = os.path.join(OUTPUT_DIR, "incoming_1_*")
    transferred_files = glob.glob(transferred_file_pattern)

    if not transferred_files:
        print("Fail: No transferred files found.")
        return

    transferred_file = transferred_files[0]

    def md5sum(file_path):
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    original_md5 = md5sum(SEND_FILE_PATH)
    transferred_md5 = md5sum(transferred_file)

    if original_md5 == transferred_md5:
        print("Success: The transferred file matches the original file")
    else:
        print("Fail: The transferred file is different from the original file")


# Mininet Callbacks
# Inside mininet console run 'init_he1'
CLI.do_init_he2 = init_he2
CLI.do_start_transfer = start_transfer
CLI.do_check_success = check_success


# Inside mininet console run 'EOF' to gracefully kill the mininet console
orig_EOF = CLI.do_EOF


# Kill mininet console
def do_EOF(self, line):
    for t in terms:
        os.kill(t.pid, signal.SIGKILL)
    return orig_EOF(self, line)


CLI.do_EOF = do_EOF


topos = {'he2': (lambda: H2Topo())}
