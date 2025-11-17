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

FONT_SIZE = 8

OUTPUT_DIR = "./out"
FILE_SIZE = int(0.5 * 1024 * 1024)
FLAG = "-d"
LOSS = 1  # Percent
SERVER_PORT = 100
send_files = ["A1", "A2", "B", "C"]
send_files = [f"A{n}" for n in range(6)]


class H2Topo(Topo):
    "Simple topology for Home Exam 2."

    def __init__(self):
        "Set up our custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')

        # Add links
        self.addLink(A, B, bw=10, delay='10ms', loss=LOSS, use_tbf=False)
        self.addLink(A, C, bw=10, delay='10ms', loss=LOSS, use_tbf=False)


terms = []


def openTerm(self, node, title, geometry, cmd="bash"):
    "Open xterm window."

    display, tunnel = tunnelX11(node)

    return node.popen(["xterm",
                       "-hold",
                       "-sl", "10000",
                       "-title", "'%s'" % title,
                       "-geometry", geometry,
                       "-fa", "Monospace",
                       "-fs", str(FONT_SIZE),
                       "-display", display,
                       "-e", cmd])


def init_he2(self, line):
    "init is an example command to extend the Mininet CLI"

    net = self.mn
    A = net.get('A')
    B = net.get('B')
    C = net.get('C')

    # Start MIP daemons
    terms.append(openTerm(self,
                          node=A,
                          title="MIP A",
                          geometry="80x10+0+0",
                          cmd="./mipd usockA 1"))

    terms.append(openTerm(self,
                          node=B,
                          title="MIP B",
                          geometry="80x10+0+0",
                          cmd="./mipd usockB 2"))

    terms.append(openTerm(self,
                          node=C,
                          title="MIP C",
                          geometry="80x10+0+0",
                          cmd="./mipd usockC 3"))

    time.sleep(2)

    # Start routing daemons
    terms.append(openTerm(self,
                          node=A,
                          title="rout A",
                          geometry="80x10+0+0",
                          cmd="./routingd usockA"))

    terms.append(openTerm(self,
                          node=B,
                          title="rout B",
                          geometry="80x10+0+0",
                          cmd="./routingd usockB"))

    terms.append(openTerm(self,
                          node=C,
                          title="rout C",
                          geometry="80x10+0+0",
                          cmd="./routingd usockC"))

    time.sleep(1)

    # Start transfer protocols
    terms.append(openTerm(self,
                          node=A,
                          title="MIP TP A",
                          geometry="80x20+0+300",
                          cmd=f"valgrind --track-origins=yes -s ./miptp {FLAG} usockA tsockA 2>&1 | tee miptpa.log"))

    terms.append(openTerm(self,
                          node=B,
                          title="MIP TP B",
                          geometry="80x20+550+300",
                          cmd=f"valgrind --track-origins=yes -s ./miptp {FLAG} usockB tsockB 2>&1 | tee miptpb.log"))

    terms.append(openTerm(self,
                          node=C,
                          title="MIP TP C",
                          geometry="80x20+1100+300",
                          cmd=f"valgrind --track-origins=yes -s ./miptp {FLAG} usockC tsockC 2>&1 | tee miptpc.log"))

    time.sleep(1)

    # Run server on B
    terms.append(openTerm(self,
                          node=B,
                          title="File transfer server B",
                          geometry="80x20+550+600",
                          cmd=f"valgrind --track-origins=yes -s ./fts {SERVER_PORT} tsockB out"))

    time.sleep(2)

    start_transfer(self, line)


def start_transfer(self, line):
    net = self.mn

    # Remove any old transfer files
    for file in glob.glob(os.path.join(OUTPUT_DIR, '*')):
        os.remove(file)

    # Remove any old send files
    for file in glob.glob("*.dat"):
        os.remove(file)

    for s in send_files:
        with open(f"{s}.dat", 'wb') as f:
            f.write(os.urandom(FILE_SIZE))

    for s in send_files:
        terms.append(openTerm(self,
                              node=net.get(s[0]),
                              title=f"File transfer client {s}",
                              geometry="80x20+1100+0",
                              cmd=f"./ftc {s}.dat 2 {SERVER_PORT} tsock{s[0]}"))


def check_success(self, line):
    transferred_file_pattern = os.path.join(OUTPUT_DIR, "incoming_*")
    transferred_files = glob.glob(transferred_file_pattern)
    success = True

    if not transferred_files:
        print("Fail: No transferred files found.")
        return

    def md5sum(file_path):
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    if (len(transferred_files) != len(send_files)):
        print(
            f"Length of transferred files is {len(transferred_files)},"
            f" length of send_files is {len(send_files)}")
        success = False

    for transfer in transferred_files:
        match_files = list()
        transferred_md5 = md5sum(transfer)
        for send_file in send_files:
            original_md5 = md5sum(f"{send_file}.dat")
            if transferred_md5 == original_md5:
                match_files.append(send_file)

        if not match_files:
            success = False
            print(
                f"Transferrred file {transfer} does not match any send file {send_files}")
        elif len(match_files) == 1:
            print(f"Transferred file {transfer} matches {match_files[0]}.dat")
        else:
            success = False
            print(
                f"Transferred file {transfer} matches multiple send files: {match_files}")

    if success:
        print("Success: All transfers match exactly one. Double-check that the file names correspond.")
    else:
        print("Fail: Some transfer(s) failed, see above")


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
