# #!/usr/bin/env python
# """
# Mininet script for IN3230/IN4230
# Struktur og rekkefølge følger hjemmeeksamen 1-oppsettet (mipd → routingd → miptpd → apper)
# """

# from mininet.topo import Topo
# from mininet.cli import CLI
# from mininet.term import tunnelX11
# import os, time, signal
# import hashlib
# import glob

# terms = []

# # ===== TOPOLOGY =====
# class MIPTPTopo(Topo):
#     def __init__(self):
#         Topo.__init__(self)
#         A = self.addHost('A')
#         B = self.addHost('B')
#         self.addLink(A, B, bw=10, delay='10ms')


# # ===== OPEN TERMINAL =====
# def openTerm(self, node, title, geometry, cmd="bash"):
#     display, tunnel = tunnelX11(node)
#     return node.popen([
#         "xterm", "-hold",
#         "-title", title,
#         "-geometry", geometry,
#         "-display", display,
#         "-e", cmd
#     ])
   

# def init_miptp_multi(self, line):
#     net = self.mn
#     A = net.get('A')
#     B = net.get('B')

#     print("=== Cleaning old files on B (/tmp) ===")
#     B.cmd("rm -f /tmp/incoming_*")

#     num_files = 8 # Hvor mange filer som skal sendes parallelt

#     print("\n=== Starting MIP daemons ===")
#     terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0", "./mipd -d usockA 1"))
#     time.sleep(1)
#     terms.append(openTerm(self, B, "MIPD [B]", "80x14+555+0", "./mipd -d usockB 2"))
#     time.sleep(3)

#     print("\n=== Starting routing daemons ===")
#     terms.append(openTerm(self, A, "ROUTING [A]", "80x14+0+220", "./routingd -d usockA"))
#     time.sleep(1)
#     terms.append(openTerm(self, B, "ROUTING [B]", "80x14+555+220", "./routingd -d usockB"))
#     time.sleep(3)

#     print("\n=== Starting MIPTP daemons ===")
#     terms.append(openTerm(self, A, "MIPTPD [A]", "80x14+0+440", "./miptpd -d usockA miptp_appA.sock"))
#     time.sleep(1)
#     terms.append(openTerm(self, B, "MIPTPD [B]", "80x14+555+440", "./miptpd -d usockB miptp_appB.sock"))
#     time.sleep(3)

#     print("\n=== Launching MIPTP server on B ===")
#     terms.append(openTerm(self, B, "MIPTP SERVER [B:99]", "80x20+1110+440",
#                           "cd bin && sudo ./miptpd_server 99 miptp_appB.sock /tmp"))
#     time.sleep(2)

#     print("\n=== Generating files on A ===")
#     for i in range(num_files):
#         terms.append(openTerm(
#             self, A, f"MAKE FILE {i}", f"80x10+0+{660 + i*40}",
#             f"cd bin && dd if=/dev/urandom of=test{i}.dat bs=1K count=32"
#         ))
#         time.sleep(0.3)

#     print("\n=== Starting parallel file transfers from A → B ===")
#     for i in range(num_files):
#         terms.append(openTerm(
#             self, A, f"MIPTP CLIENT [{i}]", f"80x20+0+{900 + i*40}",
#             f"cd bin && sudo ./miptpd_client test{i}.dat 2 99 miptp_appA.sock"
#         ))
#         time.sleep(0.2)

#     print("\nMULTI-FILE MIPTP stress test started.")
#     print("Monitor the terminals and check using 'check_multi_success' when done")

# import hashlib
# import glob

# def check_multi_success(self, line):
#     """
#     Checks whether all files transferred in init_miptp_multi were received correctly on B
#     Looks for files in /tmp on host B
#     """
    
#     net = self.mn
#     B = net.get('B')

#     num_files = 8  # samme som init_miptp_multi

#     print("\n=== Checking transferred files on B (/tmp) ===")

#     ls_output = B.cmd("ls /tmp/incoming_* 2>/dev/null").strip()
#     if not ls_output:
#         print("No received files found in /tmp on B")
#         return

#     received_files = ls_output.split()
#     print(f"Found {len(received_files)} files on B")

#     if len(received_files) != num_files:
#         print(f"Expected {num_files} files, but found {len(received_files)}.")
#         print("Continuing to verify hashes...")
    
#     def md5sum(path):
#         hasher = hashlib.md5()
#         with open(path, 'rb') as f:
#             while chunk := f.read(8192):
#                 hasher.update(chunk)
#         return hasher.hexdigest()

#     success = True

#     for rf in received_files:
#         # kopierer fil fra B -> lokal /tmp for hashing
#         local_copy = f"/tmp/local_copy_{os.path.basename(rf)}"
#         B.cmd(f"cp {rf} {local_copy}")
#         received_md5 = md5sum(local_copy)
#         os.remove(local_copy)


#         matches = []
#         for i in range(num_files):
#             original_path = f"bin/test{i}.dat"
#             if not os.path.exists(original_path):
#                 print(f"Original file missing: {original_path}")
#                 continue
#             original_md5 = md5sum(original_path)
#             if received_md5 == original_md5:
#                 matches.append(i)

#         if len(matches) == 0:
#             print(f"Received file {rf} does NOT match any original file")
#             success = False
#         elif len(matches) > 1:
#             print(f"Received file {rf} matches MULTIPLE originals: {matches}")
#             success = False
#         else:
#             print(f"{rf} matches test{matches[0]}.dat")

#     if success:
#         print("\nSUCCESS!!:))): All transferred files match exactly one original file")
#     else:
#         print("\nFAIL: Some files did not match. See logs above")


# # ===== CLEAN EXIT =====
# orig_EOF = CLI.do_EOF
# def do_EOF(self, line):
#     for t in terms:
#         try:
#             os.kill(t.pid, signal.SIGKILL)
#         except Exception:
#             pass
#     return orig_EOF(self, line)

# CLI.do_EOF = do_EOF
# CLI.do_init_miptp_multi = init_miptp_multi
# CLI.do_check_multi_success = check_multi_success

# topos = {"miptp": (lambda: MIPTPTopo())}


#!/usr/bin/env python3
"""
Three-node Mininet test for IN3230/IN4230 MIPTP implementation
Matches the teacher’s HE2 testing logic:
 - A → B
 - C → B
 - A → B and C → B simultaneously
 - B → B (self transfer)
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import time, os, signal, hashlib

# Dynamically detect absolute path to ./bin
BASE = os.path.abspath(os.getcwd())
BIN = os.path.join(BASE, "bin")

terms = []


# ===== TOPOLOGY =====
class ThreeNodeTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        A = self.addHost("A")
        B = self.addHost("B")
        C = self.addHost("C")

        # Simple chain: A — B — C
        self.addLink(A, B, bw=10, delay="10ms")
        self.addLink(B, C, bw=10, delay="10ms")


# ===== TERMINAL LAUNCHER =====
def open_term(node, title, geometry, cmd):
    display, tunnel = tunnelX11(node)
    term = node.popen([
        "xterm", "-hold",
        "-title", title,
        "-geometry", geometry,
        "-display", display,
        "-e", cmd
    ])
    terms.append(term)
    return term


# ===== INIT TEST =====
def init_he2(self, line):
    net = self.mn
    A = net.get("A")
    B = net.get("B")
    C = net.get("C")

    print("\n=== Launching 3-node HE2 MIPTP test ===")
    print(f"Binary path: {BIN}")

    # Cleanup old incoming files
    B.cmd("rm -f /tmp/incoming_*")
    C.cmd("rm -f /tmp/incoming_*")
    A.cmd("rm -f /tmp/incoming_*")

    # --- Start mipd ---
    open_term(A, "MIPD A", "80x14+0+0", f"{BIN}/mipd -d {BIN}/usockA 1")
    time.sleep(2)
    open_term(B, "MIPD B", "80x14+480+0", f"{BIN}/mipd -d {BIN}/usockB 2")
    time.sleep(2)
    open_term(C, "MIPD C", "80x14+960+0", f"{BIN}/mipd -d {BIN}/usockC 3")
    time.sleep(3)

    # --- Start routingd ---
    open_term(A, "ROUTING A", "80x14+0+220", f"{BIN}/routingd -d {BIN}/usockA")
    open_term(B, "ROUTING B", "80x14+480+220", f"{BIN}/routingd -d {BIN}/usockB")
    open_term(C, "ROUTING C", "80x14+960+220", f"{BIN}/routingd -d {BIN}/usockC")
    time.sleep(3)

    # --- Start miptpd ---
    open_term(A, "MIPTPD A", "80x14+0+440", f"{BIN}/miptpd -d {BIN}/usockA {BIN}/appA.sock")
    time.sleep(1)
    open_term(B, "MIPTPD B", "80x14+480+440", f"{BIN}/miptpd -d {BIN}/usockB {BIN}/appB.sock")
    time.sleep(1)
    open_term(C, "MIPTPD C", "80x14+960+440", f"{BIN}/miptpd -d {BIN}/usockC {BIN}/appC.sock")
    time.sleep(3)

    # --- Server on B ---
    open_term(B, "SERVER B", "80x20+480+660",
              f"cd {BIN} && sudo ./miptpd_server 99 {BIN}/appB.sock /tmp")
    time.sleep(3)

    print("\n=== TEST COMMANDS READY ===")
    print("Use:")
    print("  send_A_to_B")
    print("  send_C_to_B")
    print("  send_A_C_parallel")
    print("  send_B_to_B")
    print("  check_incoming")
    print()
    print("Open a new Mininet CLI and run those commands.\n")


# ===== TRANSFER COMMANDS =====
def send_A_to_B(self, line):
    net = self.mn
    A = net.get("A")

    print("\n=== A → B ===")
    A.cmd(f"cd {BIN} && dd if=/dev/urandom of=Afile.dat bs=1K count=64")
    open_term(A, "A→B", "80x20+0+660",
              f"cd {BIN} && ./miptpd_client Afile.dat 2 99 {BIN}/appA.sock")


def send_C_to_B(self, line):
    net = self.mn
    C = net.get("C")

    print("\n=== C → B ===")
    C.cmd(f"cd {BIN} && dd if=/dev/urandom of=Cfile.dat bs=1K count=64")
    open_term(C, "C→B", "80x20+960+660",
              f"cd {BIN} && ./miptpd_client Cfile.dat 2 99 {BIN}/appC.sock")


def send_A_C_parallel(self, line):
    print("\n=== A → B + C → B (parallel) ===")
    send_A_to_B(self, line)
    time.sleep(0.5)
    send_C_to_B(self, line)


def send_B_to_B(self, line):
    net = self.mn
    B = net.get("B")

    print("\n=== B → B self-loop ===")
    B.cmd(f"cd {BIN} && dd if=/dev/urandom of=Bself.dat bs=1K count=64")
    open_term(B, "B→B", "80x20+480+880",
              f"cd {BIN} && ./miptpd_client Bself.dat 2 99 {BIN}/appB.sock")


# ===== CHECK FILES =====
def check_incoming(self, line):
    net = self.mn
    B = net.get("B")

    print("\n=== Checking incoming files on B ===")

    files = B.cmd("ls /tmp/incoming_* 2>/dev/null").split()
    if not files:
        print("No incoming files found.")
        return

    print(f"Found {len(files)} files:")
    for f in files:
        print("  ", f)


# ===== CLEANUP =====
orig_EOF = CLI.do_EOF
def do_EOF(self, line):
    for t in terms:
        try:
            os.kill(t.pid, signal.SIGKILL)
        except:
            pass
    return orig_EOF(self, line)

CLI.do_EOF = do_EOF

# Register commands
CLI.do_init_he2 = init_he2
CLI.do_send_A_to_B = send_A_to_B
CLI.do_send_C_to_B = send_C_to_B
CLI.do_send_A_C_parallel = send_A_C_parallel
CLI.do_send_B_to_B = send_B_to_B
CLI.do_check_incoming = check_incoming

topos = {"he2": (lambda: ThreeNodeTopo())}
