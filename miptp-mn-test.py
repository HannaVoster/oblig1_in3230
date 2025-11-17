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


#!/usr/bin/env python
"""
Mininet script for IN3230/IN4230 — 3 nodes version
Starter: mipd → routingd → miptpd → klient/server
Bruker ABSOLUTTE STIER for alle UNIX-sockets (/tmp)
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import os, time, signal, hashlib

terms = []

# === ABSOLUTTE SOCKET STIER ===
SOCK = {
    "A": "/tmp/usockA",
    "B": "/tmp/usockB",
    "C": "/tmp/usockC"
}

APP = {
    "A": "/tmp/miptp_appA.sock",
    "B": "/tmp/miptp_appB.sock",
    "C": "/tmp/miptp_appC.sock"
}

# ===== TOPOLOGY =====
class ThreeNodeTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')

        self.addLink(A, B, bw=10, delay='10ms')
        self.addLink(B, C, bw=10, delay='10ms')


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


# ===== INIT: Start alle 3 noder =====
def init_three(self, line):
    net = self.mn
    A, B, C = net.get('A'), net.get('B'), net.get('C')

    nodes = {"A": A, "B": B, "C": C}

    print("=== Cleaning all old sockets ===")
    for n in nodes:
        nodes[n].cmd(f"rm -f {SOCK[n]} {APP[n]} /tmp/incoming_*")

    time.sleep(1)

    # === START MIPD ===
    print("\n=== Starting mipd ===")
    terms.append(openTerm(self, A, "MIPD[A]", "80x14+0+0",
                          f"cd bin && ./mipd -d {SOCK['A']} 1"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPD[B]", "80x14+520+0",
                          f"cd bin && ./mipd -d {SOCK['B']} 2"))
    time.sleep(1)
    terms.append(openTerm(self, C, "MIPD[C]", "80x14+1040+0",
                          f"cd bin && ./mipd -d {SOCK['C']} 3"))
    time.sleep(3)

    # === START ROUTINGD ===
    print("\n=== Starting routingd ===")
    terms.append(openTerm(self, A, "ROUTING[A]", "80x14+0+220",
                          f"cd bin && ./routingd -d {SOCK['A']}"))
    time.sleep(1)
    terms.append(openTerm(self, B, "ROUTING[B]", "80x14+520+220",
                          f"cd bin && ./routingd -d {SOCK['B']}"))
    time.sleep(1)
    terms.append(openTerm(self, C, "ROUTING[C]", "80x14+1040+220",
                          f"cd bin && ./routingd -d {SOCK['C']}"))
    time.sleep(3)

    # === START MIPTPD ===
    print("\n=== Starting miptpd ===")
    terms.append(openTerm(self, A, "MIPTPD[A]", "80x14+0+440",
                          f"cd bin && ./miptpd -d {SOCK['A']} {APP['A']}"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPTPD[B]", "80x14+520+440",
                          f"cd bin && ./miptpd -d {SOCK['B']} {APP['B']}"))
    time.sleep(1)
    terms.append(openTerm(self, C, "MIPTPD[C]", "80x14+1040+440",
                          f"cd bin && ./miptpd -d {SOCK['C']} {APP['C']}"))
    time.sleep(3)

    # === SERVER PÅ B ===
    print("\n=== Starting MIPTP server on B (port 99) ===")
    terms.append(openTerm(self, B, "SERVER[B:99]", "80x20+520+660",
                          f"cd bin && sudo ./miptpd_server 99 {APP['B']} /tmp"))
    time.sleep(2)

    print("\n=== THREE NODE TEST READY ===")
    print("Use commands:")
    print("   send_A_to_B")
    print("   send_C_to_B")
    print("   send_A_to_C")
    print("   send_C_to_A")
    print("   check_multi_success")


# ===== SENDER-FUNKSJONER =====
def start_transfer_generic(self, src_node, dst_mip, filename):
    """Sender én fil via miptpd_client fra valgt node."""
    node = self.mn.get(src_node)
    print(f"\n=== Generating file {filename} on {src_node} ===")
    node.cmd(f"cd bin && dd if=/dev/urandom of={filename} bs=1K count=32")

    print(f"=== Sending {filename} from {src_node} → MIP {dst_mip} ===")
    terms.append(openTerm(self, node,
                          f"SEND[{src_node}→{dst_mip}]",
                          "80x20+0+880",
                          f"cd bin && sudo ./miptpd_client {filename} {dst_mip} 99 {APP[src_node]}"))


def do_send_A_to_B(self, line): start_transfer_generic(self, "A", 2, "Afile.dat")
def do_send_C_to_B(self, line): start_transfer_generic(self, "C", 2, "Cfile.dat")
def do_send_A_to_C(self, line): start_transfer_generic(self, "A", 3, "A2C.dat")
def do_send_C_to_A(self, line): start_transfer_generic(self, "C", 1, "C2A.dat")


# ===== CHECK SUCCESS =====
def check_multi_success(self, line):
    """Sjekker alle incoming-filer på B"""
    B = self.mn.get('B')

    print("\n=== Checking incoming files on B ===")
    files = B.cmd("ls /tmp/incoming_* 2>/dev/null").split()

    if not files:
        print("No incoming files found.")
        return

    def md5(binpath):
        h = hashlib.md5()
        with open(binpath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    for rf in files:
        local = "/tmp/local_copy_" + os.path.basename(rf)
        B.cmd(f"cp {rf} {local}")
        md_remote = md5(local)
        os.remove(local)

        # Compare against all files in bin/
        matches = []
        for f in os.listdir("bin"):
            if f.endswith(".dat"):
                if md5("bin/" + f) == md_remote:
                    matches.append(f)

        if len(matches) == 1:
            print(f"{rf} matches {matches[0]}")
        else:
            print(f"{rf}: BAD MATCH → {matches}")


# ===== CLEAN EXIT =====
orig_EOF = CLI.do_EOF
def do_EOF(self, line):
    print("Cleaning terminals...")
    for t in terms:
        try: os.kill(t.pid, signal.SIGKILL)
        except: pass
    return orig_EOF(self, line)


# Register commands in CLI
CLI.do_init_miptp_three = init_three
CLI.do_send_A_to_B = do_send_A_to_B
CLI.do_send_C_to_B = do_send_C_to_B
CLI.do_send_A_to_C = do_send_A_to_C
CLI.do_send_C_to_A = do_send_C_to_A
CLI.do_check_multi_success = check_multi_success
CLI.do_EOF = do_EOF

topos = {"three": (lambda: ThreeNodeTopo())}




