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
Mininet script for IN3230/IN4230
A–B–C topology with full MIPD → routingd → miptpd → server/client flow

Everything runs inside bin/ to avoid path issues.
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import os, time, signal, hashlib

terms = []


# ===== TOPOLOGY =====
class MIPTPTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        A = self.addHost('A')
        B = self.addHost('B')
        C = self.addHost('C')

        # A -- B -- C
        self.addLink(A, B, bw=10, delay='10ms')
        self.addLink(B, C, bw=10, delay='10ms')


# ===== TERMINAL UTILITY =====
def openTerm(self, node, title, geometry, cmd="bash"):
    display, tunnel = tunnelX11(node)
    return node.popen([
        "xterm", "-hold",
        "-title", title,
        "-geometry", geometry,
        "-display", display,
        "-e", cmd
    ])


# ===== INITIALISERING =====
def init_miptp_multi(self, line):

    net = self.mn
    A = net.get('A')
    B = net.get('B')
    C = net.get('C')

    NUM_FILES = 4   # hvor mange filer fra A og fra C

    print("\n=== Cleaning old files on B ===")
    B.cmd("rm -f /tmp/incoming_*")

    # ---------- MIPD ----------
    print("\n=== Starting MIP daemons ===")
    terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0",
                          "cd bin && ./mipd -d usockA 1"))
    time.sleep(1)

    terms.append(openTerm(self, B, "MIPD [B]", "80x14+550+0",
                          "cd bin && ./mipd -d usockB 2"))
    time.sleep(1)

    terms.append(openTerm(self, C, "MIPD [C]", "80x14+1100+0",
                          "cd bin && ./mipd -d usockC 3"))
    time.sleep(3)

    # ---------- ROUTING ----------
    print("\n=== Starting routingd ===")
    terms.append(openTerm(self, A, "ROUTING [A]", "80x14+0+220",
                          "cd bin && ./routingd -d usockA"))
    time.sleep(1)

    terms.append(openTerm(self, B, "ROUTING [B]", "80x14+550+220",
                          "cd bin && ./routingd -d usockB"))
    time.sleep(1)

    terms.append(openTerm(self, C, "ROUTING [C]", "80x14+1100+220",
                          "cd bin && ./routingd -d usockC"))
    time.sleep(3)

    # ---------- MIPTPD ----------
    print("\n=== Starting MIPTP daemons ===")
    terms.append(openTerm(self, A, "MIPTPD [A]", "80x14+0+440",
                          "cd bin && ./miptpd -d usockA miptp_appA.sock"))
    time.sleep(1)

    terms.append(openTerm(self, B, "MIPTPD [B]", "80x14+550+440",
                          "cd bin && ./miptpd -d usockB miptp_appB.sock"))
    time.sleep(1)

    terms.append(openTerm(self, C, "MIPTPD [C]", "80x14+1100+440",
                          "cd bin && ./miptpd -d usockC miptp_appC.sock"))
    time.sleep(3)

    # ---------- Server på B ----------
    print("\n=== Starting MIPTP server on B (port 99) ===")
    terms.append(openTerm(self, B, "SERVER [B:99]", "80x20+550+660",
                          "cd bin && sudo ./miptpd_server 99 miptp_appB.sock /tmp"))
    time.sleep(2)

    # ---------- Filgenerering ----------
    print("\n=== Generating input files on A and C ===")
    for i in range(NUM_FILES):
        terms.append(openTerm(self, A, f"A MAKE {i}", f"80x10+0+700+{i*40}",
                              f"cd bin && dd if=/dev/urandom of=Afile{i}.dat bs=1K count=64"))
        time.sleep(0.3)

    for i in range(NUM_FILES):
        terms.append(openTerm(self, C, f"C MAKE {i}", f"80x10+1100+700+{i*40}",
                              f"cd bin && dd if=/dev/urandom of=Cfile{i}.dat bs=1K count=64"))
        time.sleep(0.3)

    # ---------- Start filoverføring ----------
    print("\n=== Starting transfers to B ===")
    for i in range(NUM_FILES):
        terms.append(openTerm(
            self, A, f"A→B [{i}]", f"80x20+0+900+{i*40}",
            f"cd bin && sudo ./miptpd_client Afile{i}.dat 1 99 miptp_appA.sock"
        ))
        time.sleep(0.2)

    for i in range(NUM_FILES):
        terms.append(openTerm(
            self, C, f"C→B [{i}]", f"80x20+1100+900+{i*40}",
            f"cd bin && sudo ./miptpd_client Cfile{i}.dat 3 99 miptp_appC.sock"
        ))
        time.sleep(0.2)

    print("\nMULTI-NODE MULTI-FILE TEST STARTED.")
    print("Use 'check_multi_success' after completion.")


# ===== VERIFIKASJON =====
def check_multi_success(self, line):

    net = self.mn
    B = net.get('B')

    print("\n=== Checking files on B ===")

    ls_output = B.cmd("ls /tmp/incoming_* 2>/dev/null").strip()
    if not ls_output:
        print("No received files on B.")
        return

    files = ls_output.split()
    print("Found", len(files), "received files.")

    # md5 utility
    def md5(path):
        h = hashlib.md5()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    ok = True

    for rf in files:
        local = f"/tmp/{os.path.basename(rf)}"
        B.cmd(f"cp {rf} {local}")
        received_md5 = md5(local)
        os.remove(local)

        matches = []

        # compare against Afiles
        for i in range(4):
            p = f"bin/Afile{i}.dat"
            if os.path.exists(p) and md5(p) == received_md5:
                matches.append(f"Afile{i}")

        # compare against Cfiles
        for i in range(4):
            p = f"bin/Cfile{i}.dat"
            if os.path.exists(p) and md5(p) == received_md5:
                matches.append(f"Cfile{i}")

        if len(matches) == 1:
            print(f"{rf} OK → matches {matches[0]}")
        elif len(matches) == 0:
            print(f"{rf} ERROR: matches nothing!")
            ok = False
        else:
            print(f"{rf} ERROR: matches MULTIPLE! {matches}")
            ok = False

    if ok:
        print("\nSUCCESS: all transfers correct!")
    else:
        print("\nFAIL: some transfers mismatched.")


# ===== CLEAN EXIT =====
orig_EOF = CLI.do_EOF
def do_EOF(self, line):
    for t in terms:
        try: os.kill(t.pid, signal.SIGKILL)
        except: pass
    return orig_EOF(self, line)

CLI.do_EOF = do_EOF
CLI.do_init_miptp_multi = init_miptp_multi
CLI.do_check_multi_success = check_multi_success

topos = {"miptp": MIPTPTopo}



