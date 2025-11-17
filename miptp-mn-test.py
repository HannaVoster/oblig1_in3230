#!/usr/bin/env python
"""
Mininet script for IN3230/IN4230 – MIPTP test
Struktur og rekkefølge følger hjemmeeksamen 1-oppsettet (mipd → routingd → miptpd → apper).
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.term import tunnelX11
import os, time, signal
import hashlib
import glob

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



def init_miptp(self, line):
    net = self.mn
    A = net.get('A')
    B = net.get('B')

    print("\n=== Starting MIP daemons ===")
    terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0", "./mipd -d usockA 1"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPD [B]", "80x14+555+0", "./mipd -d usockB 2"))
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

def init_miptp_multi(self, line):
    net = self.mn
    A = net.get('A')
    B = net.get('B')

    num_files = 6   # Hvor mange filer som skal sendes parallelt

    print("\n=== Starting MIP daemons ===")
    terms.append(openTerm(self, A, "MIPD [A]", "80x14+0+0", "./mipd -d usockA 1"))
    time.sleep(1)
    terms.append(openTerm(self, B, "MIPD [B]", "80x14+555+0", "./mipd -d usockB 2"))
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

    print("\n=== Launching MIPTP server on B ===")
    terms.append(openTerm(self, B, "MIPTP SERVER [B:99]", "80x20+1110+440",
                          "cd bin && sudo ./miptpd_server 99 miptp_appB.sock /tmp"))
    time.sleep(2)

    print("\n=== Generating files on A ===")
    for i in range(num_files):
        terms.append(openTerm(
            self, A, f"MAKE FILE {i}", f"80x10+0+{660 + i*40}",
            f"cd bin && dd if=/dev/urandom of=test{i}.dat bs=1K count=32"
        ))
        time.sleep(0.3)

    print("\n=== Starting parallel file transfers from A → B ===")
    for i in range(num_files):
        terms.append(openTerm(
            self, A, f"MIPTP CLIENT [{i}]", f"80x20+0+{900 + i*40}",
            f"cd bin && sudo ./miptpd_client test{i}.dat 2 99 miptp_appA.sock"
        ))
        time.sleep(0.2)

    print("\n🚀 MULTI-FILE MIPTP stress test started.")
    print("Monitor the terminals and check /tmp on B when done.")

import hashlib
import glob

def check_multi_success(self, line):
    """
    Checks whether all files transferred in init_miptp_multi were received correctly on B.
    Looks for files in /tmp on host B.
    """
    B.cmd("rm -f /tmp/incoming_*")
    net = self.mn
    B = net.get('B')

    num_files = 6  # same number as in init_miptp_multi

    print("\n=== Checking transferred files on B (/tmp) ===")

    # Find incoming files on B by running ls remotely
    ls_output = B.cmd("ls /tmp/incoming_* 2>/dev/null").strip()
    if not ls_output:
        print("❌ No received files found in /tmp on B.")
        return

    received_files = ls_output.split()
    print(f"Found {len(received_files)} files on B.")

    if len(received_files) != num_files:
        print(f"❌ Expected {num_files} files, but found {len(received_files)}.")
        print("Continuing to verify hashes...")
    
    def md5sum(path):
        hasher = hashlib.md5()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    success = True

    for rf in received_files:
        # Copy file from B -> local /tmp for hashing
        local_copy = f"/tmp/local_copy_{os.path.basename(rf)}"
        B.cmd(f"cp {rf} {local_copy}")
        received_md5 = md5sum(local_copy)
        os.remove(local_copy)


        matches = []
        for i in range(num_files):
            original_path = f"bin/test{i}.dat"
            if not os.path.exists(original_path):
                print(f"⚠ Original file missing: {original_path}")
                continue
            original_md5 = md5sum(original_path)
            if received_md5 == original_md5:
                matches.append(i)

        if len(matches) == 0:
            print(f"❌ Received file {rf} does NOT match any original file.")
            success = False
        elif len(matches) > 1:
            print(f"❌ Received file {rf} matches MULTIPLE originals: {matches}")
            success = False
        else:
            print(f"✅ {rf} matches test{matches[0]}.dat")

    if success:
        print("\n🎉 SUCCESS: All transferred files match exactly one original file.")
    else:
        print("\n❌ FAIL: Some files did not match. See logs above.")


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
CLI.do_init_miptp_multi = init_miptp_multi
CLI.do_check_multi_success = check_multi_success



topos = {"miptp": (lambda: MIPTPTopo())}

