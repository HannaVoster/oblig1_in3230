#!/bin/bash
echo "[CLEANUP] Stopping all MIP-related processes..."

# Kill daemons and clients
sudo pkill -f "mipd" 2>/dev/null
sudo pkill -f "miptpd" 2>/dev/null
sudo pkill -f "miptpd_client" 2>/dev/null
sudo pkill -f "miptpd_server" 2>/dev/null
sudo pkill -f "test_app" 2>/dev/null
sudo pkill -f "test_server" 2>/dev/null

# Remove stale UNIX sockets
sudo rm -f /tmp/mipA.sock /tmp/mipB.sock
sudo rm -f /tmp/appA.sock /tmp/appB.sock

# Remove any leftover Mininet network namespaces
sudo mn -c > /dev/null 2>&1

echo "[CLEANUP] Done. All processes stopped and sockets removed."
