# MIP Daemon IN3230 Oblig

## Task
This assignment implements a simple MIP daemon (mipd) together with two helper programs:
- ping_client: sends messages via the daemon to a destination MIP address
- ping_server: receives messages delivered by the daemon and replies back

Communication happens over:
1. UNIX domain sockets(be tween client/server and the daemon).
2. RAW Ethernet sockets (between MIP daemons).

The MIP protocol is implemented according to the specification provided in the assignment.

## Note – deviation from assignment
- In the implementation I open raw sockets with ETH_P_ALL instead of ETH_P_MIP (0x88B5).  
- This was necessary because the Mininet environment does not deliver frames with 0x88B5 back to recvmsg().  
- With ETH_P_ALL I can at least verify that raw packets are received, and I manually filter on 0x88B5 inside handle_raw_packet.

## What works
- ping_client connects to the daemon via UNIX socket and sends correctly formatted messages 
- mipd receives the message, queues it, and builds a valid MIP PDU.
- Ethernet frames are built and dumped correctly (60 bytes, Ethertype 0x88B5).
- sendto on the RAW socket returns OK, so the frame is transmitted on the interface.
- Debug output shows the correct ifindex and interface name (A-eth0, C-eth0, etc.).

## What does not work
- handle_raw_packet never receives MIP frames.  
- Only IPv6 traffic (ethertype 0x86DD) is observed.  
- No 0x88B5 frames are delivered, and therefore ping_client always times out.

## Debugging performed
- Verified with debug:
  - Interface name and ifindex are resolved correctly in find_iface.
  - Frames are built with the correct Ethertype and transmitted (sendto ok).
  - TX debug confirms broadcast destination MAC 
- Tested both ETH_P_MIP and ETH_P_ALL as socket protocol:
  - With ETH_P_ALL packets are received, but still never 0x88B5.

## Hypothesis over why no 0x88B5 frames are delivered
- Mininet maybe filters out unknown Ethertypes, meaning the MIP frames are transmitted but never delivered back to the receiver’s raw socket.  
- Alternatively, the exercise setup used by the instructor may rely on a different script or patch that explicitly enables delivery of MIP traffic.  

## Further implementation
As further improvements, I would make all comments consistent and written in English for clarity.  
Additionally, I would refactor the code into smaller source files and split large functions such as handle_raw_packet 
into more modular components for better readability and maintainability.






