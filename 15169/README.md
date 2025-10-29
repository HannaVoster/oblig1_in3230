# MIP Daemon and Distance Vector Routing Daemon

## Overview
This project implements a MIP protocol and provides four separate programs that work together to enable communication and routing between MIP nodes:

- mipd – the main MIP daemon responsible for sending and receiving MIP packets over Ethernet  
- routingd – a distance-vector routing daemon that exchanges routing information between MIP daemons  
- ping_client – sends messages to a destination MIP address through the local mipd  
- ping_server – receives messages from mipd and sends replies back

Communication between the programs is handled through:
- UNIX domain sockets – used for local communication between mipd and user programs (ping_client, ping_server, routingd)  
- RAW Ethernet sockets – used for direct communication between mipd instances across the network

### Communication
- UNIX domain sockets – local communication between client/server and mipd  
- RAW Ethernet sockets – network communication between different MIP daemons

## Routing Protocol
The implemented routing protocol is a lightweight Distance Vector Routing (DVR) protocol that operates as an extension to the MIP daemon.

Each node maintains a routing table with destination addresses, next hops, and costs (hop counts).  
Routing information is exchanged periodically between neighbors through HELLO and UPDATE messages.

### Key Features
- Neighbor Discovery: Nodes periodically broadcast HELLO messages to detect active neighbors.  
- Periodic Updates: Routing tables are shared with neighbors using UPDATE messages.  
- Poison Reverse: Prevents routing loops by advertising routes learned from a neighbor with infinite cost.  
- Link Failure Handling: If a neighbor becomes inactive, routes using that neighbor are invalidated and a triggered update is sent.  
- Triggered Updates: Ensures fast network convergence when topology changes occur.

## Count-to-Infinity Prevention
The Poison Reverse mechanism prevents loops and the count-to-infinity problem by explicitly marking routes as unreachable when advertised back to the neighbor they were learned from.  
Additionally, routes are invalidated and broadcast immediately if a neighbor times out, helping the network quickly converge to a stable state.












