
**Transport Layer (MIPTPD) - HOME EXAM 2**

## Overview
The transport layer implements the MIP Transport Protocol (MIPTP) as a separate daemon (miptpd) running between the application layer and the MIP daemon (mipd).
Its primary responsibility is to ensure reliable, ordered delivery of data between applications over the MIP network, using a Go-Back-N retransmission mechanism.

The daemon:
- Connects to the MIP daemon via a UNIX socket
- Handles multiple application connections
- Manages multiple concurrent transfers per application (each defined by their (dst_mip, dst_port) pair)
- Maintains per-transfer send windows, retransmission timers, and inbound sequence state
- Segments and reassembles application data into MIPTP PDUs
- Sends and processes acknowledgements (ACKs)
- Performs Go-Back-N retransmissions on timeout
- Provides reliable message delivery between nodes

## Building
- From the project root: make clean && make
- All binaries will be placed in the bin/ directory when running the make command

## Script
I have included a custom Mininet script that I used to test my implementation while I was working, 'miptp-mn-test.py'. I chose to include it in case it can be helpful to verify the behavior of my MIPTP implementation.
The script is inspired by the structure of Home Exam 1, but adapted to this project and extended to support richer testing scenarios. The instructions on how to run the script and which commands to use can be found in the file.

## Debug mode
The -d flag enables detailed logging of internal events
Example:
    [MIPTPD][INIT] First packet seq=0 → expected_seq=1
    [MIPTPD][GBN] ACK received for seq=0 (port=10)
    [MIPTPD] Delivered 140 bytes to app port 20 (fd=5)

## Protocol Design
The MIP Transport Protocol (MIPTP) provides reliable, connection-oriented delivery using Go-Back-N 

Key Features
- Reliable delivery:
    Every DATA packet must be acknowledged (ACK) by the receiver
- Sliding window per transfer:
    Each transfer maintains its own send window, allowing up to MIPTP_WINDOW_SIZE unacknowledged packets in flight
- Per-transfer retransmissions:
    Timers track the oldest unacknowledged packet for each transfer and trigger Go-Back-N retransmissions on timeout
- Per-transfer sequence numbering:
    Each transfer uses independent 14-bit sequence numbers with wrap-around handling
- Multiple concurrent transfers per application:
    An application may communicate with multiple remote (mip, port) endpoints simultaneously
    Each such communication pair maintains its own send-state (base_seq, next_seq, window, retransmission timers) and receive-state (expected_seq, sync state)
- Full duplex support:
    Inbound and outbound transfers are tracked separately, allowing a single application to send and receive data concurrently using independent flow control

## Data flow
Application <-> MIPTPD <-> MIPD <-> Network <-> Remote MIPD <-> Remote MIPTPD <-> Application

## Project Structure
- Network and Routing Layer (mipd_and_routingd)
    This part contains everything related to the MIP network:
    the MIP daemon (mipd), the routing daemon (routingd), ARP handling, interface code, and packet/PDU processing.

- Transport Layer, miptpd (transport)
    This is the implementation of the MIP Transport Protocol.
    The transport daemon (miptpd) handles application data and ensures reliable delivery.
    It is separated from the network layer and communicates with mipd through UNIX domain sockets.

- Compiled binaries (bin/)
    All executables end up in the bin/ directory after running make.
    This puts all binaries—mipd, routingd, miptpd, and all test programs—in one place.

- Top-level build system
    A top-level Makefile builds the whole project, while each subsystem (mipd_and_routing and transport) has its own Makefile

## Note
Comments are written in Norwegian, as this made the implementation easier for me to work with during development. Ideally they would be in English for consistency.



