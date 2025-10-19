from mininet.topo import Topo

# Usage example:
# sudo mn --mac --custom he1-mn-topo.py --topo he1 --link tc


class H1Topo(Topo):
    "Larger topology for Home Exam 1."
    def __init__(self):
        Topo.__init__(self)
        A = self.addHost('A')
        B = self.addHost('B')
        self.addLink(A, B, bw=10, delay='5ms')

topos = {'he1': (lambda: H1Topo())}

#     def __init__(self):
#         "Set up our custom topo."

#         # Initialize topology
#         Topo.__init__(self)

#         # Add hosts
#         A = self.addHost('A')
#         B = self.addHost('B')
#         C = self.addHost('C')
#         D = self.addHost('D')
#         E = self.addHost('E')

#         # Add links
#         self.addLink(A, B, bw=10, delay='10ms', loss=0.0, use_tbf=False)
#         self.addLink(B, C, bw=10, delay='10ms', loss=0.0, use_tbf=False)
#         self.addLink(B, D, bw=10, delay='10ms', loss=0.0, use_tbf=False)
#         self.addLink(C, D, bw=10, delay='10ms', loss=0.0, use_tbf=False)
#         self.addLink(D, E, bw=10, delay='10ms', loss=0.0, use_tbf=False)


# topos = {'he1': (lambda: H1Topo())}
