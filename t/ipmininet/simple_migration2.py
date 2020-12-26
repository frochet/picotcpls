from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.link import TCIntf
from mininet.log import lg
from ipmininet.router.config import OSPF, RouterConfig

class MyTopology(IPTopo):

    def build(self, *args, **kwargs):
        """
                 -----r2-----
                /             \ 
       c --- r1                r3 --- s
                \             /
                 -----r4------
        """

        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2", use_v6=False)
        r3 = self.addRouter("r3")
        r4 = self.addRouter("r4", use_v4=False)
        c = self.addHost("c")
        s = self.addHost("s")
        self.addLink(c, r1)
        r1r2 = self.addLink(r1, r2, delay="10ms", bw=30)
        r2r3 = self.addLink(r2, r3, delay="10ms", bw=30)
        r1r4 = self.addLink(r1, r4, delay="20ms", bw=30)
        r4r3 = self.addLink(r4, r3, delay="20ms", bw=30)
        self.addLink(r3, s)
        super().build(*args, **kwargs)

lg.setLogLevel("info")
net = IPNet(topo=MyTopology(), intf=TCIntf)
try:
    net.start()
    IPCLI(net)
finally:
    net.stop()

