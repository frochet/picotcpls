from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.link import TCIntf
from mininet.log import lg
from ipmininet.router.config import RouterConfig, STATIC, StaticRoute

class MyTopology(IPTopo):

    def build(self, *args, **kwargs):
        """
                   -----r2-----
          -v4-    /             \ -v4-
         c     r1                r3    s  50.50.50.5 and 2042:cafe::1
          -v6-    \             / -v6-
                   -----r4------
        """

        r1 = self.addRouter("r1", config=RouterConfig,\
                            lo_addresses=["2042:1::1/64", "10.50.0.1/24"])
        r2 = self.addRouter("r2", config=RouterConfig,
                            lo_addresses=["10.51.0.1/24"])
        r3 = self.addRouter("r3", config=RouterConfig,\
                            lo_addresses=["2042:2::1/64", "10.52.0.1/24"])
        r4 = self.addRouter("r4", config=RouterConfig,
                            lo_addresses=["2042:3::1/64"])
        c = self.addHost("c")
        s = self.addHost("s")
        
        cr1 = self.addLink(c, r1)
        cr1_v6 = self.addLink(c, r1)
        cr1[c].addParams(ip=("130.104.205.174/24"))
        cr1[r1].addParams(ip=("130.104.205.1/24"))
        cr1_v6[c].addParams(ip=("2042:abe::1/64"))
        cr1_v6[r1].addParams(ip=("2042:abe::2/64"))

        r1r2 = self.addLink(r1, r2, delay="10ms", bw=30)
        r1r2[r1].addParams(ip=("10.1.0.1/24"))
        r1r2[r2].addParams(ip=("10.1.0.2/24"))

        r2r3 = self.addLink(r2, r3, delay="10ms", bw=30)
        r2r3[r2].addParams(ip=("10.2.0.1/24"))
        r2r3[r3].addParams(ip=("10.2.0.2/24"))

        r3s = self.addLink(r3, s)
        r3s_v6 = self.addLink(r3, s)
        r3s[s].addParams(ip=("50.50.50.5/24"))
        r3s[r3].addParams(ip=("50.50.50.1/24"))
        r3s_v6[s].addParams(ip=("2042:cafe::1/64"))
        r3s_v6[r3].addParams(ip=("2042:cafe::a/64"))
    
        r1r4 = self.addLink(r1, r4, delay="20ms", bw=30)
        r1r4[r1].addParams(ip=("2042:1a::1/64"))
        r1r4[r4].addParams(ip=("2042:1a::a/64"))

        r4r3 = self.addLink(r4, r3, delay="20ms", bw=30)
        r4r3[r4].addParams(ip=("2042:2b::2/64"))
        r4r3[r3].addParams(ip=("2042:2b::b/64"))
    
        r1.addDaemon(STATIC, static_routes=[StaticRoute("50.50.50.0/24",\
                                                        "10.1.0.2"),\
                                            StaticRoute("10.2.0.0/24",\
                                                        "10.1.0.2"),\
                                            StaticRoute("2042:cafe::/64",\
                                                        "2042:1a::a")])
        r2.addDaemon(STATIC, static_routes=[StaticRoute("50.50.50.0/24",\
                                                        "10.2.0.2"),\
                                            StaticRoute("130.104.205.0/24",\
                                                        "10.1.0.1")])
        r3.addDaemon(STATIC, static_routes=[StaticRoute("130.104.205.0/24",\
                                                        "10.2.0.1"),\
                                            StaticRoute("10.1.0.0/24",\
                                                        "10.2.0.1"),\
                                            StaticRoute("2042:abe::/64",\
                                                        "2042:2b::2")])
        
        r4.addDaemon(STATIC, static_routes=[StaticRoute("2042:abe::/64",\
                                                      "2042:1a::1"),\
                                          StaticRoute("2042:cafe::/64",\
                                                      "2042:2b::b")])

        super().build(*args, **kwargs)

lg.setLogLevel("info")
net = IPNet(topo=MyTopology(), intf=TCIntf, allocate_IPs=False)
try:
    net.start()
    net["c"].cmd("ip -6 route add default via 2042:abe::2")
    net["s"].cmd("ip -6 route add default via 2042:cafe::a")
    IPCLI(net)
finally:
    net.stop()

