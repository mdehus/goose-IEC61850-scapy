from scapy.all import *
import goose

a = rdpcap("/home/dehus/Downloads/wireshark2.pcap")
for i in a:
    try:
        if i.type == 0x88b8:
            g = goose.GOOSE(i.load)
            print repr(g.load)
            gpdu = goose.GOOSEPDU(g.load[4:])
            print gpdu.__dict__
    except AttributeError:
        continue
