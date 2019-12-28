from scapy.all import *

iface = 'ens224'

def parse_tcp_options(tcp_options_raw):
    tcp_opts = {}
    for x in tcp_options_raw:
        if x[0] == 'MSS':
            tcp_opts.update({'mss' : x[1]})
        elif x[0] == 'SAckOK':
            tcp_opts.update({'sok' : x[1]})
        elif x[0] == 'Timestamp':
            tcp_opts.update({'ts' : x[1]})
        elif x[0] == 'NOP':
            tcp_opts.update({'nop' : x[1]})
        elif x[0] == 'WScale':
            tcp_opts.update({'ws' : x[1]})
        else:
            pass

    return tcp_opts

def adjust_ttl(cttl):
    if cttl == (255 or 128 or 64 or 32):
        ittl = cttl
    elif cttl < 255 and cttl > 128:
        ittl = 255
    elif cttl < 128 and cttl > 64:
        ittl = 128
    elif cttl < 64:
        ittl = 64
    else:
        ittl = cttl

    return ittl

def parse_packet(packet):
    if packet['TCP'].flags == 'S':
        ver = str(packet['IP'].version)
        ttl = str(adjust_ttl(packet['IP'].ttl))
        pkt_options_dict = parse_tcp_options(packet['TCP'].options)
        sig = ver + ':' + ttl + ':' + '0:'
        print(sig)

sniff(iface=iface, filter="tcp", prn=parse_packet)
