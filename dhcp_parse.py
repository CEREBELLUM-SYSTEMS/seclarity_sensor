#!/usr/bin/env python3
from pymongo import MongoClient
from scapy.all import *
import json

iface = ''

uri = ''
client = MongoClient(uri)
db = ''

def parse_packet(packet):
    if (packet.haslayer(DHCP)):
        if packet[DHCP].options[0][1] == 3:
            vid = ' '
            mac = packet[Ether].src
            dhcp_hostname = ''
            for x in packet[DHCP].options:
                if x[0] == 'param_req_list':
                    df = x[1]
                elif x[0] == 'vendor_class_id':
                    vid = x[1].decode('ascii')
                elif x[0] == 'hostname':
                    dhcp_hostname = x[1].decode('ascii')
            db_status = db.devices.update_one(
                { 'mac': mac },
                { '$set' : 
                    {
                        'mac': mac,
                        'classifiers': {
                            'dhcp_hostname': dhcp_hostname,
                            'dhcp_fingerprint': df,
                            'dhcp_vendor_id': vid,
                        }
                    }
                },
                upsert = True
            )
            print(db_status)
        else:
            pass
    else:
        pass


sniff(iface=iface, filter="udp and (port 67 or 68)", prn=parse_packet)
