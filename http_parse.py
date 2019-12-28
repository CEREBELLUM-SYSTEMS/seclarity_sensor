#!/usr/bin/env python3
from pymongo import MongoClient
import json
import scapy.all as scapy
import scapy_http.http

iface = ''

uri = ''
client = MongoClient(uri)
db = client.db_name

def parse_packet(packet):
    if 'HTTPRequest' in packet:
        ua = getattr(packet['HTTPRequest'], 'User-Agent')
        if ua != None:
            mac = packet['Ether'].src
            ua = ua.decode('ascii')
            db.devices.update_one(
                {'mac': mac},
                { '$addToSet': {
                    'classifiers.user-agents': ua }
                    },
            )
            db.devices.update_one(
                {'mac': mac},
                {'$set': {
                    'ip': packet['IP'].src
                    }
                },
                upsert=True
            )
scapy.sniff(iface=iface, filter='tcp port 80',  prn=parse_packet)
