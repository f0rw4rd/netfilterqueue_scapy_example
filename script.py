#!/bin/env python3
# based on https://github.com/Simone-Zabberoni/scapy-nfqueue-dnsspoof/blob/master/dnsSpoof.py

from scapy.utils import hexdump, hexdiff
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.all import *
from scapy.fields import ( ByteField, ByteEnumField, FieldLenField, StrLenField, LEIntField, PacketField)
from netfilterqueue import NetfilterQueue
import argparse
import sys
import struct
import os
import crcmod
from pprint import pprint
import binascii
import random

crc32 = crcmod.mkCrcFun(0x1414141AB, initCrc=0, xorOut=0xFFFFFFFF)
target_ip = "127.0.0.1"
target_port = 5555
debug = False

class _CatotronMessageTypes(Packet): 
    def extract_padding(self, p):
	    return b'', p

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            t = pkt[0]
            return catotronMessageTypes.get(t)
        return cls

class DiceRoll(_CatotronMessageTypes):
    name = "DiceRoll"
    fields_desc=[
        ByteField("type", 0x2),
        LEIntField("rng", random.randint(1, 0x41414141))
    ]

class HeartBeat(_CatotronMessageTypes):
    name = "HeartBeat"
    fields_desc=[
        ByteField("type", 0x0),
        LEShortField("counter", 0x42)
     ]

class TextMessage(_CatotronMessageTypes):
    name = "TextMessage"
    fields_desc=[ ByteField("type", 0x1),
                  FieldLenField("length", None, fmt="<H", length_of="data"),
                  StrLenField("data", None, length_from=lambda p:p.length)]

class Catotron(Packet):
    name = "Catotron"
    fields_desc=[ ByteField("version",1),
                  ByteField("subversion",2),              
                  FieldLenField("size", None, fmt="<H",length_of="message"),
                  PacketListField("message", [], _CatotronMessageTypes, length_from=lambda p:p.size),
                  LEIntField("crc", None),
                  LEShortField("end_frame", 0x4141)]
                  

    def post_build(self, p, pay):         
        if self.crc is None:
            end_of_frame=2
            crc_length=4            
            p = p[:-(end_of_frame+crc_length)]+ struct.pack("<I",  crc32(raw(p[:-5]))) + p[-end_of_frame:len(p)]         
        return p

catotronMessageTypes = {
    0: HeartBeat,
    1: TextMessage,
    2: DiceRoll
}

bind_layers(UDP, Catotron, dport=target_port)

def packetspoof(packet):
    # only udp packets should reach this method
    rawPacket = packet.get_payload()
    p = IP(rawPacket)

    if debug:
        p.show2()
    
    if not p.haslayer(Catotron): # filter 
        print("Got a differnt packet on the target port")                
        p.show2()
        packet.accept()    
        return 

    
    print("Intercepted request for {}".format(p.summary()))        
    print("Spoofing response to: {}".format(p.summary()))
    for m in p[Catotron].message:
        if isinstance(m, TextMessage):
            m.data = "You have been intercepted!" 
            del m.length

    # delete checksum and size to force and update
    del p[Catotron].size
    del p[Catotron].crc 
    del p[UDP].chksum 
    rawPacket_changed = bytes(p)
    if debug:            
        print("Hex diff packet")
        hexdiff(rawPacket, rawPacket_changed)
        print("Hexdump of the packet")
        restored = Catotron(bytes(IP(rawPacket_changed)[Catotron])) # for some reason the packet needs to decoded again to be displayed correctly
        hexdump(restored)
        print(bytes(restored))
        restored.show()

    packet.set_payload(rawPacket_changed)
    packet.accept()
    


def setup_nf():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, packetspoof)
    nfqueue.bind(2, packetspoof)

    # wait for packets
    try:    
        print("Running NF")
        nfqueue.run()
    except KeyboardInterrupt:
        pass

def test_catotron():
    p = Catotron(message=[HeartBeat(), TextMessage(data=":-D"), DiceRoll()])
    
    p.show2()
    hexdump(p)    
    Catotron(bytes(p)).show2()
    print(bytes(p))

test_catotron()
setup_nf()