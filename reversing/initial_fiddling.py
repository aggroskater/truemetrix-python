#!/usr/bin/env python3

# truemetrix
# Copyright (C) 2021 Preston Maness
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#
# Goal: Prove that most of the packet data bytes are similar with the exception
# of the ones at the start (the first 9 or 10 bytes)
#
# Status: Proven
#

from typing import Dict
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket

bytearray = []

with open('./captures/true-metrix-usb-cap-2021-12-06.pcapng','rb') as fp:
    
    # each entry in bytearray is a dict that records how many times each
    # binary value was found in the Nth byte in the packet
    for i in range(64):
        bytearray.append({})
        
    #print(bytearray)
    scanner = FileScanner(fp)
    for block in scanner:
        #print("block found")
        #blk = block.interface
        #print(block.packet_payload_info)

                

        try:
            packet = block.packet_payload_info
            if(packet[1] == 128):

                # we don't have any handy dandy types to help us
                # like there are in wireshark. so... we want to
                # filter based on direction so we only look at
                # 128 byte length packets from device to host,
                # not host to device. If this byte is 1, then
                # it's host to device. Don't want it. Skip it.
                if int(bytes(packet[2])[10]) == 1:
                    continue

                bytestring = bytes(packet[2])[64:]
                ctr = 0
                for b in bytestring:
                    #print(b, end='')
                    if str(b) not in bytearray[ctr]:
                        bytearray[ctr][str(b)] = 1
                    else:
                        bytearray[ctr][str(b)] = bytearray[ctr][str(b)] + 1
                    ctr = ctr + 1
                #print()
            else:
                #print("skip")
                pass
        except AttributeError:
            pass
    
    #print(bytearray)
    for dic in bytearray:
        print(len(dic))

