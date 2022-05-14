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

mybytearray = []

for i in range(9):
    byteinfo = {
        "index": i,
        "min": 255,
        "max": 0,
        "unique_vals": []
    }
    mybytearray.append(byteinfo)

with open('/home/preston/true-metrix-usb-driver-adventure/true-metrix-python/reversing/captures/true-metrix-usb-cap-2021-12-06.pcapng','rb') as fp:
        
    #print(bytearray)
    scanner = FileScanner(fp)
    pkt = 0
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

                # only the first nine bytes have meaningfully different values
                #bytestring = bytearray(packet[2])[64:][:9]
                temp1 = packet[2]
                temp2 = temp1[64:]
                temp3 = temp2[:9]
                temp4 = list(temp3)

                ctr = 0
                for byte in temp4:
                    data = mybytearray[ctr]
                    temp5 = data['max']
                    if byte > data['max']:
                        data['max'] = byte
                    elif byte < data['min']:
                        data['min'] = byte
                    if byte not in data['unique_vals']:
                        data['unique_vals'].append(byte)
                    ctr = ctr + 1

                

            else:
                #print("skip")
                pkt = pkt + 1
                pass
        except AttributeError:
            pass

    for i in mybytearray:
        i['uniq_count'] = len(i['unique_vals'])
        print("index: " + str(i['index']))
        print("min: " + str(i['min']))
        print("max: " + str(i['max']))
        print("range: " + str(i['max'] - i['min']))
        print("uniqs: " + str(i['uniq_count']))
        print()

    #print(mybytearray)