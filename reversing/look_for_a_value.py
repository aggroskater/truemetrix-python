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
    pkt = 0
    for block in scanner:
        #print("block found")
        #blk = block.interface
        #print(block.packet_payload_info)
        try:
            packet = block.packet_payload_info
            if(packet[1] == 128):
                bytestring = bytes(packet[2])[64:][:10]
                bnum = 0
                # also try to just look at the raw bytestream as zeros and ones...
                bytestream = ''
                for b in bytestring:
                    #print(hex(b), end='')
                    #print(b, end='')
                    bytestream += '{:08b}'.format(b)
                    actual = '0x{0:0{1}X}'.format(b,2)
                    desired = '0x{0:0{1}X}'.format(150,2)
                    if actual == desired:
                        print("packet number: " + pkt)
                        print("byte number: " + bnum)
                        print('0x{0:0{1}X}'.format(b,2))
                    #print('|', end='')
                    bnum = bnum + 1
                #print()
                #print(bytestream)

                # I've popped several 150s, so if they're storing
                # the data as any normal form of integer, I should
                # see a '10010110' substring inside at least *some*
                # of these `bytestream`s.
                desired = '{:b}'.format(150)
                if desired in bytestream:
                    print("normal - packet number: " + str(pkt))
                # Result: nada :(

                # Maybe some weird-ass BCD thing going on?
                desired = '{:08b}'.format(1) + '{:08b}'.format(6) + '{:08b}'.format(0)
                #print(desired)
                if desired in bytestream:
                    print("weird bcd - packet number: " + str(pkt))

                # normal bcd?
                # BCD of '150' is '000101010000'
            #    desired = '000101010000'
            #    if desired in bytestream:
            #        print("normal bcd - packet number: " + str(pkt))
                # Got 18 results... I've only popped 3 150s though...
                # what if it's counting 15X though and storing the last digit elsewhere?
                #
                # xxxx xxxx xxxx xxxx xxxx x
                #
                # hmmmm 21 instances of a 15X.
                #
                # granted, my pull was from... Dec 9. So let's go back and erase past that.
                # 
                # 3 x from Dec 10 or past.
                # 1 x from Dec 9.
                # gonna say the one from Dec 9 is included in my set and the 3 past aren't.
                # which means... 21 instances of 15X minus 3 that won't be in our capture...
                # gives us... 18. Awesome. So perhaps there's we're storing 150 as a base, and
                # then adding the last decimal from elsewhere.
                #
                # next thing to do is... see where in each packet this particular bitstream
                # exists.

                # and if I throw a BCD I know I haven't done, like 410?
                # 410
                #desired = '010000010000'
                # 300
                #desired = '001100000000'
                # 120
                #
                # xxxx xxxx x
                #
                # 9 in memory up to Dec 9, and we found... 8. Maybe I miscounted by 1?
                # Maybe it's incidental that another bitstream looks like that? This is
                # where knowing position would be helpful. Let's do that too.
                desired = '000100100000'
                if desired in bytestream:
                    #print("normal bcd - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired)))
                    print("normal bcd - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
                pkt = pkt + 1

                #
                # Ok. That's not at all helpful either. position is all over the place -__-
                # Maybe if I divide by 8 to get bytes? Still not good. 4, 3, 2, 5, 4, 2, 1, 6
                #
                #
                # I mean, maybe that's not a big deal? I mean, having it line up would imply
                # that every single packet, of which there are 128 total bytes and 64 useful
                # bytes, would be devoted to a single entry. And odds are, you can store more
                # than one entry in 64 bytes. An entry consists of a date, time, measurement,
                # and possible label. That's it. What if the waffling on position is just a
                # reflection that some portion of a particular entry coming over the wire
                # might get split across packets? Causing the start of the next one to be
                # offset slightly? Rather than right on the first byte?
                #
                # But if that were the case, why are only the first 10 bytes filled with
                # data? I mean, I guess the same problem could manifest itself even if
                # you're only using the first 10 bytes, just... why not send more?
                # I'd assume because the device can't do it. But I don't know that for
                # sure.
            else:
                #print("skip")
                pkt = pkt + 1
                pass
        except AttributeError:
            pass
