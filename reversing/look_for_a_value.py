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
            #    desired = '000100100000'
            #    if desired in bytestream:
            #        #print("normal bcd - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired)))
            #        print("normal bcd - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
            #    pkt = pkt + 1

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

                # HOLLUPAMINIT. What about endianness? I've been operating assuming that
                # I'll be getting data "in order", where I get the bigest pieces first.
                # But what if it's little endian? Apparently USB does little endian by
                # default and what I have is a raw USB packet capture, so... 

                # 147 in BCD is... '0001 0100 0111' . Let's assume we use two bytes and
                # pad the last value as '0000'. So big endian would be '0000 0001 0100 0111'.
                # But if we got the bytes in little endian order, we'd get '0100 0111 0000 0001'.
                # Let's check both...
                # little 147
                #desired = '0100011100000001' # 1 match
                # little 176 "0001 0111 0110" -> "0000 0001 0111 0110" -> "0111 0110 0000 0001"
                # little 176 label "0001 0111 0110" -> "0001 0001 0111 0110" -> "0111 0110 0001 0001"
                #desired = '0111011000000001'
                desired = '0111011001000001' # with 0100 as the padding, I get a single result, and it's at an early packet; 62.
                # with 0100 as padding...
                #
                # padded normal bcd LE - packet number: 62 - position - 1.0
                #
                # how many "not eaten 176" reads do I have? ...
                #
                # drum roll...
                #
                # x
                #
                # just one :)

                # ok... so that's promising...

                # is the very next entry one of the next packets? or at least after packet 62?
                # 177 eaten (eaten is "0000") -> "0000 0001 0111 0111" -> "0111 0111 0000 0001"
                desired = '0111011100000001'
                # drats. no results.
                # maybe boundary problem?
                # try next entry: 116 not eaten (not eaten is "0100") -> "0100 0001 0001 0110" -> "0001011001000001"
                #desired = '0001011001000001'
                # again nothing -__-
                # what if we only look for "16" portions of the BCD?
                desired = '10011001'
                # that found a few things...
                # maybe I should focus on trying to find a pattern from just that byte that's consistent and work
                # my way outwards?
                # 
                # eh... not much promise there.
                #
                # maybe we're not getting whole readings in order? but JUST all readings, then JUST all labels?
                # something like that? 176 then 177 are first two readings. if they were in order, and just
                # padded with zeros, we'd see...
                # "0000 0001 0111 0110" + "0000 0001 0111 0111"
                # which reversed would be...
                # "0111 0110 0000 0001" + "0111 0111 0000 0001"
                desired = "01110110000000010111011100000001"
                # nothing. with estimated padding info?
                desired = "01110110010000010111011100000001"
                # nope.

                # back to fiddling with eaten 177...
                desired = '1001'+'0000'+'0000'+'0000'
                # nothing. no matter the padding value, nothing -__-

                # is it not actually Little Endian? Did I just get lucky a few times?
                #
                # I feel like going back to my "it seems like they store 15X" idea.
                #
                # Like, searching for BE "000101010010" for 152 gets nothing, but
                # "000101010000" for 150 gets lots, what if that's a consequence of
                # BE padding? Like, "0001" + "0101" + "0000" + "0010" would be 152?
                # But how? I guess if you're both doing BE, *and* saying digits 1 and
                # 5 should go in the first byte, and then a padding indicator plus
                # the last nibble going into the second byte... hmmm. Let's play with
                # that. First without any notion of the label getting stuffed into that
                # padding.
                #
                # 176
                desired = "0001" + "0111" + "0000" + "0110"
                # nothing! FFS.
                #
                # Maybe they're storing mmol/L and merely presenting/converting to mg/dL?
                # Is it possible to store mmol/L more efficiently? Perhaps with a single bit
                # to indicate whether you're on the even mg/dL or up one unit for the odd
                # mg/dL?
                #
                # 176 mg/dL == 9.8 mmol/L
                #
                # If I wanted to store 9.8, I could do it as two BCD entries rather than 3.
                # But eventually I'd need 3 again for higher readings, which we already know
                # the device can show. But... 
                #
                # 255 mmol/L = 4,590 mg/dL
                #
                # If you've got 4500 mg/dL, then you're dead. Or at least on your way to death.
                #
                # Which means... you could store a mmol/L in a single byte! That would only
                # give you even mg/dL, but a single bit there can serve to determine incrementing
                # by one or not. 9 bits is definitely cheaper than 12 bits...
                #
                # Let's experiment with this a bit. Let's say we want to store 176 mg/dL as
                # 9.8 mmol/L, and we'll store "9.8" as integer "98", and there's a bit for
                # whether or not to shift/divide by ten or not. That'd still give us 10 total
                # bits as opposed to 12... And we could do math on those integers more easily
                # *on the device* than having to convert every BCD to an int representation or
                # something...

                # Ok. 98 in hex is 0x62, which is '01100010'
                desired = '01100010'
                # lots of results. Which I guess is expected when we're literally only looking
                # for a single byte. There's probably lots of false positives here. But let's
                # keep going.
                # 116 0x74 '01110100'
                desired = '01110100'

                # 154 0x9A '10011010'
                desired = '10011010'

                #####################################################################

                #
                # big 147
                #desired = '0000000101000111' # no match
                #
                # And if we padded on the other end...
                #
                # BE: '0001 0100 0111 0000'
                # LE: '0111 0000 0001 0100'
                #
                # little reverse pad 147
                #desired = '0111000000010100' # 2 matches, both at position 5.125.
                # LE reverse pad 176...  "0001 0111 0110" -> "0001 0111 0110 0000" -> "0110 0000 0001 0111"
                #desired = '0110000000010111' # nothing?
                # big reverse pad 147
                #desired = '0001010001110000' # 7 matches, all but one at position 5.125.
                if desired in bytestream:
                    #print("padded normal bcd BE - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
                    print("padded normal bcd LE - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
                    #print("reverse padded normal bcd BE - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
                    #print("reverse padded normal bcd LE - packet number: " + str(pkt) + " - position - " + str(bytestream.index(desired) / 8 ))
                pkt = pkt + 1

                # now... how many 147s have I popped from start to Dec 9?
                #
                # drumroll...
                #
                # x
                #
                # ugh. only one. But... the two entries i have for 147 with little reverse pad are at packets 158 and 162, so they're
                # close at least? And on the same position?
                #
                # Waitwaitwait... I got one match with normal little endian, right?
                #
                # ... yeah:
                #
                # reverse padded normal bcd LE - packet number: 504 - position - 1.625
                #
                #
                # But i'm not getting other values in that format that I know exist -__-
                #
                # Hmmm. There is also a "label" that you can apply to a reading. I wonder
                # if that's getting shoved into the "padding" of the reading. The single 147
                # I have is an "eaten apple" (indicating i took the reading after eating)
                # Four bits would be more than enough to cover all of the labels. Perhaps
                # "0000" is eaten? And something else is "full apple" (indicating i took the
                # reading prior to eating)? there are six labels:
                #
                # full apple - haven't eaten
                # eaten apple - have eaten
                # running man - after exercise
                # pill - other medications in play
                # flag - some other indicator that means whatever you want it to mean
                # fever face - you're sick
                #
                # And we'll assume...
                # eaten apple - "0000"
                # full apple - "????" assuming "0100"
                # let's try "0001" for full apple... 

            else:
                #print("skip")
                pkt = pkt + 1
                pass
        except AttributeError:
            pass
