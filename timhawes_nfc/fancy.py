#
# Copyright 2021 Tim Hawes
# All Rights Reserved
#

from .card import SimpleCard, APDUError, nfc_tlv_parse
from .ntag import NtagMixin
from .iso import IsoMixin
#from .piv import PivMixin


class FancyCard(NtagMixin, IsoMixin, SimpleCard):

    def read_block(self, block: int) -> bytes:
        """Read 16 bytes starting at the given block."""
        print("fetching block", block)
        return self.dataexchange([0x30, block], response_length=16)

    def read_blocks(self, start_block: int, end_block: int) -> bytes:
        data = b""
        for block in range(start_block, end_block, 4):
            data = data + self.read_block(block)
        return data

    def nfc_type_2_read(self) -> bytes:
        blocks3to6 = self.mifare_read_blocks(3)
        cc = blocks3to6[0:4]
        data = blocks3to6[4:]
        if cc[0] == 0xE1:
            version = cc[1]
            data_area_size = cc[2] * 8
            read_access = cc[3] >> 4
            write_access = cc[3] & 0x0F
            # print("cc", binascii.hexlify(cc, " "))
            # print("  version {}.{}".format(version >> 4, version & 0x0F))
            # print("  data area size {}".format(data_area_size))
            # print("  read access {}".format(read_access))
            # print("  write access {}".format(write_access))
            # if len(data) < data_area_size:
            #     print("fetching more data")
            #     nblocks = (data_area_size - len(data)) / 4
            #     data = data + self.read_blocks(7, 6 + nblocks)
            # print("data", data)
            messages = []
            terminated = False
            for t, l, v in nfc_tlv_parse(data):
                print("tlv", t, l, v)
                if t == 0xFE:
                    terminated = True
                    break
                if t == 0x03:
                    messages.append(v)
            if not terminated:
                print("missing data")
            if messages:
                return messages[0]

    def nfc_type_4_read(self) -> bytes:
        try:
            # Select NFC application
            self.iso_select_df(b"\xD2\x76\x00\x00\x85\x01\x01")
            # Select CC file
            response, sw1, sw2 = self.apdu(b"\x00\xA4\x00\x0C\x02\xE1\x03")
            # ReadBinary
            cc, sw1, sw2 = self.apdu(b"\x00\xB0\x00\x00\x0F")
            # print("cc", binascii.hexlify(cc, ' '))
            # print("cc len", cc[0:2])
            # print("cc mapping version", cc[2])
            # print("cc maximum data size readbinary", cc[3:5])
            # print("cc maximum data size updatebinary", cc[5:7])
            # print("cc ndef file control tlv", cc[7:15])
            ndef_max_readbinary = int.from_bytes(cc[3:5], "big")
            ndef_file_id = cc[9:11]
            ndef_max_size = int.from_bytes(cc[11:13], "big")
            ndef_read_access = cc[13]
            ndef_write_access = cc[14]
            # print("ndef_file_id", ndef_file_id)
            # print("ndef_max_size", ndef_max_size)
            # print("ndef_read_access", ndef_read_access)
            # print("ndef_write_access", ndef_write_access)
            # Select NDEF file
            response, sw1, sw2 = self.apdu(b"\x00\xA4\x00\x0C\x02" + ndef_file_id)
            # ReadBinary, first two bytes
            response, sw1, sw2 = self.apdu(b"\x00\xB0\x00\x00\x02")
            ndef_length = int.from_bytes(response[0:2], "big")
            # ReadBinary, payload
            # FIXME: check sizes and download larger messages
            response, sw1, sw2 = self.apdu(b"\x00\xB0\x00\x02" + response[1:2], response_length=ndef_length+2)
            return response
        except APDUError as e:
            if e.sw1 == 0x6A and e.sw2 == 0x82:
                # File or application not found
                return None
            raise e

    @property
    def ndef_data(self) -> bytes:
        if self.is_iso14443_4:
            return self.nfc_type_4_read()
        else:
            return self.nfc_type_2_read()
