#
# Copyright 2021 Tim Hawes
# All Rights Reserved
#

import binascii

from .card import nfc_tlv_parse


class NtagMixin:
    
    @property
    def ntag_version(self):
        if "ntag_version" in self.data:
            return self.data["ntag_version"]
        response = self.communicatethru([0x60], response_length=8)
        if response:
            self.data["ntag_version"] = response
            return self.data["ntag_version"]

    @property
    def ntag_model(self):
        if "ntag_model" in self.data:
            return self.data["ntag_model"]
        version_map = {
            b"\x00\x04\x04\x02\x01\x00\x0F\x03": "NTAG213",
            b"\x00\x04\x04\x02\x01\x00\x11\x03": "NTAG215",
            b"\x00\x04\x04\x02\x01\x00\x13\x03": "NTAG216",
        }
        if self.ntag_version:
            return version_map.get(self.ntag_version)

    @property
    def ntag_signature(self):
        if "ntag_signature" in self.data:
            return self.data["ntag_signature"]
        response = self.communicatethru([0x3C, 0x00], response_length=32)
        if response:
            self.data["ntag_signature"] = bytes(response)
            return self.data["ntag_signature"]

    @property
    def ntag_data(self):
        if "ntag_data" in self.data:
            return self.data["ntag_data"]
        if self.ntag_version is None:
            return None
        version_map = {
            b"\x00\x04\x04\x02\x01\x00\x0F\x03": 0x2C,
            b"\x00\x04\x04\x02\x01\x00\x11\x03": 0x86,
            b"\x00\x04\x04\x02\x01\x00\x13\x03": 0xE6,
        }
        max_block = version_map[self.ntag_version]
        read_blocks = 56
        data = b""
        for block_start in range(0, max_block, read_blocks):
            block_end = min(block_start + read_blocks, max_block)
            response = self.communicatethru(
                [0x3A, block_start, block_end],
                response_length=((block_end - block_start) * 4) + 4,
            )
            if response:
                data = data + response
            else:
                return None
        self.data["ntag_data"] = data
        return self.data["ntag_data"]

    @property
    def ntag_counter(self):
        if "ntag_counter" in self.data:
            return self.data["ntag_counter"]
        response = self.communicatethru([0x3A, 0, 0], response_length=4)
        response = self.communicatethru([0x39, 0x02], response_length=3)
        if response:
            self.data["ntag_counter"] = int.from_bytes(response, "little")
            return self.data["ntag_counter"]

    @property
    def ntag_ndef(self):
        cc = self.ntag_data[12:16]
        data = self.ntag_data[16:]
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
            # print(data)
            for t, l, v in nfc_tlv_parse(data):
                #print("tlv", t, l, v)
                if t == 0xFE:
                    terminated = True
                    break
                if t == 0x03:
                    messages.append(v)
            if not terminated:
                print("missing data")
            return messages


