# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii

from .card import nfc_tlv_parse, CardError


class NtagMixin:
    def fast_read(self, start, end):
        length = (end + 1 - start) * 4
        return self.communicatethru([0x3A, start, end], response_length=length)

    def read_cnt(self, counter):
        response = self.communicatethru([0x39, counter], response_length=3)
        if response:
            return int.from_bytes(response, "little")
        return None

    def read_sig(self):
        return self.communicatethru([0x3C, 0x00], response_length=32)

    def pwd_auth(self, pwd):
        # pwd should be 4 bytes
        return self.communicatethru(b"\x1B" + pwd, response_length=2)

    @property
    def ntag_version(self):
        return self.version

    @property
    def ntag_model(self):
        return self.model

    @property
    def ntag_signature(self):
        if "ntag_signature" in self.data:
            return self.data["ntag_signature"]
        try:
            self.data["ntag_signature"] = self.read_sig()
            return self.data["ntag_signature"]
        except CardError:
            return None

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
            b"\x00\x04\x04\x04\x01\x00\x0F\x03": 0x2C,
            b"\x00\x04\x04\x04\x01\x00\x11\x03": 0x86,
            b"\x00\x04\x04\x04\x01\x00\x13\x03": 0xE6,
        }
        try:
            max_block = version_map[self.ntag_version]
        except KeyError:
            return None
        read_blocks = 56
        data = b""
        for block_start in range(0, max_block, read_blocks):
            block_end = min(block_start + read_blocks, max_block)
            try:
                response = self.fast_read(block_start, block_end)
            except CardError:
                return None
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
        try:
            # read block zero to ensure that counter is incremented
            # self.communicatethru([0x3A, 0, 0], response_length=4)
            self.fast_read(0, 0)
            count = self.read_cnt(2)
            if count is not None:
                self.data["ntag_counter"] = count
                return count
        except CardError:
            return None

    @property
    def ntag_ndef(self):
        if self.ntag_data is None:
            return None
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
                # print("tlv", t, l, v)
                if t == 0xFE:
                    terminated = True
                    break
                if t == 0x03:
                    messages.append(v)
            if not terminated:
                print("missing data")
            return messages
