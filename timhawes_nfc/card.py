# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii


class NFCError(Exception):
    pass


class CardError(NFCError):
    pass


class APDUError(CardError):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2

    def __str__(self):
        return "SW1={:02X} SW2={:02X}".format(self.sw1, self.sw2)

    def __repr__(self):
        return "{}: SW1={:02X} SW2={:02X}".format(
            self.__class__.__name__, self.sw1, self.sw2
        )


def nfc_tlv_parse(data):
    # pylint: disable=invalid-name
    while len(data) > 0:
        t = data[0]
        if t == 0x00:
            continue
        if t == 0xFE:
            yield t, None, None
            return
        if data[1] == 0xFF:
            l = int.from_bytes(data[2:4], "big")
            v = data[4 : 4 + l]
            if len(v) == l:
                data = data[4 + l :]
                yield t, l, v
            else:
                raise ValueError
        else:
            l = data[1]
            v = data[2 : 2 + l]
            if len(v) == l:
                data = data[2 + l :]
                yield t, l, v
            else:
                raise ValueError("NDEF was not terminated")


class BaseCard:
    # pylint: disable=unused-argument

    def __init__(self):
        self.data = {}

    def __repr__(self) -> str:
        return "<{} {}>".format(self.__class__.__name__, self.uid_hex)

    def __str__(self) -> str:
        return self.uid_hex

    @property
    def uid(self) -> bytes:
        return self.data["uid"]

    @property
    def uid_hex(self) -> str:
        return binascii.hexlify(self.uid).decode("ascii")

    def dump(self):
        for k in sorted(self.data.keys()):
            print(k, self.data[k])

    def communicatethru(self, data: bytes, response_length=64) -> bytes:
        return NotImplementedError

    def dataexchange(self, data: bytes, response_length=64) -> bytes:
        return NotImplementedError

    def apdu(self, data: bytes, response_length=64, raise_exceptions=True):
        return NotImplementedError

    @property
    def is_iso14443_3(self):
        return NotImplementedError

    @property
    def is_iso14443_4(self):
        return NotImplementedError


class SimpleCard(BaseCard):
    pass
