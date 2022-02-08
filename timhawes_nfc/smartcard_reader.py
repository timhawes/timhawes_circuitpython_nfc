# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii

from . import card
from . import fancy
from . import desfire


class SmartcardMixin:
    @classmethod
    def from_pyscard_connection(cls, connection, debug=False):
        card = cls()
        card.connection = connection
        card.debug = debug
        card.data["uid"] = card._pyscard_get_uid()
        card.data["atr"] = card._pyscard_get_atr()
        ats = card._pyscard_get_ats()
        if ats:
            card.data["ats"] = ats
        return card

    # def __init__(self, *args, **kwargs):
    #     super(__class__, self).__init__(*args, **kwargs)

    def _pyscard_get_uid(self):
        response, sw1, sw2 = self.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x04])
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response)

    def _pyscard_get_atr(self):
        return bytes(self.connection.getATR())

    def _pyscard_get_ats(self):
        response, sw1, sw2 = self.connection.transmit([0xFF, 0xCA, 0x01, 0x00, 0x04])
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes(response)

    @property
    def is_iso14443_3(self):
        if self.data["atr"][7:13] == b"\xA0\x00\x00\x03\x06\x03":
            # PC/SC RID + level 3
            return True
        else:
            return False

    @property
    def is_iso14443_4(self):
        if "ats" in self.data:
            return True
        else:
            return False

    def apdu(
        self, cla, ins, p1, p2, data=b"", response_length=None, raise_exceptions=True
    ):
        GET_RESPONSE = [0x00, 0xC0, 0x00, 0x00]
        if len(data) > 0:
            command = bytes([cla, ins, p1, p2, len(data)]) + data
        else:
            command = bytes([cla, ins, p1, p2])
        if response_length is None or response_length == 256:
            command = command + b"\x00"
        elif response_length > 256:
            raise NotImplementedError("Cannot handle response length >256 bytes")
        elif response_length > 0:
            command = command + bytes([response_length])
        # else: 0 encoded as absent field
        if self.debug:
            print("APDU-C {}".format(binascii.hexlify(bytes(command)).decode("ascii")))
        response, sw1, sw2 = self.connection.transmit(list(command))
        if self.debug:
            print(
                "APDU-R {} {:02x}{:02x}".format(
                    binascii.hexlify(bytes(response)).decode("ascii") or "-", sw1, sw2
                )
            )
        while sw1 == 0x61:
            if self.debug:
                print(
                    "APDU-C {}".format(
                        binascii.hexlify(bytes(GET_RESPONSE + [sw2]).decode("ascii"))
                    )
                )
            data, sw1, sw2 = self.connection.transmit(GET_RESPONSE + [sw2])
            if self.debug:
                print(
                    "APDU-R {} {:02x}{:02x}".format(
                        binascii.hexlify(bytes(data)).decode("ascii") or "-", sw1, sw2
                    )
                )
            response = response + data
        if sw1 not in [0x90, 0x91]:
            if raise_exceptions:
                raise card.APDUError(
                    sw1, sw2, command=bytes(command), response=bytes(response)
                )
        return bytes(response), sw1, sw2

    def dataexchange(self, data, response_length=64):
        # This is DESFire ISO 7816-4 APDU wrapping
        # It probably won't work as a general solution for other cards
        if len(data) > 1:
            apdu = [0x90, data[0], 0x00, 0x00, len(data) - 1] + list(data[1:]) + [0x00]
        else:
            apdu = [0x90, data[0], 0x00, 0x00, 0x00]
        response, sw1, sw2 = self.apdu(apdu, raise_exceptions=False)
        if sw1 in [0x90, 0x91]:
            return bytes(bytes([sw2]) + response)

    # InCommunicateThru via ACR122U/PN532
    def communicatethru(self, data, response_length=64):
        apdu = [0xFF, 0x00, 0x00, 0x00, len(data) + 2, 0xD4, 0x42] + list(data)
        response, sw1, sw2 = self.apdu(apdu)
        if (
            sw1 == 0x90
            and sw2 == 0x00
            and response[0] == 0xD5
            and response[1] == 0x43
            and response[2] == 0x00
        ):
            return response[3:]

    def mifare_read_blocks(self, block, length=16):
        if not (1 <= length <= 16):
            raise ValueError("Length must be 1-16 bytes")
        response, sw1, sw2 = self.apdu(bytes([0xFF, 0xB0, 0x00, block, 0x10]))
        return response
