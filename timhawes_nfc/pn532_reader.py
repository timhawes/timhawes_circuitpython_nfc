# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii

from .card import NFCError, CardError, APDUError


class PN532Error(NFCError):
    pass


class PN532Mixin:
    @classmethod
    def from_pn532(cls, pn532, timeout=0.1, debug=False):
        response = pn532.call_function(
            0x4A, params=[1, 0], response_length=64, timeout=timeout
        )
        # 0 = NbTg
        # 1 = 0x01 (target id 1)
        if response and response[0] == 1:
            card = cls()
            card.pn532 = pn532
            card.debug = debug
            card.data["atqa"] = (response[2] << 8) | response[3]  # sens_res
            card.data["sak"] = response[4]  # sel_res
            uid_length = response[5]
            card.data["uid"] = bytes(response[6 : 6 + uid_length])
            if len(response) > uid_length + 6:
                ats_length = response[6 + uid_length]
                card.data["ats"] = bytes(
                    response[6 + uid_length : 6 + uid_length + ats_length]
                )
            if card.is_iso14443_4:
                card.pn532_inselect()
            return card
        return None

    def pn532_call_function(
        self, cmd: int, params: bytes = b"", response_length: int = 64
    ) -> bytes:
        if response_length > 254:
            raise PN532Error("Cannot handle a response length >254")
        if self.debug:
            print(
                "PN532-C {:02X}{}".format(
                    cmd, binascii.hexlify(bytes(params)).decode("ascii")
                )
            )
        response = self.pn532.call_function(
            cmd, params=list(params), response_length=response_length + 1
        )
        if response:
            if self.debug:
                print("PN532-R {}".format(binascii.hexlify(response).decode("ascii")))
            if response[0] == 0:
                return bytes(response[1:])
            else:
                raise CardError(
                    "Card error 0x{:02X} on command 0x{:02X}".format(response[0], cmd)
                )
        else:
            if self.debug:
                print("PN532-R [timeout]")
            raise PN532Error("PN532 timeout on command 0x{:02X}".format(cmd))

    def pn532_inselect(self):
        return self.pn532_call_function(0x54, params=[1], response_length=1)

    def communicatethru(self, data, response_length=64):
        return self.pn532_call_function(
            0x42, params=list(data), response_length=response_length
        )

    def dataexchange(self, data, response_length=64):
        return self.pn532_call_function(
            0x40, params=[1] + list(data), response_length=response_length
        )

    def apdu(
        self, cla, ins, p1, p2, data=b"", response_length=None, raise_exceptions=True
    ):
        if len(data) > 255:
            raise NotImplementedError("Cannot handle command data length >255 bytes")
        elif len(data) > 0:
            command = bytes([cla, ins, p1, p2, len(data)]) + data
            # command = bytes(command) + bytes([len(data)]) + data
        else:
            command = bytes([cla, ins, p1, p2])
            # command = bytes(command)
        if response_length is None or response_length == 256:
            command = command + b"\x00"
        elif response_length > 256:
            raise NotImplementedError("Cannot handle response length >256 bytes")
        elif response_length > 0:
            command = command + bytes([response_length])
        # else: 0 encoded as absent field
        if self.debug:
            print("APDU-C {}".format(binascii.hexlify(bytes(command)).decode("ascii")))
        response = self.dataexchange(command, response_length=200)
        if response:
            output = response[0:-2]
            while response[-2] == 0x61:
                remaining_length = response[-1]
                if remaining_length == 0:
                    remaining_length = 256
                remaining_length = min(remaining_length, 250)
                response = self.dataexchange(
                    [0x00, 0xC0, 0x00, 0x00, remaining_length],
                    response_length=remaining_length + 2,
                )
                output = output + response[0:-2]
            if response[-2] not in [0x90, 0x91]:
                if raise_exceptions:
                    raise APDUError(
                        response[-2],
                        response[-1],
                        command=bytes(command),
                        response=bytes(response[:-2]),
                    )
            return output, response[-2], response[-1]
        else:
            raise PN532Error("APDU error, no response")

    # @property
    # def is_iso14443_3(self) -> bool:
    #     return not self.is_iso14443_4

    @property
    def is_iso14443_4(self) -> bool:
        return bool((self.data["sak"] & 0b00100100) == 0b00100000)

    @property
    def maybe_ntag21x(self) -> bool:
        return bool(
            len(self.data["uid"]) == 7
            and self.data["atqa"] == 0x0044
            and self.data["sak"] == 0x00
        )

    def mifare_read_blocks(self, block, length=16):
        if not (1 <= length <= 16):
            raise ValueError("Length must be 1-16 bytes")
        response = self.dataexchange([0x30, block], response_length=16)
        return response[0:length]
