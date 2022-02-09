# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii


class NFCError(Exception):
    pass


class CardError(NFCError):
    pass


class APDUError(CardError):
    def __init__(self, sw1, sw2, command=b"", response=b""):
        self.sw1 = sw1
        self.sw2 = sw2
        self.command = command
        self.response = response

    def __str__(self):
        return "SW1={:02X} SW2={:02X} COMMAND={} RESPONSE={}".format(
            self.sw1, self.sw2, self.command, self.response
        )

    def __repr__(self):
        return "{}: SW1={:02X} SW2={:02X} COMMAND={} RESPONSE={}".format(
            self.__class__.__name__, self.sw1, self.sw2, self.command, self.response
        )


#
# 00 - vendor
# 01 - product type
# 02 - subtype
# 03 - major product version
# 04 - minor product version
# 05 - storage size
# 06 - protocol type (03 = ISO 14443-3, 04 = ISO 14443-4, 05 = 3+4)
#
VERSIONS = {
    b"\x04\x01\x01\x01\x00\x16\x05": "MIFARE DESFire EV1 MF3ICD21",
    b"\x04\x01\x01\x01\x00\x18\x05": "MIFARE DESFire EV1 MF3ICD41",
    b"\x04\x01\x01\x01\x00\x1A\x05": "MIFARE DESFire EV1 MF3ICD81",
    b"\x04\x01\x02\x01\x00\x16\x05": "MIFARE DESFire EV1 MF3ICDH21",
    b"\x04\x01\x02\x01\x00\x18\x05": "MIFARE DESFire EV1 MF3ICDH41",
    b"\x04\x01\x02\x01\x00\x1A\x05": "MIFARE DESFire EV1 MF3ICDH81",
    b"\x04\x03\x01\x01\x00\x0b\x03": "MIFARE Ultralight EV1 MF0UL11",
    b"\x04\x03\x01\x01\x00\x0e\x03": "MIFARE Ultralight EV1 MF0UL21",
    b"\x04\x03\x02\x01\x00\x0b\x03": "MIFARE Ultralight EV1 MF0ULH11",
    b"\x04\x03\x02\x01\x00\x0e\x03": "MIFARE Ultralight EV1 MF0ULH21",
    b"\x04\x04\x02\x01\x00\x0F\x03": "NTAG213",
    b"\x04\x04\x02\x01\x00\x11\x03": "NTAG215",
    b"\x04\x04\x02\x01\x00\x13\x03": "NTAG216",
    b"\x04\x04\x02\x30\x00\x11\x05": "NTAG 424 DNA NT4H2421Gx",
    b"\x04\x04\x04\x01\x00\x0F\x03": "NTAG213F",
    b"\x04\x04\x04\x01\x00\x11\x03": "NTAG215F",
    b"\x04\x04\x04\x01\x00\x13\x03": "NTAG216F",
    b"\x04\x08\x01\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLx0",
    b"\x04\x08\x01\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLx0",
    b"\x04\x08\x02\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLHx0",
    b"\x04\x08\x02\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLHx0",
}


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
            if isinstance(self.data[k], bytes):
                print(k, binascii.hexlify(self.data[k]).decode("ascii"))
            else:
                print(k, self.data[k])
        if "ats" in self.data:
            ats = self.data["ats"]
            if len(ats) == 0:
                print("ATS is zero length")
            elif ats[0] != len(ats):
                print("ATS length is incorrect")
            elif ats[0] == 1:
                print("ATS is empty")
            else:
                print("ATS", end="")
                t0 = ats[1]
                print(f" T0={t0:02X}", end="")
                fsci = t0 & 0x0F
                ta_present = t0 & 0b00010000
                tb_present = t0 & 0b00100000
                tc_present = t0 & 0b01000000
                position = 2
                ta = None
                tb = None
                tc = None
                if ta_present:
                    ta = ats[position]
                    position = position + 1
                    print(f" TA={ta:02X}", end="")
                if tb_present:
                    tb = ats[position]
                    position = position + 1
                    print(f" TB={tb:02X}", end="")
                if tc_present:
                    tc = ats[position]
                    position = position + 1
                    print(f" TC={tc:02X}", end="")
                historical_bytes = ats[position:]
                if len(historical_bytes) > 0:
                    print(
                        " historical={}".format(
                            binascii.hexlify(historical_bytes).decode("ascii")
                        ),
                        end="",
                    )
                print()

    def communicatethru(self, data: bytes, response_length=64) -> bytes:
        return NotImplementedError

    def dataexchange(self, data: bytes, response_length=64) -> bytes:
        return NotImplementedError

    def apdu(
        self, cla, ins, p1, p2, data=b"", response_length=64, raise_exceptions=True
    ):
        return NotImplementedError

    @property
    def has_random_uid(self) -> bool:
        if len(self.uid) == 4 and self.uid[0] == 0x80:
            return True
        return False

    @property
    def is_iso14443_3(self):
        return NotImplementedError

    @property
    def is_iso14443_4(self):
        return NotImplementedError

    @property
    def historical_bytes(self):
        try:
            ats = self.data["ats"]
            t0 = ats[1]
            position = 2
            if t0 & 0b00010000:
                position = position + 1
            if t0 & 0b00100000:
                position = position + 1
            if t0 & 0b01000000:
                position = position + 1
            return ats[position:]
        except KeyError:
            pass
        except IndexError:
            pass

    def get_version(self):
        if self.is_iso14443_3:
            return self.communicatethru([0x60])
        elif self.is_iso14443_4:
            version, sw1, sw2 = self.apdu(0x90, 0x60, 0x00, 0x00)
            while sw1 == 0x91 and sw2 == 0xAF:
                version2, sw1, sw2 = self.apdu(0x90, 0xAF, 0x00, 0x00)
                version = version + version2
            return version

    @property
    def version(self):
        if "version" in self.data:
            return self.data["version"]
        try:
            self.data["version"] = self.get_version()
            return self.data["version"]
        except CardError:
            return None

    @property
    def model(self):
        if len(self.uid) > 4:
            if self.uid[0:2] == b"\x02\xE2":
                return "ST25TA02K"
        if self.version:
            if len(self.version) == 8 and self.version[0] == 0x00:
                return VERSIONS.get(self.version[1:8])
            return VERSIONS.get(self.version[0:7])
        return None


class SimpleCard(BaseCard):
    pass
