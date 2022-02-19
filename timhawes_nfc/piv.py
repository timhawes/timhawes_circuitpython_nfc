# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

# PIV specifications: https://csrc.nist.gov/publications/detail/sp/800-73/4/final

from .card import APDUError
from .iso import IsoMixin


PIV_AID = b"\xA0\x00\x00\x03\x08\x00\x00\x10\x00"
GET_DATA = b"\x00\xCB\x3F\xFF"
PIV_CHUID = b"\x5F\xC1\x02"  # Card Holder Unique Identifier
CERTIFICATE_9A = b"\x5F\xC1\x05"  # X.509 Certificate for PIV Authentication
CERTIFICATE_9C = b"\x5F\xC1\x0A"  # X.509 Certificate for Digital Signature
CERTIFICATE_9D = b"\x5F\xC1\x0B"  # X.509 Certificate for Key Management
CERTIFICATE_9E = b"\x5F\xC1\x01"  # X.509 Certificate for Card Authentication


def unwrap_tlv(data):
    tag = data[0]
    length = data[1]
    if length < 128:
        return data[2:2 + length]
    elif length == 128:
        raise ValueError
    elif length == 255:
        raise ValueError
    else:
        length_length = length & 127
        length = int.from_bytes(data[2:2 + length_length], "big")
        return data[2 + length_length:2 + length_length + length]

class PivMixin(IsoMixin):
    def piv_select(self):
        self.iso_select_df(PIV_AID)

    def piv_get_data(self, data_field):
        response, sw1, sw2 = self.apdu(0x00, 0xCB, 0x3F, 0xFF, data_field)
        return response

    def piv_get_certificate(self, slot=0x9E):
        """Retrieve a certificate from the card and return in DER format."""
        if slot == 0x9A:
            data_object_identifier = CERTIFICATE_9A
        elif slot == 0x9C:
            data_object_identifier = CERTIFICATE_9C
        elif slot == 0x9D:
            data_object_identifier = CERTIFICATE_9D
        elif slot == 0x9E:
            data_object_identifier = CERTIFICATE_9E
        else:
            raise ValueError("Unknown slot 0x{:02X}".format(slot))
        try:
            return unwrap_tlv(unwrap_tlv(self.piv_get_data(b"\x5C\x03" + data_object_identifier)))
        except APDUError as e:
            if e.sw1 == 0x6A and e.sw2 == 0x80:
                # Incorrect parameters in the command data field
                return None
            if e.sw1 == 0x6A and e.sw2 == 0x82:
                # File or application not found
                return None
            raise e

    def piv_general_authenticate(self, algo, slot, data):
        response, sw1, sw2 = self.apdu(0x00, 0x87, algo, slot, data)
        return response

    def piv_sign(self, nonce, algo=0x14, slot=0x9E):
        """Sign a message on the card and return the signature in DER format."""
        if algo not in [0x11, 0x14]:
            # 0x07 RSA 2048
            # 0x11 ECC P-256
            # 0x14 ECC P-384
            raise NotImplementedError
        if algo == 0x11:
            if len(nonce) > 32:
                raise ValueError("nonce must be <= 32 bytes for P-256")
        if algo == 0x14:
            if len(nonce) > 48:
                raise ValueError("nonce must be <= 48 bytes for P-384")

        challenge = [0x82, 0x00, 0x81, len(nonce)] + list(nonce)
        dynamic_auth_template = [0x7C, len(challenge)] + challenge
        response = self.piv_general_authenticate(
            algo, slot, bytes(dynamic_auth_template)
        )
        return unwrap_tlv(unwrap_tlv(response))
