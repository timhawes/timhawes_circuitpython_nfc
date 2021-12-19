# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

# PIV specifications: https://csrc.nist.gov/publications/detail/sp/800-73/4/final

import asn1

from .card import APDUError
from .iso import IsoMixin


PIV_AID = b"\xA0\x00\x00\x03\x08\x00\x00\x10\x00"
SELECT = b"\x00\xA4\x04\x00"
GET_DATA = b"\x00\xCB\x3F\xFF"
PIV_CHUID = b"\x5F\xC1\x02" # Card Holder Unique Identifier
CERTIFICATE_9A = b"\x5F\xC1\x05" # X.509 Certificate for PIV Authentication
CERTIFICATE_9C = b"\x5F\xC1\x0A" # X.509 Certificate for Digital Signature
CERTIFICATE_9D = b"\x5F\xC1\x0B" # X.509 Certificate for Key Management
CERTIFICATE_9E = b"\x5F\xC1\x01" # X.509 Certificate for Card Authentication


class PivMixin(IsoMixin):

    def piv_select(self):
        self.iso_select_df(PIV_AID)

    def piv_get_data(self, data_field):
        apdu = GET_DATA + bytes([len(data_field)+2, 0x5C, len(data_field)]) + data_field
        response, sw1, sw2 = self.apdu(apdu, response_length=250)
        return response

    def piv_get_certificate(self, slot=0x9E):
        if slot == 0x9A:
            data_tlv = CERTIFICATE_9A
        elif slot == 0x9C:
            data_tlv = CERTIFICATE_9C
        elif slot == 0x9D:
            data_tlv = CERTIFICATE_9D
        elif slot == 0x9E:
            data_tlv = CERTIFICATE_9E
        else:
            raise ValueError("Unknown slot 0x{:02X}".format(slot))
        try:
            self.piv_select()
            return self.piv_get_data(data_tlv)
        except APDUError as e:
            if e.sw1 == 0x6A and e.sw2 == 0x80:
                # Incorrect parameters in the command data field
                return None
            if e.sw1 == 0x6A and e.sw2 == 0x82:
                # File or application not found
                return None
            raise e

    def piv_general_authenticate(self, algo, slot, data):
        apdu = b"\x00\x87" + bytes([algo, slot, len(data)]) + bytes(data) + bytes([0x00])
        return self.apdu(apdu)

    def piv_sign(self, nonce, algo=0x14, slot=0x9E):
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

        self.iso_select_df(PIV_AID)
        challenge = [0x82, 0x00, 0x81, len(nonce)] + list(nonce)
        dynamic_auth_template = [0x7C, len(challenge)] + challenge
        response, sw1, sw2 = self.piv_general_authenticate(algo, slot, dynamic_auth_template)

        decoder = asn1.Decoder()
        decoder.start(response)
        tag = decoder.peek()
        if tag.nr == 28 and tag.typ == 32 and tag.cls == 64:
            decoder.enter()
            tag = decoder.peek()
            if tag.nr == 2 and tag.typ == 0 and tag.cls == 128:
                tag, value = decoder.read()
                decoder = asn1.Decoder()
                decoder.start(value)
                decoder.enter()
                tag1, value1 = decoder.read() # r
                tag2, value2 = decoder.read() # s
                if algo == 0x11:
                    # P-256
                    return value1.to_bytes(32, "big") + value2.to_bytes(32, "big")
                elif algo == 0x14:
                    # P-384
                    return value1.to_bytes(48, "big") + value2.to_bytes(48, "big")
