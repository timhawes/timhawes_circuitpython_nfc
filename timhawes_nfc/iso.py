#
# Copyright 2021 Tim Hawes
# All Rights Reserved
#

class IsoMixin:

    def iso_select_df(self, aid):
        apdu = b"\x00\xA4\x04\x00" + bytes([len(aid)]) + aid
        self.apdu(apdu)
