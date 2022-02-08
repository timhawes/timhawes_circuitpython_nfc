# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later


class IsoMixin:
    def iso_select_df(self, aid):
        apdu = b"\x00\xA4\x04\x00" + bytes([len(aid)]) + aid
        self.apdu(apdu)
