# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later


class IsoMixin:
    def iso_select_df(self, aid):
        self.apdu(0x00, 0xA4, 0x04, 0x00, aid)
