# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import time
import traceback

from .card import SimpleCard, CardError
from .desfire import EV1Card
from .pn532_reader import PN532Mixin

# from .piv import PivMixin


class MyCard(PN532Mixin, EV1Card):
    pass


class NFCBaseScanner:
    def __init__(self, pn532, timeout=0.05):
        self.pn532 = pn532
        self.timeout = timeout
        self.start_auth_callback = None
        self.setup()

    def setup(self):
        ic, ver, rev, support = self.pn532.firmware_version

        # Configure PN532 to communicate with MiFare cards
        self.pn532.SAM_configuration()

    def loop(self):
        raise NotImplementedError

    def poll(self):
        raise NotImplementedError


class NFCSimpleScanner(NFCBaseScanner):
    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.seen = {}

    def loop(self):
        for uid, timestamp in self.seen.items():
            if time.monotonic() - timestamp > 0.75:
                # pylint: disable=unnecessary-dict-index-lookup
                del self.seen[uid]

    def poll(self):
        try:
            card = MyCard.from_pn532(self.pn532, timeout=self.timeout)

            if card is None:
                return None

            if card.uid in self.seen:
                self.seen[card.uid] = time.monotonic()
                return None
            self.seen[card.uid] = time.monotonic()

            return card
        except RuntimeError as e:
            print("PN532 exception:", e)
            return None


class NFCFancyScanner(NFCSimpleScanner):
    def poll(self):
        try:
            card = MyCard.from_pn532(self.pn532, timeout=self.timeout)

            if card is None:
                return None

            if card.uid in self.seen:
                self.seen[card.uid] = time.monotonic()
                return None
            self.seen[card.uid] = time.monotonic()

            return card

        except RuntimeError as e:
            print("PN532 exception:", e)
            return None


class NFCDesfireScanner(NFCBaseScanner):
    def __init__(self, *args, authenticator=None, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.authenticator = authenticator
        self.seen = {}
        self.backoff_until = None

    def loop(self):
        for uid, timestamp in self.seen.items():
            if time.monotonic() - timestamp > 0.75:
                # pylint: disable=unnecessary-dict-index-lookup
                del self.seen[uid]

    def poll(self):
        if self.backoff_until:
            if time.monotonic() < self.backoff_until:
                return None
            else:
                self.backoff_until = None
        try:
            card = MyCard.from_pn532(self.pn532, timeout=self.timeout, debug=True)

            if card is None:
                if len(self.seen) == 0:
                    self.pn532.power_down()
                return None

            if card.uid in self.seen:
                self.seen[card.uid] = time.monotonic()
                return None
            self.seen[card.uid] = time.monotonic()

            if callable(self.start_auth_callback):
                # pylint: disable=not-callable
                self.start_auth_callback()

            card.dump()

            if not card.is_iso14443_4:
                return card

            print("ndef", card.nfc_type_4_read())

            # x = card.piv_get_certificate()
            # if x:
            #     print("piv-9e", len(x), x)
            # else:
            #     print("piv-9e None")

            if self.authenticator.authenticate(card):
                print("auth ok")
                self.seen[card.uid] = time.monotonic()
                self.backoff_until = time.monotonic() + 0.75
                return card
            else:
                print("auth failed")
                self.backoff_until = time.monotonic() + 0.75
                self.seen[card.uid] = time.monotonic()
                return None

        except CardError as e:
            traceback.print_exception(None, e, e.__traceback__)
            self.backoff_until = time.monotonic() + 0.75
            return None
