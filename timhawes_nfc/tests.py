from .desfire import DiversifiedAuthenticator, EV1Error, randbytes, desfire_model_lookup
from .desfireutil import parse_desfire_version

authenticator = DiversifiedAuthenticator(0x123456)
authenticator.add_uid_query_key(
    0x02, b"\x11\x11\x22\x22\x11\x11\x22\x22\x11\x11\x22\x22\x11\x11\x22\x22"
)
authenticator.add_master_key(
    0x01, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
)


def multi_test(card):

    print(repr(card))

    if card.has_random_uid:
        print("uses random UID")

    card.dump()

    print("VERSION:", card.version)
    print("MODEL:", card.model)

    if card.is_iso14443_3:

        print("ISO 14443-3")

        ntag_version = card.ntag_version
        if ntag_version:
            print("NTAG version:", card.ntag_version)
            print("NTAG model:", card.ntag_model)
            # print("NTAG data:", card.ntag_data)
            ndef_data = card.ntag_ndef
            print("NTAG ndef:", ndef_data)
            # for m in ndef_data:
            #     message = ndef.NdefMessage(m)
            #     for record in message.records:
            #         print("  record", record.id, record.type[0], record.payload)
            print("NTAG signature:", card.ntag_signature)
            print("NTAG counter:", card.ntag_counter)
            # print("NTAG PWD AUTH:", card.pwd_auth(b"1234"))

    if card.is_iso14443_4:

        print("ISO 14443-4")
        print("historical bytes:", card.historical_bytes)

        # print("NDEF:", card.nfc_type_4_read())

        try:
            ev1_version = card.ev1_get_version()
            print("EV1 version:", ev1_version)
            print("EV1 model:", desfire_model_lookup(ev1_version))
            print("EV1 parsed:", parse_desfire_version(ev1_version))
        except EV1Error:
            ev1_version = None
        # ev1_version = True

        # print("ndef", card.nfc_type_4_read())
        # print("piv-9e", card.piv_get_certificate())
        # print("chuid", card.piv_get_data(PIV_CHUID))

        # nonce = randbytes(64)
        # nonce_hash = SHA384.new(nonce)
        # try:
        #     sig = card.piv_sign(nonce_hash.digest())
        #     if verify(nonce, sig, "/Users/tim/tim-9e.crt"):
        #         print("piv sig ok")
        # except CardError:
        #     pass

        if ev1_version:
            if card.ev1_authenticate_iso(0x00, b"\x00\x00\x00\x00\x00\x00\x00\x00"):
                print("Authenticated with default DES master key")
            elif card.ev1_authenticate_iso(
                0x80,
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ):
                print("Authenticated with default AES master key")
            else:
                result = authenticator.authenticate(card)
                if result:
                    print("Authenticated with authenticator helper")
                else:
                    print("Not authenticated")

            # card.get_version()
