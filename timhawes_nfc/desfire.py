# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: GPL-3.0-or-later

import aesio
import binascii
import random

import desio

from .card import CardError
from .fancy import FancyCard

from .desfireutil import (
    cmac_helper,
    desfire_crc32,
    DESFIRE_STATUS_CODES,
    diversify_an10922_aes,
    generate_aes_subkeys,
    generate_des_subkeys,
    pad_zero,
    xor_bytes,
)

#
# 00 - vendor ID (04 is NXP)
# 01 - product type (01 assumed to EV1)
# 02 - subtype (01 assumed to be 17pF, 02 assumed to be 70pF)
# 03 - major product version (NXP 01 = EV1)
# 04 - minor product version
# 05 - storage size (16 = 2k, 18 = 4k)
# 06 - protocol type (03 = ISO 14443-3, 04 = ISO 14443-4, 05 = 3+4)
#
NXP_VERSION_DATA = {
    b"\x04\x01\x01\x01\x00\x16\x05": "MIFARE DESFire EV1 MF3ICD21",
    b"\x04\x01\x01\x01\x00\x18\x05": "MIFARE DESFire EV1 MF3ICD41",
    b"\x04\x01\x01\x01\x00\x1A\x05": "MIFARE DESFire EV1 MF3ICD81",
    b"\x04\x01\x02\x01\x00\x16\x05": "MIFARE DESFire EV1 MF3ICDH21",
    b"\x04\x01\x02\x01\x00\x18\x05": "MIFARE DESFire EV1 MF3ICDH41",
    b"\x04\x01\x02\x01\x00\x1A\x05": "MIFARE DESFire EV1 MF3ICDH81",
    b"\x04\x08\x01\x30\x00\x13\x05": "MIFARE DESFire Light MF2DL10",
    b"\x04\x08\x01\x30\x00\x13\x05": "MIFARE DESFire Light MF2DL10",
    b"\x04\x08\x02\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLH10",
    b"\x04\x08\x02\x30\x00\x13\x05": "MIFARE DESFire Light MF2DLH10",
}


def desfire_model_lookup(version):
    if version:
        return NXP_VERSION_DATA.get(version[0:7])
    return None


class EV1Error(CardError):
    pass


def randbytes(n):
    """Generate n random bytes."""
    return bytes([random.randint(0, 255) for i in range(0, n)])


class DiversifiedAuthenticator:
    def __init__(self, aid=0x000000):
        self.aid = aid
        self.uid_query_keys = []
        self.master_keys = []
        self.whitelist = None

    def add_uid_query_key(self, key_id, key_data):
        self.uid_query_keys.append((key_id, key_data))

    def add_master_key(self, key_id, key_data):
        self.master_keys.append((key_id, key_data))

    def set_whitelist(self, uids):
        self.whitelist = uids

    def authenticate(self, card, diversification=None):
        if not card.ev1_select_application(self.aid):
            print("application not found")
            return False

        if card.uid[0] == 0x80:
            uid = None
            for key_id, key_data in self.uid_query_keys:
                print("trying key {} for uid".format(key_id))
                if card.ev1_authenticate_aes(key_id, key_data):
                    uid = card.real_uid
                    if uid:
                        break
            if uid is None or uid[0] == 0x80:
                print("unable to fetch real uid")
                return False
            else:
                print("real uid is {}".format(binascii.hexlify(uid)))
        else:
            uid = card.uid

        diversification_input = uid + self.aid.to_bytes(3, "big")

        for key_id, key_data in self.master_keys:
            # print("trying derived key id {}".format(key_id))
            card_key = diversify_an10922_aes(key_data, diversification_input)
            if card.ev1_authenticate_aes(key_id, card_key):
                # print("auth successful using key id {}, uid={}".format(key_id, binascii.hexlify(uid)))
                if self.whitelist:
                    if uid in self.whitelist:
                        # print("uid in whitelist, ok")
                        return True
                    else:
                        print("uid not in whitelist, fail")
                        return False
                else:
                    # print("no whitelist, ok")
                    return True

        print("auth failed")
        return False


class EV1Card(FancyCard):
    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.reset_authentication()
        self.selected_application = None

    def reset_authentication(self):
        self.context = None
        self.session_key = None
        self.subkey1 = None
        self.subkey2 = None
        self.authenticated = False
        self.authenticated_key_id = None
        self.authenticated_key_data = None

    @property
    def real_uid(self):
        if "real_uid" in self.data:
            return self.data["real_uid"]
        if self.uid[0] == 0x80:
            self.data["real_uid"] = self.get_card_uid()
            return self.data["real_uid"]
        else:
            return self.uid

    @property
    def real_uid_hex(self):
        return binascii.hexlify(self.real_uid).decode("ascii")

    @property
    def ev1_authenticated(self):
        if self.authenticated:
            return self.selected_application, self.authenticated_key_id

    def cmac(self, data):
        return cmac_helper(
            self.context, self.session_key, self.subkey1, self.subkey2, data
        )

    def ev1_raw_command(self, cmd, data=b""):
        response, sw1, sw2 = self.apdu(0x90, cmd, 0x00, 0x00, data)
        if sw1 == 0x91:
            return sw2, response
        else:
            raise EV1Error("No response to command 0x{:02X}".format(cmd))

    # def ev1_raw_command_old(self, cmd, data=b"", debug=False):
    #     if debug:
    #         print("--> {}".format(binascii.hexlify(bytes([cmd]) + data).decode()))
    #     packet = self.dataexchange(bytes([cmd]) + data)
    #     if packet:
    #         if debug:
    #             print("<-- {}".format(binascii.hexlify(packet).decode()))
    #         status = packet[0]
    #         response = packet[1:]
    #         return status, response
    #     else:
    #         if debug:
    #             print("<-- None")
    #         #raise CardError("Bad response from card")
    #         return None, None

    def ev1_command(
        self,
        cmd,
        data=b"",
        send_cmac=False,
        rx_cmac=False,
        send_encrypted=None,
        rx_decrypt=False,
        send_crc=False,
        debug=True,
    ):
        if debug:
            print(
                "EV1 send {:02X}{}".format(cmd, binascii.hexlify(data).decode("ascii"))
            )

        if send_crc:
            data += desfire_crc32(bytes([cmd]) + data)
        if self.authenticated:
            if send_encrypted is None:
                # don't calculate or add cmac if we're going to encrypt
                cmac_bytes = self.cmac(bytes([cmd]) + data)
                if debug:
                    print(
                        "EV1 cmac: {} -> {}".format(
                            binascii.hexlify(bytes([cmd]) + data),
                            binascii.hexlify(cmac_bytes),
                        )
                    )
                if send_cmac:
                    data += cmac_bytes[0:8]
            if send_encrypted is not None:
                plaintext = pad_zero(data[send_encrypted:], self.key_length)
                if debug:
                    print(
                        "padding to {} bytes: {} -> {}".format(
                            self.key_length,
                            binascii.hexlify(data[send_encrypted:]),
                            binascii.hexlify(plaintext),
                        )
                    )
                # if self.auth_type == 'aes':
                #    print("sending with AES encryption")
                ciphertext = bytearray(len(plaintext))
                self.context.encrypt_into(plaintext, ciphertext)
                ciphertext = bytes(ciphertext)
                # else:
                #    print("sending with DES encryption")
                #    ciphertext = self.context.encrypt(plaintext)
                if debug:
                    print(
                        "EV1 encrypted packet will be: cmd={:02x} plain={} crypted={}".format(
                            cmd,
                            binascii.hexlify(data[0:send_encrypted]),
                            binascii.hexlify(ciphertext),
                        )
                    )
                data = data[0:send_encrypted] + ciphertext

        status, response = self.ev1_raw_command(cmd, data)

        if status not in [0x00, 0x0C, 0xAF, 0xF0]:
            self.reset_authentication()
            print(repr(status))
            print(
                "EV1 status {:02X}={}".format(
                    status, DESFIRE_STATUS_CODES.get(status, "")
                )
            )

        while status == 0xAF:
            status, response_af = self.ev1_raw_command(0xAF)
            response += response_af

        if self.authenticated:
            if rx_decrypt:
                decrypted = bytearray(len(response))
                # if self.auth_type == 'aes':
                self.context.decrypt_into(response, decrypted)
                # else:
                #    decrypted = self.context.decrypt(response)
                response = bytes(decrypted)
            else:
                if len(response) < 8:
                    print("EV1 not enough data to contain a CMAC")
                else:
                    data_chunk = response[0 : len(response) - 8] + bytes([status])
                    cmac_chunk = response[-8:]
                    if debug:
                        print(
                            "EV1 cmac split: {} {}".format(
                                binascii.hexlify(data_chunk),
                                binascii.hexlify(cmac_chunk),
                            )
                        )
                    calculated_cmac = self.cmac(data_chunk)
                    if debug:
                        print(
                            "EV1 cmac calc: input={} output={} first-8={}".format(
                                binascii.hexlify(data_chunk),
                                binascii.hexlify(calculated_cmac),
                                binascii.hexlify(calculated_cmac[0:8]),
                            )
                        )
                    if cmac_chunk != calculated_cmac[0:8]:
                        raise CardError("CMAC doesn't match")
                    response = response[0 : len(response) - 8]

        if debug:
            print(
                "EV1 recv {:02X}{}".format(
                    status, binascii.hexlify(response).decode("ascii")
                )
            )
        return status, response

    def ev1_authenticate_aes(self, key_id, key_data, debug=False):
        self.reset_authentication()

        key_length = len(key_data)

        cmd_status, response = self.ev1_raw_command(0xAA, bytes([key_id]))
        if cmd_status != 0xAF:
            print("authentication failed, card returned 0x{:02x}".format(cmd_status))
            return False

        b_crypt = bytes(response)
        if debug:
            print("their b (crypted): {}".format(binascii.hexlify(b_crypt)))

        b = bytearray(len(b_crypt))
        aesio.AES(
            bytes(key_data),
            mode=aesio.MODE_CBC,
            IV=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ).decrypt_into(b_crypt, b)
        if debug:
            print("their b (decrypted): {}".format(binascii.hexlify(b)))

        b_rotated = b[1:] + b[0:1]
        a = randbytes(16)
        a_rotated = a[1:] + a[0:1]
        my_reply = bytearray(len(b_crypt) * 2)
        aesio.AES(bytes(key_data), mode=aesio.MODE_CBC, IV=b_crypt).encrypt_into(
            a + b_rotated, my_reply
        )

        # send reply
        cmd_status, response = self.ev1_raw_command(0xAF, my_reply)
        if cmd_status != 0x00:
            print("authentication failed, card returned 0x{:02x}".format(cmd_status))
            return False

        # verify
        a_crypt_by_card = response
        a_rotated_decrypted = bytearray(len(a_crypt_by_card))
        ctx = aesio.AES(bytes(key_data), mode=aesio.MODE_CBC, IV=my_reply[-key_length:])
        ctx.decrypt_into(a_crypt_by_card, a_rotated_decrypted)
        if a_rotated == a_rotated_decrypted:
            session_key = a[0:4] + b[0:4] + a[12:16] + b[12:16]
            self.session_key = session_key
            self.subkey1, self.subkey2 = generate_aes_subkeys(session_key)
            self.context = aesio.AES(
                session_key,
                mode=aesio.MODE_CBC,
                IV=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
            self.authenticated = True
            self.auth_type = "aes"
            self.key_length = key_length
            self.authenticated_key_id = key_id & 0x0F
            self.authenticated_key_data = key_data
            print("authentication successful")
            return True
        else:
            print("authentication failed, card response doesn't verify key")
            return False

    def ev1_authenticate_iso(self, key_id, key_data, debug=False):
        self.reset_authentication()

        key_length = len(key_data)

        cmd_status, response = self.ev1_raw_command(0x1A, bytes([key_id]))
        if cmd_status != 0xAF:
            print("authentication failed, card returned 0x{:02x}".format(cmd_status))
            return False

        b_crypt = bytes(response)
        if debug:
            print("their b (crypted): {}".format(binascii.hexlify(b_crypt)))

        b = bytearray(len(b_crypt))
        desio.DES(
            bytes(key_data),
            mode=desio.MODE_CBC,
            IV=b"\x00" * key_length,
        ).decrypt_into(b_crypt, b)
        if debug:
            print("their b (decrypted): {}".format(binascii.hexlify(b)))

        b_rotated = b[1:] + b[0:1]
        a = randbytes(key_length)
        a_rotated = a[1:] + a[0:1]
        my_reply = bytearray(len(b_crypt) * 2)
        desio.DES(bytes(key_data), mode=desio.MODE_CBC, IV=b_crypt).encrypt_into(
            a + b_rotated, my_reply
        )

        # send reply
        cmd_status, response = self.ev1_raw_command(0xAF, my_reply)
        if cmd_status != 0x00:
            print("authentication failed, card returned 0x{:02x}".format(cmd_status))
            return False

        # verify
        a_crypt_by_card = response
        a_rotated_decrypted = bytearray(len(a_crypt_by_card))
        ctx = desio.DES(key_data, desio.MODE_CBC, IV=my_reply[-key_length:])
        ctx.decrypt_into(a_crypt_by_card, a_rotated_decrypted)
        if a_rotated == a_rotated_decrypted:
            session_key = a[0:4] + b[0:4]
            self.session_key = session_key
            self.subkey1, self.subkey2 = generate_des_subkeys(session_key)
            self.context = desio.DES(
                session_key, desio.MODE_CBC, IV=b"\x00" * key_length
            )
            self.authenticated = True
            self.auth_type = "des"
            self.key_length = key_length
            self.authenticated_key_id = key_id & 0x0F
            self.authenticated_key_data = key_data
            print("authentication successful")
            return True
        else:
            print("authentication failed, card response doesn't verify key")
            return False

    def get_card_uid(self):
        status, response = self.ev1_command(0x51, rx_decrypt=True)
        print("get_card_uid 0x51 -> {} {}".format(status, binascii.hexlify(response)))
        if status == 0:
            uid = response[0:7]
            crc32 = response[7:11]
            if desfire_crc32(uid + bytes([status])) == crc32:
                print("get_card_uid -> {}".format(binascii.hexlify(uid)))
                return uid
            else:
                print("get_card_uid -> bad crc")

    def ev1_get_version(self):
        version = {}
        status, response = self.ev1_command(0x60, rx_cmac=True)
        if status == 0x00:
            print("get_version -> {}".format(binascii.hexlify(response)))
        return response

    def set_default_key(self, key_data=b"", key_version=0x00):
        key_data = pad_zero(key_data, 24)
        status, response = self.ev1_command(
            0x5C,
            b"\x01" + key_data + bytes([key_version]),
            send_encrypted=1,
            send_crc=True,
        )
        if status == 0x00:
            return True

    def ev1_get_application_ids(self):
        status, response = self.ev1_command(0x6A, rx_cmac=True, debug=True)
        print(
            "get_application_ids -> 0x{:02X} {}".format(
                status, binascii.hexlify(response)
            )
        )
        if status == 0x00:
            return [
                int.from_bytes(response[i : i + 3], "big")
                for i in range(0, len(response), 3)
            ]

    def get_key_settings(self):
        status, response = self.ev1_command(0x45)
        if status == 0x00:
            data = {"master_key_can_be_changed": False}
            number_of_keys = response[1] & 0x0F
            if response[1] & 0x40 == 0x40:
                use_3k3des = True
            else:
                use_3k3des = False
            if response[1] & 0x80 == 0x80:
                use_aes = True
            else:
                use_aes = False
            return list(response)  # settings, number_of_keys

    def get_df_names(self):
        status, response = self.ev1_command(0x6D)
        print("get_df_names -> {}".format(binascii.hexlify(response)))
        # if status == 0x00:
        #    return [bytes(response[i:i+3]) for i in range(0, len(response), 3)]

    def get_file_ids(self):
        status, response = self.ev1_command(0x6F)
        # print("get_file_ids -> {}".format(binascii.hexlify(response)))
        if status == 0x00:
            return list(response)
        elif status == 0xF0:
            return []

    def get_iso_file_ids(self):
        status, response = self.ev1_command(0x61)
        if status == 0x00:
            return [
                int.from_bytes(bytes(response[i : i + 2]), "big")
                for i in range(0, len(response), 2)
            ]
        elif status == 0xF0:
            return []

    def get_file_settings(self, file_id):
        status, response = self.ev1_command(0xF5, bytes([file_id]))
        if status == 0x00:
            if response[0] == 0x00:
                data = [
                    response[0],  # Standard file
                    response[1],  # comms settings
                    int.from_bytes(response[2:4], "big"),  # access rights
                    int.from_bytes(response[4:7], "big"),  # file size
                ]
            elif response[0] == 0x01:
                data = [
                    response[0],  # Backup file
                    response[1],  # comms settings
                    int.from_bytes(response[2:4], "big"),  # access rights
                    int.from_bytes(response[4:7], "big"),  # file size
                ]
            elif response[0] == 0x02:
                data = [
                    response[0],  # Value file
                    response[1],  # comms settings
                    int.from_bytes(response[2:4], "big"),  # access rights
                    int.from_bytes(response[4:8], "big"),  # min
                    int.from_bytes(response[8:12], "big"),  # max
                    int.from_bytes(response[12:16], "big"),  # limited credit
                    int.from_bytes(response[16], "big"),  # limited credit
                ]
            elif response[0] == 0x03:
                data = [
                    response[0],  # Linear record file
                    response[1],  # comms settings
                    int.from_bytes(response[2:4], "big"),  # access rights
                    int.from_bytes(response[4:7], "big"),  # record size
                    int.from_bytes(response[7:10], "big"),  # max records
                    int.from_bytes(response[10:13], "big"),  # records existing
                ]
            elif response[0] == 0x04:
                data = [
                    response[0],  # Cyclic record file
                    response[1],  # comms settings
                    int.from_bytes(response[2:4], "big"),  # access rights
                    int.from_bytes(response[4:7], "big"),  # record size
                    int.from_bytes(response[7:10], "big"),  # max records
                    int.from_bytes(response[10:13], "big"),  # records existing
                ]
            return data

    def read_file_data(self, file_id, offset=0, length=0):
        status, response = self.ev1_command(
            0xBD,
            bytes([file_id]) + offset.to_bytes(3, "big") + length.to_bytes(3, "big"),
            rx_cmac=True,
            rx_decrypt=True,
            debug=True,
        )
        return response

    def create_application(
        self,
        aid,
        key_settings=0x09,
        app_settings=0x01,
        want_iso_application=False,
        want_iso_file_identifiers=False,
        iso_file_id=None,
        iso_file_name=None,
    ):
        if want_iso_file_identifiers:
            app_settings |= 0x20
        status, response = self.ev1_command(
            0xCA,
            aid.to_bytes(3, "big") + bytes([key_settings, app_settings]),
            send_cmac=False,
            rx_cmac=True,
            debug=True,
        )
        return status

    def delete_application(self, aid):
        status, response = self.ev1_command(0xDA, aid.to_bytes(3, "big"), rx_cmac=True)
        if status == 0x00:
            if aid == self.selected_application:
                print("deleted selected application, resetting authentication state")
                self.selected_application = None
                self.reset_authentication()

    def ev1_select_application(self, aid):
        status, response = self.ev1_command(0x5A, aid.to_bytes(3, "big"))
        if status == 0x00:
            self.reset_authentication()
            self.selected_application = aid
            return True

    def change_key(self, key_id, key_data, key_version=1):
        if not self.authenticated:
            raise CardError("change_key requires authentication")
        if key_id & 0x80 == 0x80:
            is_aes_key = True
            key_id = key_id & 0x0F
        else:
            is_aes_key = False
        # crc_payload = bytes([0xC4, key_id]) + key_data + bytes([key_version])
        # crc_payload = bytes([0xC4, key_id]) + key_data
        # crc32 = desfire_crc32(crc_payload)
        # print("desfire_crc32: {} -> {}".format(binascii.hexlify(crc_payload), binascii.hexlify(crc32)))
        if key_id == self.authenticated_key_id:
            # changing the current key, use short format command
            # (key id + key data + key version + crc)
            print("- changing current key")
            if is_aes_key:
                if self.selected_application is None:
                    print("- is card aes key")
                    data = bytes([key_id | 0x80]) + key_data + bytes([key_version])
                else:
                    print("- is application aes key")
                    data = bytes([key_id]) + key_data + bytes([key_version])
            else:
                print("- is des key")
                data = bytes([key_id]) + key_data
            status, response = self.ev1_command(
                0xC4, data, rx_cmac=True, send_encrypted=1, send_crc=True
            )
            if status == 0x00:
                self.reset_authentication()
            print("change key 0xC4 -> {} {}".format(status, response))
        else:
            # changing a different key, use long format command
            print("- changing different key")
            if is_aes_key:
                if self.selected_application is None:
                    print("- is card aes key")
                    data = (
                        bytes([key_id | 0x80])
                        + (xor_bytes(key_data, self.authenticated_key_data))
                        + bytes([key_version])
                    )
                else:
                    print("- is application aes key")
                    data = (
                        bytes([key_id])
                        + (xor_bytes(key_data, self.authenticated_key_data))
                        + bytes([key_version])
                    )
            else:
                print("- is des key")
                data = bytes([key_id]) + (
                    xor_bytes(key_data, self.authenticated_key_data)
                )
            data += desfire_crc32(b"\xC4" + data)
            data += desfire_crc32(key_data)
            status, response = self.ev1_command(
                0xC4, data, rx_cmac=True, send_encrypted=1, send_crc=False
            )
            print("change key 0xC4 -> {} {}".format(status, response))

    def format_ndef(self):
        self.create_application(
            b"\x00\x00\x01",
            0x0F,
            0x21,
            want_iso_application=True,
            want_iso_file_identifiers=False,
            iso_file_id=0xE110,
            iso_file_name=b"\xD2\x76\x00\x00\x85\x01\x01",
        )
        self.ev1_select_application(b"\x00\x00\x01")

    def format_picc(self):
        status, response = self.ev1_command(0xFC)
