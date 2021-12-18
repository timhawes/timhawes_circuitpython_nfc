#
# Copyright 2021 Tim Hawes
# All Rights Reserved
#

import aesio
import desio

DESFIRE_STATUS_CODES = {
    0x00: 'Success',
    0x0C: 'No change',
    0x0E: 'Out of EEPROM',
    0x1C: 'Illegal command',
    0x1E: 'Integrity error',
    0x40: 'No such key',
    0x6E: 'Error (ISO?)',
    0x7E: 'Length error',
    0x97: 'Crypto error',
    0x9D: 'Permission denied',
    0x9E: 'Parameter error',
    0xA0: 'Application not found',
    0xAE: 'Authentication error',
    0xAF: 'Additional frame',
    0xBE: 'Boundary error',
    0xC1: 'Card integrity error',
    0xCA: 'Command aborted',
    0xCD: 'Card disabled',
    0xCE: 'Count error',
    0xDE: 'Duplicate error',
    0xEE: 'EEPROM error',
    0xF0: 'File not found',
    0xF1: 'File integrity error',
}

def desfire_crc32(data):
    poly = 0xEDB88320
    crc = 0xFFFFFFFF
    for x in data:
        crc = crc ^ x
        for bit in range(0, 8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc = crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF, (crc >> 16) & 0xFF, (crc >> 24) & 0xFF])

def iso14443a_crc16(data):
    poly = 0x8408
    crc = 0x6363
    for x in data:
        crc = crc ^ x
        for bit in range(0, 8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc = crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

def pad_desfire(data, length):
    if len(data) != 0 and len(data) % length == 0:
        return data
    new_length = len(data) + length - (len(data) % length)
    padded_data = data + b'\x80' + (b'\x00' * (length - 1))
    return padded_data[0:new_length]

def pad_zero(data, length):
    if len(data) != 0 and len(data) % length == 0:
        return data
    new_length = len(data) + length - (len(data) % length)
    padded_data = data + (b'\x00' * length)
    return padded_data[0:new_length]

def generate_aes_subkeys(session_key):
    key_length = len(session_key)
    block_length = 16
    zero_key = b'\x00' * block_length

    sk1 = bytearray(16)
    aesio.AES(session_key, aesio.MODE_CBC, IV=zero_key).encrypt_into(zero_key, sk1)

    if sk1[0] & 0b10000000 == 0b10000000:
        sk1 = ((int.from_bytes(sk1, 'big') << 1) ^ 0x87).to_bytes(block_length+1, 'big')[1:]
    else:
        sk1 = (int.from_bytes(sk1, 'big') << 1).to_bytes(block_length+1, 'big')[1:]

    if sk1[0] & 0b10000000 == 0b10000000:
        sk2 = ((int.from_bytes(sk1, 'big') << 1) ^ 0x87).to_bytes(block_length+1, 'big')[1:]
    else:
        sk2 = (int.from_bytes(sk1, 'big') << 1).to_bytes(block_length+1, 'big')[1:]
        
    return sk1, sk2

def generate_des_subkeys(session_key):
    key_length = len(session_key)
    zero_key = b'\x00' * key_length
    if key_length == 8:
        r = 0x1B
    else:
        r = 0x87

    sk1 = bytearray(key_length)
    desio.DES(session_key, desio.MODE_CBC, IV=zero_key).encrypt_into(zero_key, sk1)

    if sk1[0] & 0b10000000 == 0b10000000:
        sk1 = ((int.from_bytes(sk1, 'big') << 1) ^ r).to_bytes(len(session_key)+1, 'big')[1:]
    else:
        sk1 = (int.from_bytes(sk1, 'big') << 1).to_bytes(len(session_key)+1, 'big')[1:]

    if sk1[0] & 0b10000000 == 0b10000000:
        sk2 = ((int.from_bytes(sk1, 'big') << 1) ^ r).to_bytes(len(session_key)+1, 'big')[1:]
    else:
        sk2 = (int.from_bytes(sk1, 'big') << 1).to_bytes(len(session_key)+1, 'big')[1:]
        
    return sk1, sk2

# yes, this could also be done by XORing one byte at a time,
# but converting to integers is slightly quicker
def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("Inputs must be the same length")
    return (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).to_bytes(len(a), 'big')

def xor_block(data, key):
    key_length = len(key)

    # XOR will only be applied to the last $key_length bytes
    section1, section2 = data[0:len(data) - key_length], data[-key_length:]

    return section1 + xor_bytes(section2, key)

def cmac_helper(context, session_key, subkey1, subkey2, data):
    key_length = len(session_key)
    padded_data = pad_desfire(data, key_length)
    if data == padded_data:
        xored_data = xor_block(padded_data, subkey1)
    else:
        xored_data = xor_block(padded_data, subkey2)
    encrypted_data = bytearray(len(padded_data))
    context.encrypt_into(xored_data, encrypted_data)
    context.rekey(session_key, encrypted_data[-key_length:])
    return encrypted_data[-key_length:]

def parse_desfire_version(data):
    storage_sizes = {0x16: 2048, 0x18: 4096, 0x1A: 8192}
    output = {}
    if len(data) >= 7:
        output['hardware'] = {
            'vendor_id': data[0],
            'type': data[1],
            'sub_type': data[2],
            'major_version': data[3],
            'minor_version': data[4],
            'storage_size': storage_sizes.get(data[5]),
            'protocol_type': data[6],
        }
    if len(data) >= 14:
        output['software'] = {
            'vendor_id': data[7],
            'type': data[8],
            'sub_type': data[9],
            'major_version': data[10],
            'minor_version': data[11],
            'storage_size': storage_sizes.get(data[12]),
            'protocol_type': data[13],
        }
    if len(data) >= 28:
        output['general'] = {
            'uid': data[14:21],
            'batch': data[21:26],
            'week': int('{:02x}'.format(data[26])),
            'year': int('{:02x}'.format(data[27])),
        }
        if output['general']['uid'] == b'\x00\x00\x00\x00\x00\x00\x00':
            output['general']['uid'] = None
    return output

def an10922_cmac(k, d, padded):
    k1, k2 = generate_aes_subkeys(k)
    if padded:
        xored_data = xor_block(d, k2)
    else:
        xored_data = xor_block(d, k1)
    output = bytearray(len(xored_data))
    aesio.AES(k, aesio.MODE_CBC, IV=b'\x00'*16).encrypt_into(xored_data, output)
    return output[-16:]

def diversify_an10922_aes128(master_key, diversification_input):
    if len(master_key) != 16:
        raise ValueError('Key must be 128 bits')
    if not (1 <= len(diversification_input) <= 31):
        raise ValueError('Diversification input must be 1-31 bytes')

    if len(diversification_input) < 31:
        d = pad_desfire(b'\x01' + diversification_input, 32)
        diversified_key = an10922_cmac(master_key, d, True)
    else:
        d = b'\x01' + diversification_input
        diversified_key = an10922_cmac(master_key, d, False)

    return diversified_key

def diversify_an10922_aes192(master_key, diversification_input):
    if len(master_key) != 24:
        raise ValueError('Key must be 192 bits')
    if not (1 <= len(diversification_input) <= 31):
        raise ValueError('Diversification input must be 1-31 bytes')

    if len(diversification_input) < 31:
        d1 = pad_desfire(b'\x11' + diversification_input, 32)
        d2 = pad_desfire(b'\x12' + diversification_input, 32)
        padded = True
    else:
        d1 = b'\x11' + diversification_input
        d2 = b'\x12' + diversification_input
        padded = False

    # FIXME: each instance of cmac will generate the subkeys again
    a = an10922_cmac(master_key, d1, padded)
    b = an10922_cmac(master_key, d2, padded)
    diversified_key = a[0:8] + xor_bytes(a[8:16], b[0:8]) + b[8:16]
    return diversified_key

def diversify_an10922_aes256(master_key, diversification_input):
    if len(master_key) != 32:
        raise ValueError('Key must be 256 bits')
    if not (1 <= len(diversification_input) <= 31):
        raise ValueError('Diversification input must be 1-31 bytes')

    if len(diversification_input) < 31:
        d1 = pad_desfire(b'\x41' + diversification_input, 32)
        d2 = pad_desfire(b'\x42' + diversification_input, 32)
        padded = True
    else:
        d1 = b'\x41' + diversification_input
        d2 = b'\x42' + diversification_input
        padded = False

    # FIXME: each instance of cmac will generate the subkeys again
    a = an10922_cmac(master_key, d1, padded)
    b = an10922_cmac(master_key, d2, padded)
    diversified_key = a + b
    return diversified_key

def diversify_an10922_aes(master_key, diversification_input):
    if len(master_key) == 16:
        return diversify_an10922_aes128(master_key, diversification_input)
    elif len(master_key) == 24:
        return diversify_an10922_aes192(master_key, diversification_input)
    elif len(master_key) == 32:
        return diversify_an10922_aes256(master_key, diversification_input)
    else:
        raise NotImplementedError('AES keys may only be 128/192/256-bits')
