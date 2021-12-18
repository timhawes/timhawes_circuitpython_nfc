#
# Copyright 2021 Tim Hawes
# All Rights Reserved
#

import aesio
from binascii import unhexlify

from .desfireutil import iso14443a_crc16, desfire_crc32, generate_aes_subkeys, xor_bytes, xor_block, cmac_helper, pad_desfire, pad_zero, an10922_cmac, diversify_an10922_aes

def run_tests():
    # these test cases are not from a verified source
    assert iso14443a_crc16(unhexlify('00102030405060708090A0B0B0A09080')) == unhexlify('528c')
    assert iso14443a_crc16(unhexlify('12345678')) == unhexlify('f031')

    # these test cases are from RevK's DESfire document
    assert desfire_crc32(unhexlify('00102030405060708090A0B0B0A09080')) == unhexlify('bfe37919')
    assert desfire_crc32(unhexlify('c4800000000000000000000000000000000001')) == unhexlify('1dd9eac2')

    assert generate_aes_subkeys(unhexlify('2B7E151628AED2A6ABF7158809CF4F3C')) == (unhexlify('FBEED618357133667C85E08F7236A8DE'), unhexlify('F7DDAC306AE266CCF90BC11EE46D513B'))

    assert xor_bytes(unhexlify('353f11'), unhexlify('9fc266')) == unhexlify('aafd77')
    assert xor_bytes(unhexlify('11')*64, unhexlify('22')*64) == unhexlify('33')*64

    assert xor_block(unhexlify('80000000000000000000000000000000'), unhexlify('F7DDAC306AE266CCF90BC11EE46D513B')) == unhexlify('77ddac306ae266ccf90bc11ee46d513b')
    assert xor_block(unhexlify('6BC1BEE22E409F96E93D7E117393172A'), unhexlify('FBEED618357133667C85E08F7236A8DE')) == unhexlify('902F68FA1B31ACF095B89E9E01A5BFF4')
    assert xor_block(unhexlify('6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE4118000000000000000'), unhexlify('F7DDAC306AE266CCF90BC11EE46D513B')) == unhexlify('6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51C715B076C9BE82DD790BC11EE46D513B')

    cmac_test_session_key = unhexlify('2B7E151628AED2A6ABF7158809CF4F3C')
    cmac_test_subkey1, cmac_test_subkey2 = generate_aes_subkeys(cmac_test_session_key)

    cmac_test_context = aesio.AES(cmac_test_session_key, aesio.MODE_CBC, IV=unhexlify('00000000000000000000000000000000'))
    cmac_test_data = unhexlify('')
    cmac_test_result = unhexlify('BB1D6929E95937287FA37D129B756746')
    assert cmac_helper(cmac_test_context, cmac_test_session_key, cmac_test_subkey1, cmac_test_subkey2, cmac_test_data) == cmac_test_result

    cmac_test_context = aesio.AES(cmac_test_session_key, aesio.MODE_CBC, IV=unhexlify('00000000000000000000000000000000'))
    cmac_test_data = unhexlify('6BC1BEE22E409F96E93D7E117393172A')
    cmac_test_result = unhexlify('070A16B46B4D4144F79BDD9DD04A287C')
    assert cmac_helper(cmac_test_context, cmac_test_session_key, cmac_test_subkey1, cmac_test_subkey2, cmac_test_data) == cmac_test_result

    cmac_test_context = aesio.AES(cmac_test_session_key, aesio.MODE_CBC, IV=unhexlify('00000000000000000000000000000000'))
    cmac_test_data = unhexlify('6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411')
    cmac_test_result = unhexlify('DFA66747DE9AE63030CA32611497C827')
    assert cmac_helper(cmac_test_context, cmac_test_session_key, cmac_test_subkey1, cmac_test_subkey2, cmac_test_data) == cmac_test_result

    assert pad_desfire(unhexlify(''),                                   16) == unhexlify('80000000000000000000000000000000')
    assert pad_desfire(unhexlify('000102030405060708090A0B0C0D0E0F'),   16) == unhexlify('000102030405060708090A0B0C0D0E0F')
    assert pad_desfire(unhexlify('000102030405060708090A0B0C0D0E'),     16) == unhexlify('000102030405060708090A0B0C0D0E80')
    assert pad_desfire(unhexlify('000102030405060708090A0B0C0D'),       16) == unhexlify('000102030405060708090A0B0C0D8000')
    assert pad_desfire(unhexlify('000102030405060708090A0B0C0D0E0F10'), 16) == unhexlify('000102030405060708090A0B0C0D0E0F10800000000000000000000000000000')
    assert pad_zero(   unhexlify(''),                                   16) == unhexlify('00000000000000000000000000000000')
    assert pad_zero(   unhexlify('000102030405060708090A0B0C0D0E0F'),   16) == unhexlify('000102030405060708090A0B0C0D0E0F')
    assert pad_zero(   unhexlify('000102030405060708090A0B0C0D0E'),     16) == unhexlify('000102030405060708090A0B0C0D0E00')
    assert pad_zero(   unhexlify('000102030405060708090A0B0C0D'),       16) == unhexlify('000102030405060708090A0B0C0D0000')
    assert pad_zero(   unhexlify('000102030405060708090A0B0C0D0E0F10'), 16) == unhexlify('000102030405060708090A0B0C0D0E0F10000000000000000000000000000000')

    # Test cases from AN10922
    assert generate_aes_subkeys(unhexlify('00112233445566778899AABBCCDDEEFF')) == (unhexlify('FBC9F75C9413C041DFEE452D3F0706D1'), unhexlify('F793EEB928278083BFDC8A5A7E0E0D25'))
    assert generate_aes_subkeys(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708')) == (unhexlify('A5B6B5FCF6C9DFF563D25DD53078BEE6'), unhexlify('4B6D6BF9ED93BFEAC7A4BBAA60F17D4B'))
    assert generate_aes_subkeys(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F00')) == (unhexlify('0FFFD837DBED19CDA7A375D0A25F3026'), unhexlify('1FFFB06FB7DA339B4F46EBA144BE604C'))
    assert an10922_cmac(unhexlify('00112233445566778899AABBCCDDEEFF'), unhexlify('0104782E21801D803042F54E5850204162758000000000000000000000000000'), True) == unhexlify('A8DD63A3B89D54B37CA802473FDA9175')
    assert an10922_cmac(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708'), unhexlify('1104782E21801D803042F54E5850204162758000000000000000000000000000'), True) == unhexlify('CE39C8E1CD82D9A7869FE6A2EF75725D')
    assert an10922_cmac(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F00'), unhexlify('4104782E21801D803042F54E5850204162758000000000000000000000000000'), True) == unhexlify('4FC6EEC820B4C54314990B8611662DB6')
    assert diversify_an10922_aes(unhexlify('00112233445566778899AABBCCDDEEFF'), unhexlify('04782E21801D803042F54E585020416275')) == unhexlify('A8DD63A3B89D54B37CA802473FDA9175')
    assert diversify_an10922_aes(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708'), unhexlify('04782E21801D803042F54E585020416275')) == unhexlify('CE39C8E1CD82D9A7BEDBE9D74AF59B23176755EE7586E12C')
    assert diversify_an10922_aes(unhexlify('00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F00'), unhexlify('04782E21801D803042F54E585020416275')) == unhexlify('4FC6EEC820B4C54314990B8611662DB695E7880982C0001E6067488346100AED')

    # Test cases from AN10957
    assert diversify_an10922_aes(unhexlify('F3F9377698707B688EAF84ABE39E3791'), unhexlify('04DEADBEEFFEED')) == unhexlify('0BB408BAFF98B6EE9F2E1585777F6A51')

    print("ok")

if __name__ == '__main__':
    run_tests()
