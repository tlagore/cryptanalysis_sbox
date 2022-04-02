from subpermnetwork import SPN

# 43 just lets us keep the random seed so we know expected keys
spn = SPN(4, keys=[516,516,516,516,516])

msgs = [0xABCD, 0xDEF1, 0x1234, 0x5125, 0x3151]

for msg in msgs: 
    print(f"Encrypting: {msg:x}")
    ciphertext = spn.encrypt(msg)
    decrypted = spn.decrypt(ciphertext)
    print(f"Decrypted: {decrypted:x}")
    assert msg == decrypted, f"Test fail! Expected: 0x{msg:x} but got 0x{decrypted:x}"

def tests():
    """ these tests will currently likely break """
    sub_lookup_expected = {
        0x0123: 0xe4d1,
        0x4567: 0x2fb8,
        0x89AB: 0x3a6c,
        0xCDEF: 0x5907,
        0x000F: 0xeee7,
        0x1000: 0x4eee
    }

    spn = SPN(4, [516, 516, 516, 516, 516])

    for input, expected in sub_lookup_expected.items():
        val = spn._substitute(input, spn.sub_lookup)
        assert(val == expected)

    for expected, input in sub_lookup_expected.items():
        val = spn._substitute(input, spn.decrypt_sub_lookup)
        assert(val == expected)

    # dnour should invert round
    msg = 0xABCD
    r1 = spn.round(msg, 0)
    undone = spn.dnuor(r1, 0)
    assert(undone == msg)

    msg = "Junlin, I have created our sbox encryption implementation - woohoo!"
    encrypted = spn.encrypt_decrypt_ascii(msg)
    decrypted = spn.encrypt_decrypt_ascii(encrypted, False)
    assert(decrypted == msg)

    
# encrypted = sbox.encrypt_decrypt("Junlin, I have created our sbox encryption implementation - woohoo!")
# sbox.encrypt_decrypt(encrypted, False)
# tests()
