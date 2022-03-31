from subpermnetwork import SPN


# 43 just lets us keep the random seed so we know expected keys
spn = SPN(4, keys=[516,516,516,516,516])

msgs = [0xABCD, 0xDEF1, 0x1234, 0x5125, 0x3151]

for msg in msgs: 
    print(f"Encrypting: {msg:x}")
    ciphertext = spn.encrypt(msg)
    decrypted = spn.decrypt(ciphertext)
    print(f"Decrypted: {decrypted:x}")
    assert(msg == decrypted, f"Test fail! Expected: 0x{msg:x} but got 0x{decrypted:x}")