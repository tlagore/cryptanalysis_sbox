from subpermnetwork import SPN


# 43 just lets us keep the random seed so we know expected keys
spn = SPN(4, 43, [516,516,516,516,516])

msg = 0xABCD
print(f"Encrypting: {msg:x}")
ciphertext = spn.encrypt(msg)
decrypted = spn.decrypt(ciphertext)
print(f"Decrypted: {decrypted:x}")