
from argparse import ArgumentError
from tabnanny import verbose
import time
import random

DEBUG = True
VERBOSE = False

def debug_print(*args, **kwargs):
    if DEBUG:
        print(f"| {time.strftime('%H:%M%p %Z on %b %d, %Y')} -- DEBUG:: ", end='')
        print(*args, **kwargs)

def verbose_print(*args, **kwargs):
    if VERBOSE:
        debug_print(*args, **kwargs)

class SBox:
    BITS_SIZE = 16

    def __init__(self, n_rounds, random_key = time.time()):
        random.seed(random_key)
        self.keys = []

        # generate random keys
        [ self.keys.append(random.randint(0, 2**self.BITS_SIZE)) for _ in range(n_rounds+1) ]

        for idx, key in enumerate(self.keys):
            debug_print(f'key {idx+1}: {key:x}')

        # number of bytes that we can handle in 1 round
        self.block_size = int(self.BITS_SIZE / 8)

        self.n_rounds = n_rounds

        self.sub_lookup = {
            0x0: 0xE,
            0x1: 0x4,
            0x2: 0xD,
            0x3: 0x1,
            0x4: 0x2,
            0x5: 0xF,
            0x6: 0xB,
            0x7: 0x8,
            0x8: 0x3,
            0x9: 0xA,
            0xA: 0x6,
            0xB: 0xC,
            0xC: 0x5,
            0xD: 0x9,
            0xE: 0x0,
            0xF: 0x7,
        }

        self.perm_lookup = {
            1: 1,
            2: 5,
            3: 9,
            4: 13,
            5: 2,
            6: 6,
            7: 10,
            8: 14,
            9: 3,
            10: 7,
            11: 11,
            12: 15,
            13: 4,
            14: 8,
            15: 12,
            16: 16,
        }


    def _str_to_bits(self, str_val):
        """ no need to prepend bits, they will all be 0's """

        int_val = 0
        for ch in str_val:
            int_val = (int_val << 8) | ord(ch)

        return int_val

    def _bits_to_str(self, bits):
        mask = 0xFF
        ret_str = ""

        while bits != 0:
            ch = chr(bits & mask)
            bits = bits >> 8
            ret_str = ch + ret_str 

        return ret_str

    def _encrypt(self, bits):
        """ """
        for i in range(self.n_rounds):
            bits = self.round(bits, i)
            verbose_print(f"Encrypt: Round {i+1}: {bits:x}")

        bits = self._mix_key(bits, self.keys[self.n_rounds])
        return bits

    def encrypt_decrypt(self, message, encrypt=True):
        if encrypt:
            debug_print(f"ENCRYPTING: '{message}'")
        else:
            debug_print(f"DECRYPTING: '{message}'")

        m = message
        c = ""
        c_bits = 0
        while len(m) > 0:
            block = m[0:self.block_size]
            m = m[self.block_size:]
            bits = self._str_to_bits(block)

            if encrypt:
                bits = self._encrypt(bits)
            else:
                bits = self._decrypt(bits)

            c += self._bits_to_str(bits)
            c_bits = (c_bits << self.BITS_SIZE) | bits

            
        if encrypt:
            debug_print(f"Ciphertext:\nhex: {c_bits:x}\nascii:{c}")
        else:
            debug_print(f"Decrypted message:\nhex:{c_bits:x}\nascii:{c}")

        return c

    def _decrypt(self, bits):
        """ """
        bits = self._mix_key(bits, self.keys[self.n_rounds])

        for i in range(self.n_rounds-1, -1, -1):
            bits = self.dnour(bits, i)
            verbose_print(f"Decrypt: Round {self.n_rounds - (i)}: {bits:x}")

        return bits

    def dnour(self, input_val, cur_round):
        """ """
        # second last round we do not permute
        if cur_round != self.n_rounds - 1:
            input_val = self._permute(input_val)

        input_val = self._substitute(input_val)
        input_val = self._mix_key(input_val, self.keys[cur_round])

        return input_val

    def round(self, input_val, cur_round):
        """ """
        input_val = self._mix_key(input_val, self.keys[cur_round])
        input_val = self._substitute(input_val)

        # second last round we do not permute
        if cur_round != self.n_rounds - 1:
            input_val = self._permute(input_val)

        return input_val

    def _substitute(self, message):
        """ """
        ret_val = 0
        mask = 0xF

        for idx in range(0, int(self.BITS_SIZE/4)):
            ret_val |= self.sub_lookup[(message & mask) >> (idx*4)]
            mask <<= 4

        return message

    def _permute(self, message):
        """ """
        ret_val = 0
        mask = 0x8000

        # permute lookup is 1 indexed, so we go from [16 -> 1]
        # leftmost bit is 1, rightmost bit is 16
        for idx in range(1, self.BITS_SIZE+1):
            # extract value of current 
            curBit = (message & mask)

            # only need to set the bit if it's 1
            if curBit:
                # need to shift it weird because the paper indexed with 1 as the leftmost bit for some reason
                shift = self.BITS_SIZE-(self.perm_lookup[idx])
                location = (1 << shift)
                ret_val |= location
                verbose_print(f"permute:: idx: {idx}, to:{(self.perm_lookup[idx])}, bit_val: {curBit}, shift: {shift}, mask: {mask:x}, location: {location:b} ret_val:{ret_val:b}")

            mask >>= 1

        return ret_val

    def _mix_key(self, bits, key):
        """ simple xor """
        return (bits ^ key)


sbox = SBox(4, 43)
encrypted = sbox.encrypt_decrypt("Junlin, I have created our sbox encryption implementation - woohoo!")
sbox.encrypt_decrypt(encrypted, False)