from subpermnetwork import SPN
from collections import Counter

BITS_SIZE = SPN.BITS_SIZE
spn = SPN(4, keys=[516, 516, 516, 516, 516])
SBOX = spn.sub_lookup


def sbox_transform(input_pairs: tuple) -> tuple:
    return tuple(SBOX[i] for i in input_pairs)


def diff_table(sbox: dict) -> Counter:
    all_input_pairs = [(i, j) for i in range(BITS_SIZE) for j in range(BITS_SIZE)]  # [(0, 0), (0, 1), ..., (1, 0), ..., (14, 15), ..., (15, 14), (15, 15)]
    # corresponding_output_pairs = [sbox_transform(pair) for pair in all_input_pairs]
    corresponding_output_pairs = [(sbox[pair[0]], sbox[pair[1]]) for pair in all_input_pairs]
    input_diffs = [pair[0] ^ pair[1] for pair in all_input_pairs]  # X difference (XOR) for each input pair
    corresponding_output_diffs = [pair[0] ^ pair[1] for pair in corresponding_output_pairs]  # Y difference (XOR) for each output pair
    diff_counter = Counter(zip(input_diffs, corresponding_output_diffs))
    print(diff_counter)
    return diff_counter


diff_table(SBOX)

# def difference_distribution_table(sbox, input_difference):
