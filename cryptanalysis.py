from subpermnetwork import SPN
from collections import Counter, OrderedDict
from random import sample, choice, randrange
from math import log2, prod
from itertools import product as cartesian_product
from time import time


BITS_SIZE = SPN.BITS_SIZE
N_SBOX_PER_ROUND = SPN.N_SBOX_PER_ROUND
# keys = [1, 1, 1, 1, 1]
keys = [randrange(2**16) for _ in range(4 + 1)]
spn = SPN(4, keys=keys)
SBOX: dict = spn.sub_lookup
SBOX_INVERSED: dict = spn.decrypt_sub_lookup
SBOX_SIZE: int = int(log2(len(SBOX)))  # Should be 4 for this project
N_ROUNDS = spn.n_rounds


def diff_table(sbox: dict) -> Counter:
    all_input_pairs = [(i, j) for i in range(BITS_SIZE) for j in range(BITS_SIZE)]  # [(0, 0), (0, 1), ..., (1, 0), ..., (14, 15), ..., (15, 14), (15, 15)]
    corresponding_output_pairs = [(sbox[pair[0]], sbox[pair[1]]) for pair in all_input_pairs]
    input_diffs = [pair[0] ^ pair[1] for pair in all_input_pairs]  # X difference (XOR) for each input pair
    corresponding_output_diffs = [pair[0] ^ pair[1] for pair in corresponding_output_pairs]  # Y difference (XOR) for each output pair
    diff_counter = Counter(zip(input_diffs, corresponding_output_diffs))
    return diff_counter


difference_distribution_table: Counter = diff_table(SBOX)


def most_probable_diff_pairs() -> dict:
    """
    Given a sbox lookup, return a dictionary of the most probable differential pairs (delta_X, delta_Y) and their probability.
    If multiple output difference has the same probabilities, include them all.
    :param sbox: a sbox lookup dictionary
    :return: {input_difference: ([most_probable_output_difference], probability)}
    """
    diff_counter: Counter = difference_distribution_table
    diff_pairs: OrderedDict = OrderedDict()
    for ((in_diff, out_diff), freq) in diff_counter.most_common():
        if in_diff not in diff_pairs:
            diff_pairs[in_diff] = ([out_diff], freq / BITS_SIZE)
        elif freq / BITS_SIZE == diff_pairs[in_diff][1]:
            diff_pairs[in_diff][0].append(out_diff)
    return diff_pairs


most_probable_differential: OrderedDict = most_probable_diff_pairs()


def most_probable_output_diff(input_diff):
    diffs, prob = most_probable_differential[input_diff]
    return diffs[0], prob
    # return choice(diffs), prob


def chop_into_sbox_size(binary_num: int) -> list[int]:
    """0b0000101100000000 -> [0b0000, 0b1011, 0b0000, 0b0000]"""
    binary_num = binary_num
    res = []
    mask = 2**SBOX_SIZE - 1  # 0b1111
    for _ in range(N_SBOX_PER_ROUND):
        res.insert(0, binary_num & mask)
        binary_num = binary_num >> SBOX_SIZE
    return res


def stitch_num_list(num_list: list[int]) -> int:
    """[0b0000, 0b1011, 0b0000, 0b0000] -> 0b0000101100000000"""
    res: int = 0
    lst_len = len(num_list)
    for idx, val in enumerate(num_list):
        res += val << ((lst_len - idx - 1) * SBOX_SIZE)
    return res


def greedy_output_diff_and_probability(input_diff) -> (int, int):
    output_diff_and_probabilities = [most_probable_output_diff(in_diff) for in_diff in
                                     chop_into_sbox_size(input_diff)]
    output_diffs, probabilities = zip(*output_diff_and_probabilities)
    return stitch_num_list(output_diffs), prod(probabilities)


def differential_characteristic_and_probability(input_diff: int) -> (int, int, int):
    current_round_input = input_diff
    current_prob = 1
    for r in range(N_ROUNDS - 1):
        v, prob = greedy_output_diff_and_probability(current_round_input)
        current_round_input = spn.permute(v)
        current_prob *= prob
    return input_diff, current_round_input, current_prob


def possible_target_partial_subkeys(expected_output_diffs):
    expected_diffs_list = chop_into_sbox_size(expected_output_diffs)
    possible_subkeys_in_list = map(lambda n: [0] if n == 0 else list(range(2**SBOX_SIZE)), expected_diffs_list)
    return [stitch_num_list(key_list) for key_list in cartesian_product(*possible_subkeys_in_list)]


C = 10


def extract_partial_keys(starting_input_diff):
    input_diff, expected_output_diff, prob = differential_characteristic_and_probability(starting_input_diff)
    expected_diffs_list = chop_into_sbox_size(expected_output_diff)
    active_sbox_index = [index for index, diff in enumerate(expected_diffs_list) if diff != 0]
    expected_active_diffs_list = [expected_diffs_list[i] for i in active_sbox_index]
    inactive_sbox_index = [index for index, diff in enumerate(expected_diffs_list) if diff == 0]
    all_possible_keys = possible_target_partial_subkeys(expected_output_diff)
    best_guess = 0
    best_n_right_pairs = 0

    sample_size = int(C // prob)
    X1_samples = sample(range(2**(N_SBOX_PER_ROUND * SBOX_SIZE)), sample_size)
    cipher_text_pairs = [(spn.encrypt(x), spn.encrypt(x ^ input_diff)) for x in X1_samples]

    for key in all_possible_keys:
        n_right_pairs = 0
        for c1, c2 in cipher_text_pairs:
            v1 = chop_into_sbox_size(c1 ^ key)
            v2 = chop_into_sbox_size(c2 ^ key)
            if not all([v1[i] == v2[i] for i in inactive_sbox_index]):
                continue

            active_diff = [SBOX_INVERSED[v1[i]] ^ SBOX_INVERSED[v2[i]] for i in active_sbox_index]
            if active_diff == expected_active_diffs_list:
                n_right_pairs += 1

        if n_right_pairs > best_n_right_pairs:
            best_guess = key
            best_n_right_pairs = n_right_pairs

    res = chop_into_sbox_size(best_guess)
    for i in inactive_sbox_index:
        res[i] = None
    return res


promising_starts = list(most_probable_differential.keys())[1:]  # Drop 0


def attack():
    last_key = [None] * N_SBOX_PER_ROUND
    for start_input in promising_starts:
        if None not in last_key:
            break
        full_inputs = [start_input << i * SBOX_SIZE for i in range(N_SBOX_PER_ROUND)]
        candidates = [differential_characteristic_and_probability(input_diff) for input_diff in full_inputs]
        input_diff, output_diff, probability = max(candidates, key=lambda t: t[2])
        active_sbox_index = [index for index, diff in enumerate(chop_into_sbox_size(output_diff)) if diff != 0]
        if all([last_key[i] for i in active_sbox_index]):
            continue
        if probability < .005:
            continue
        partial_keys = extract_partial_keys(input_diff)
        for i, key in enumerate(partial_keys):
            if (key is not None) and (last_key[i] is None):
                last_key[i] = key
    return stitch_num_list(last_key)


print(f'SPN keys: {keys}')
start = time()
retrieved_last_round_key = attack()
end = time()
print(f'Last round key retrieved: {retrieved_last_round_key}, took {end - start} sec')
