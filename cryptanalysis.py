from subpermnetwork import SPN
from collections import Counter, OrderedDict
from random import sample, choice, randrange
from math import log2, prod
from itertools import product as cartesian_product
from time import time


class DifferentialCryptanalysis:
    def __init__(self, n_rounds, n_sbox_per_round, sbox_size, spn: SPN):
        self.SBOX_SIZE = sbox_size
        self.BITS_SIZE = n_sbox_per_round * sbox_size
        self.N_SBOX_PER_ROUND = n_sbox_per_round
        self.spn = spn
        self.SBOX: dict = spn.sub_lookup
        self.SBOX_INVERSED = {v: k for k, v in self.SBOX.items()}
        self.N_ROUNDS = n_rounds
        self.difference_distribution_table: Counter = self._diff_table(self.SBOX)
        self.most_probable_differential: OrderedDict = self._most_probable_diff_pairs()
        self.promising_starts = list(self.most_probable_differential.keys())[1:]  # Drop 0

    def _diff_table(self, sbox: dict) -> Counter:
        BITS_SIZE = self.BITS_SIZE
        all_input_pairs = [(i, j) for i in range(BITS_SIZE) for j in
                           range(BITS_SIZE)]  # [(0, 0), (0, 1), ..., (1, 0), ..., (14, 15), ..., (15, 14), (15, 15)]
        corresponding_output_pairs = [(sbox[pair[0]], sbox[pair[1]]) for pair in all_input_pairs]
        input_diffs = [pair[0] ^ pair[1] for pair in all_input_pairs]  # X difference (XOR) for each input pair
        corresponding_output_diffs = [pair[0] ^ pair[1] for pair in
                                      corresponding_output_pairs]  # Y difference (XOR) for each output pair
        diff_counter = Counter(zip(input_diffs, corresponding_output_diffs))
        return diff_counter

    def _most_probable_diff_pairs(self) -> dict:
        """
        Given a sbox lookup, return a dictionary of the most probable differential pairs (delta_X, delta_Y) and their probability.
        If multiple output difference has the same probabilities, include them all.
        :param sbox: a sbox lookup dictionary
        :return: {input_difference: ([most_probable_output_difference], probability)}
        """
        BITS_SIZE = self.BITS_SIZE
        diff_counter: Counter = self.difference_distribution_table
        diff_pairs: OrderedDict = OrderedDict()
        for ((in_diff, out_diff), freq) in diff_counter.most_common():
            if in_diff not in diff_pairs:
                diff_pairs[in_diff] = ([out_diff], freq / BITS_SIZE)
            elif freq / BITS_SIZE == diff_pairs[in_diff][1]:
                diff_pairs[in_diff][0].append(out_diff)
        return diff_pairs

    def _most_probable_output_diff(self, input_diff: int) -> (int, float):
        diffs, prob = self.most_probable_differential[input_diff]
        return diffs[0], prob
        # return choice(diffs), prob

    def _chop_into_sbox_size(self, binary_num: int) -> list[int]:
        """0b0000101100000000 -> [0b0000, 0b1011, 0b0000, 0b0000]"""
        binary_num = binary_num
        res = []
        mask = 2 ** self.SBOX_SIZE - 1  # 0b1111
        for _ in range(self.N_SBOX_PER_ROUND):
            res.insert(0, binary_num & mask)
            binary_num = binary_num >> self.SBOX_SIZE
        return res

    def _stitch_num_list(self, num_list: list[int]) -> int:
        """[0b0000, 0b1011, 0b0000, 0b0000] -> 0b0000101100000000"""
        res: int = 0
        lst_len = len(num_list)
        for idx, val in enumerate(num_list):
            res += val << ((lst_len - idx - 1) * self.SBOX_SIZE)
        return res

    def _greedy_output_diff_and_probability(self, input_diff) -> (int, int):
        output_diff_and_probabilities = [self._most_probable_output_diff(in_diff) for in_diff in
                                         self._chop_into_sbox_size(input_diff)]
        output_diffs, probabilities = zip(*output_diff_and_probabilities)
        return self._stitch_num_list(output_diffs), prod(probabilities)

    def _differential_characteristic_and_probability(self, input_diff: int) -> (int, int, int):
        current_round_input = input_diff
        current_prob = 1
        for r in range(self.N_ROUNDS - 1):
            v, prob = self._greedy_output_diff_and_probability(current_round_input)
            current_round_input = self.spn.permute(v)
            current_prob *= prob
        return input_diff, current_round_input, current_prob

    def _possible_target_partial_subkeys(self, expected_output_diffs):
        expected_diffs_list = self._chop_into_sbox_size(expected_output_diffs)
        possible_subkeys_in_list = map(lambda n: [0] if n == 0 else list(range(2 ** self.SBOX_SIZE)),
                                       expected_diffs_list)
        return [self._stitch_num_list(key_list) for key_list in cartesian_product(*possible_subkeys_in_list)]

    def _extract_partial_keys(self, starting_input_diff):
        input_diff, expected_output_diff, prob = self._differential_characteristic_and_probability(starting_input_diff)
        expected_diffs_list = self._chop_into_sbox_size(expected_output_diff)
        active_sbox_index = [index for index, diff in enumerate(expected_diffs_list) if diff != 0]
        expected_active_diffs_list = [expected_diffs_list[i] for i in active_sbox_index]
        inactive_sbox_index = [index for index, diff in enumerate(expected_diffs_list) if diff == 0]
        all_possible_keys = self._possible_target_partial_subkeys(expected_output_diff)
        best_guess = 0
        best_n_right_pairs = 0
        C = 10
        sample_size = int(C // prob)
        X1_samples = sample(range(2 ** (self.N_SBOX_PER_ROUND * self.SBOX_SIZE)), sample_size)
        cipher_text_pairs = [(self.spn.encrypt(x), self.spn.encrypt(x ^ input_diff)) for x in X1_samples]

        for key in all_possible_keys:
            n_right_pairs = 0
            for c1, c2 in cipher_text_pairs:
                v1 = self._chop_into_sbox_size(c1 ^ key)
                v2 = self._chop_into_sbox_size(c2 ^ key)
                if not all([v1[i] == v2[i] for i in inactive_sbox_index]):
                    continue

                active_diff = [self.SBOX_INVERSED[v1[i]] ^ self.SBOX_INVERSED[v2[i]] for i in active_sbox_index]
                if active_diff == expected_active_diffs_list:
                    n_right_pairs += 1

            if n_right_pairs > best_n_right_pairs:
                best_guess = key
                best_n_right_pairs = n_right_pairs

        res = self._chop_into_sbox_size(best_guess)
        for i in inactive_sbox_index:
            res[i] = None
        return res

    def attack(self):
        last_key = [None] * self.N_SBOX_PER_ROUND
        for start_input in self.promising_starts:
            if None not in last_key:
                break
            full_inputs = [start_input << i * self.SBOX_SIZE for i in range(self.N_SBOX_PER_ROUND)]
            candidates = [self._differential_characteristic_and_probability(input_diff) for input_diff in full_inputs]
            input_diff, output_diff, probability = max(candidates, key=lambda t: t[2])
            active_sbox_index = [index for index, diff in enumerate(self._chop_into_sbox_size(output_diff)) if diff != 0]
            if all([last_key[i] for i in active_sbox_index]):
                continue
            if probability < .005:
                continue
            partial_keys = self._extract_partial_keys(input_diff)
            for i, key in enumerate(partial_keys):
                if (key is not None) and (last_key[i] is None):
                    last_key[i] = key
        return self._stitch_num_list(last_key)


# keys = [1, 1, 1, 1, 1]
keys = [randrange(2 ** 16) for _ in range(4 + 1)]
spn = SPN(4, keys=keys)
dc = DifferentialCryptanalysis(4, 4, 4, spn)
print(f'SPN keys: {keys}')
start = time()
retrieved_last_round_key = dc.attack()
end = time()
print(f'Last round key retrieved: {retrieved_last_round_key}, took {end - start} sec')
