import argparse
import io
import sys
from dataclasses import dataclass
from itertools import cycle, starmap

# constants
A = ord('A')
MAX_KEY_LENGTH = 50
MAX_KEY_CANDIDATE = 10
MAX_DUPLICATED_PART = 0.7

# frequency taken from https://en.wikipedia.org/wiki/Letter_frequency
FREQ_ENGLISH = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
                0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
                0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
                0.06327, 0.09056, 0.02758, 0.00978, 0.0236, 0.0015,
                0.01974, 0.00074]
# IC(index of coincidence) expected for english
IC_ENGLISH = sum(f * f for f in FREQ_ENGLISH) * 26


def alpha_only(text):  # -> str:
    """ get all capitalized alpha only text """
    return ''.join(filter(lambda c: c.isalpha(), text)).upper()


class Vigenere:
    def __init__(self, keyword: str):
        self.keyword = alpha_only(keyword)

    @staticmethod
    def get_cipher(p, k):  # -> str:
        """ encrypt character p using character k as key """
        return chr(A + ((ord(p) - A) + (ord(k) - A)) % 26)

    @staticmethod
    def get_plain(c, k):  # -> str:
        """ decrypt character c using character k """
        return chr(A + ((ord(c) - A) - (ord(k) - A)) % 26)

    @staticmethod
    def extract_extra(text):
        """ extract spaces and other non-alpha character's positional information """
        return list(filter(lambda x: not x[1].isalpha(), enumerate(text)))

    @staticmethod
    def add_extra(text, extra):
        text = list(text)
        for e in extra:
            text.insert(*e)
        return ''.join(text)

    def encrypt(self, plain_text, keep_extra=False):  # -> str:
        extra = self.extract_extra(plain_text) if keep_extra else []
        plain_text = alpha_only(plain_text)
        cipher_text = ''.join(starmap(self.get_cipher, zip(plain_text, cycle(self.keyword))))
        return self.add_extra(cipher_text, extra) if extra else cipher_text

    def decrypt(self, cipher_text, keep_extra=False):  # -> str:
        extra = self.extract_extra(cipher_text) if keep_extra else []
        cipher_text = alpha_only(cipher_text)
        plain_text = ''.join(starmap(self.get_plain, zip(cipher_text, cycle(self.keyword))))
        return self.add_extra(plain_text, extra) if extra else plain_text

    def encrypt_file(self, in_path, out_path, keep_extra=True):
        with open(in_path, 'r') as in_file, open(out_path, 'w') as out_file:
            cipher_text = self.encrypt(in_file.read(), keep_extra)
            out_file.write(cipher_text)

    def decrypt_file(self, in_path, out_path, keep_extra=True):
        with open(in_path, 'r') as in_file, open(out_path, 'w') as out_file:
            plain_text = self.decrypt(in_file.read(), keep_extra)
            out_file.write(plain_text)


def index_of_coincidence(text):  # -> float:
    """ calculate IC(index of coincidence) of given string sequence
    Check this for details: https://en.wikipedia.org/wiki/Index_of_coincidence"""
    n = len(text)
    if n <= 1:
        return 26  # or should I raise an error here?
    counts = [0 for _ in range(26)]
    for c in text:
        counts[ord(c) - A] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1) / 26)


def group_with_length(text, n):  # -> list[list[str]]:
    """ i_th item falls into (i % length)_th group """
    results = [[] for _ in range(n)]
    for i, c in enumerate(text):
        results[i % n].append(c)
    return results


@dataclass(frozen=True)
class KeyInfo:
    length: int
    ic: float


@dataclass(frozen=True)
class Key:
    key: str
    ic: float


def guess_key_length(text):  # -> list[KeyInfo]:
    """ compare AVERAGE IC of every key length in [1, MAX_KEY_LENGTH),
     return the top MAX_KEY_CANDIDATE ones close to IC_ENGLISH """
    key_info = []
    for length in range(1, min(MAX_KEY_LENGTH, len(text))):
        substrings = group_with_length(text, length)
        average_ic = sum(index_of_coincidence(ss) for ss in substrings) / len(substrings)
        key_info.append(KeyInfo(length, average_ic))
    return sorted(key_info, key=lambda x: abs(x.ic - IC_ENGLISH))[:10]


def correlation_of(text):  # -> float:
    """ correlation between the text letter frequencies and the relative letter frequencies for normal English text """
    n = len(text)
    counts = [0] * 26
    for c in text:
        counts[ord(c) - A] += 1
    return sum(counts[i] / n * FREQ_ENGLISH[i] for i in range(26))


def get_single_key(text):  # -> str:
    """ test every character as key for given text, use the one that has the highest correlation """
    correlations, max_idx = [], 0
    for i in range(26):
        v = Vigenere(chr(A + i))
        correlations.append(correlation_of(v.decrypt(text)))
        if correlations[i] > correlations[max_idx]:
            max_idx = i
    return chr(A + max_idx)


def crack_virginia(cipher_text, save_to: io.TextIOBase, keep_extra):
    extra = Vigenere.extract_extra(cipher_text) if keep_extra else []
    cipher_text, keys = alpha_only(cipher_text), []

    # try all possible key length, find their corresponding keys
    for key_info in guess_key_length(cipher_text):
        substrings = group_with_length(cipher_text, key_info.length)
        key = Key(''.join(get_single_key(ss) for ss in substrings), key_info.ic)
        keys.append(key)

    # add extra information back
    cipher_text = Vigenere.add_extra(cipher_text, extra)

    # remove similar(the ones have duplicated part bigger than MAX_DUPLICATED_PART) keys
    copy, keep = sorted(keys, key=lambda k: len(k.key)), []
    while len(copy) > 1:
        drop = False
        for other in copy[:-1]:
            original = len(copy[-1].key)
            processed = len(copy[-1].key.replace(other.key, ''))
            if (1 - processed / original) > MAX_DUPLICATED_PART:
                drop = True
                break
        if not drop:
            keep.insert(0, copy[-1])
        copy.pop()
    keep.extend(copy)
    keys = list(filter(lambda k: k in keep, keys))

    # save decoding results
    for key in keys:
        save_to.write(f'Decrypt using {key}:\n')
        v = Vigenere(key.key)
        save_to.write(v.decrypt(cipher_text, keep_extra))
        save_to.write('\n\n')


def normal_mode(in_file, out_file, key, encrypt, remove_extra, **kwargs):
    v = Vigenere(key)
    keep_extra = not remove_extra
    input_text = in_file.read()
    if encrypt:
        result_text = v.encrypt(input_text, keep_extra)
    else:
        result_text = v.decrypt(input_text, keep_extra)
    out_file.write(result_text)


def cracking_mode(in_file, out_file, remove_extra, **kwargs):
    keep_extra = not remove_extra
    input_text = in_file.read()
    crack_virginia(input_text, out_file, keep_extra)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Vigenere encryption, '
                                                 'decryption and ciphertext-only attack in python.')
    subparsers = parser.add_subparsers(dest='subparser_name', help='choose a working mode', required=True)

    parser_normal = subparsers.add_parser('normal', help='normal mode')
    parser_normal.add_argument('-k', '--key', type=str, required=True, help='use this key to encrypt/decrypt')
    parser_normal.add_argument('-e', '--encrypt', action='store_const', const=True, help='do encryption')
    parser_normal.add_argument('-d', '--decrypt', action='store_const', const=True, help='do decryption')
    parser_normal.set_defaults(func=normal_mode)

    parser_crack = subparsers.add_parser('crack', help='cracking mode')
    parser_crack.set_defaults(func=cracking_mode)

    for subparser in [parser_normal, parser_crack]:
        subparser.add_argument('-r', '--remove_extra', action='store_const', const=True,
                               help='remove extra information in text(spaces and other non-alpha characters)')
        subparser.add_argument('in_file', nargs='?', type=argparse.FileType('r'), help='input file')
        subparser.add_argument('out_file', nargs='?', type=argparse.FileType('w'), help='output file')
        subparser.set_defaults(in_file=sys.stdin, out_file=sys.stdout)

    args = parser.parse_args()
    args.func(**vars(args))
