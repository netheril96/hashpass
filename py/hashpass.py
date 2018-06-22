#!/usr/bin/env python3
import fire
import random
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import unicodedata
import string
import json
from typing import *

BACKEND = default_backend()
N = 16384
R = 8
P = 1
NUM_OCTATS = 16


def ensure_bytes(value: AnyStr) -> bytes:
    if isinstance(value, str):
        value = unicodedata.normalize('NFKC', value)
        return value.encode('utf-8')
    return value


def bytes_to_big_endian_large_int(b: ByteString) -> int:
    result = 0
    for v in b:
        result = result * 256 + v
    return result


def derive(master_password: str, domain: str, user: str, counter: int, length: int, charset: str) -> str:
    if counter < 0 or counter > 255:
        raise ValueError(
            f'Counter {counter} cannot be represented by a single byte')
    master_password = ensure_bytes(master_password)
    domain = ensure_bytes(domain)
    user = ensure_bytes(user)

    salt = domain + b'\0' + user + b'\0' + bytes([counter])
    hash_bytes: bytes = Scrypt(salt=salt, length=NUM_OCTATS, n=N, r=R,
                               p=P, backend=BACKEND).derive(master_password)
    hash_int = bytes_to_big_endian_large_int(hash_bytes)
    result = [None] * length
    for i in range(length):
        if not hash_int:
            raise ValueError(
                f'Entropy exhausted. Requested derived password too long (len={length}).')
        hash_int, residue = divmod(hash_int, len(charset))
        result[i] = charset[residue]
    return ''.join(result)


def write_test_file(filename, seed=0xCAD0981F):
    domains = ['google', 'abc', '163', '招商银行', '🤦🏼‍♂️', 'Ç']
    users = ['rsy', 'blah96']
    obj = []
    state = random.Random(seed)
    charset = string.printable
    for d in domains:
        for u in users:
            master_password = ''.join(state.choices(
                population=charset, k=state.randrange(1, 17)))
            length = state.randrange(1, 17)
            counter = state.randrange(0, 9)
            obj.append({'domain': d,
                        'user': u,
                        'length': length,
                        'master_password': master_password,
                        'counter': counter,
                        'derived': derive(master_password, d, u, counter, length, charset)
                        })
    with open(filename, 'w') as f:
        json.dump({'charset': charset, 'objects': obj},
                  f, ensure_ascii=False, indent=4)


if __name__ == '__main__':
    fire.Fire()
