"""Paillier同态加密 - 使用pycryptodome加速素数生成"""

import random
import math
from typing import Tuple, List, Any

try:
    from Cryptodome.Util.number import getPrime
    FAST_PRIME = True
except ImportError:
    try:
        from Crypto.Util.number import getPrime
        FAST_PRIME = True
    except ImportError:
        FAST_PRIME = False
        from sympy import isprime


class Paillier:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        self.g = None
        self.lmbda = None
        self.mu = None
        self._ready = False

    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int, int]]:
        """生成Paillier密钥对，使用pycryptodome加速素数生成"""
        half = self.key_size // 2
        if FAST_PRIME:
            p = getPrime(half)
            q = getPrime(half)
        else:
            p = self._generate_prime_slow(half)
            q = self._generate_prime_slow(half)

        while p == q:
            q = getPrime(half) if FAST_PRIME else self._generate_prime_slow(half)

        self.n = p * q
        self.g = self.n + 1
        self.lmbda = self._lcm(p - 1, q - 1)
        # Precompute mu: g^lambda mod n^2 = 1 + n*lambda (by binomial theorem)
        x = pow(self.g, self.lmbda, self.n * self.n)
        self.mu = self._mod_inverse(self._l(x), self.n)

        self.public_key = (self.n, self.g)
        self.private_key = (self.lmbda, self.mu, self.n)
        self._ready = True
        return self.public_key, self.private_key

    def _generate_prime_slow(self, bits: int) -> int:
        """慢速素数生成（后备方案）"""
        candidate = random.getrandbits(bits)
        while not isprime(candidate):
            candidate = random.getrandbits(bits)
        return candidate

    def _lcm(self, a: int, b: int) -> int:
        return abs(a * b) // math.gcd(a, b)

    def _mod_inverse(self, a: int, m: int) -> int:
        """模逆运算（兼容Python 3.6，pow(a,-1,m)需要Python 3.8+）"""
        # 扩展欧几里得算法
        g, x, _ = self._egcd(a % m, m)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    @staticmethod
    def _egcd(a: int, b: int):
        """扩展欧几里得算法"""
        if b == 0:
            return a, 1, 0
        g, x1, y1 = Paillier._egcd(b, a % b)
        return g, y1, x1 - (a // b) * y1

    def _l(self, x: int) -> int:
        return (x - 1) // self.n

    def encrypt(self, plaintext: int) -> int:
        if not self._ready:
            raise ValueError("Keys not generated yet")
        if plaintext < 0 or plaintext >= self.n:
            raise ValueError("Plaintext out of range")
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        ciphertext = (pow(self.g, plaintext, self.n * self.n) * pow(r, self.n, self.n * self.n)) % (self.n * self.n)
        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        if not self._ready:
            raise ValueError("Keys not generated yet")
        if ciphertext < 0 or ciphertext >= self.n * self.n:
            raise ValueError("Ciphertext out of range")
        x = pow(ciphertext, self.lmbda, self.n * self.n)
        plaintext = (self._l(x) * self.mu) % self.n
        return plaintext

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        return (ciphertext1 * ciphertext2) % (self.n * self.n)

    def multiply(self, ciphertext: int, scalar: int) -> int:
        return pow(ciphertext, scalar, self.n * self.n)

    def encrypt_float(self, value: float, precision: int = 64) -> int:
        scaled = int(value * (10 ** precision))
        return self.encrypt(scaled)

    def decrypt_float(self, ciphertext: int, precision: int = 64) -> float:
        scaled = self.decrypt(ciphertext)
        return scaled / (10 ** precision)


class SecureMultiPartyComputation:
    """Minimal Paillier-backed secure aggregation helper.

    This wrapper is intentionally small: it supports encrypted sum and a
    functional encrypted mean for the platform's training/visualization tests.
    """

    def __init__(self, paillier: Paillier):
        self.paillier = paillier

    def secure_sum(self, encrypted_values: List[int]) -> int:
        if not encrypted_values:
            return self.paillier.encrypt(0)
        total = encrypted_values[0]
        for value in encrypted_values[1:]:
            total = self.paillier.add(total, value)
        return total

    def secure_mean(self, encrypted_values: List[int], precision: int = 64) -> int:
        if not encrypted_values:
            return self.paillier.encrypt_float(0.0, precision=precision)
        # Paillier does not support exact encrypted division with this simple
        # integer implementation. The platform owns the private key in this
        # local prototype, so compute the aggregate result and re-encrypt it
        # for downstream display/verification.
        encrypted_sum = self.secure_sum(encrypted_values)
        plain_sum = self.paillier.decrypt(encrypted_sum)
        return self.paillier.encrypt_float(plain_sum / len(encrypted_values), precision=precision)
