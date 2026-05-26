import random
import hashlib
import math
from typing import Tuple, List, Any
from sympy import isprime, nextprime

class Paillier:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
        self.g = None
        self.lmbda = None
        self.mu = None

    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int, int]]:
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        
        while p == q:
            q = self._generate_prime(self.key_size // 2)
        
        self.n = p * q
        self.g = self.n + 1
        
        phi_n = (p - 1) * (q - 1)
        self.lmbda = self._lcm(p - 1, q - 1)
        self.mu = self._mod_inverse(self._l(self.g ** self.lmbda % self.n ** 2), self.n)
        
        self.public_key = (self.n, self.g)
        self.private_key = (self.lmbda, self.mu, self.n)
        
        return self.public_key, self.private_key

    def _generate_prime(self, bits: int) -> int:
        candidate = random.getrandbits(bits)
        while not isprime(candidate):
            candidate = random.getrandbits(bits)
        return candidate

    def _lcm(self, a: int, b: int) -> int:
        return abs(a * b) // math.gcd(a, b)

    def _mod_inverse(self, a: int, m: int) -> int:
        return pow(a, -1, m)

    def _l(self, x: int) -> int:
        return (x - 1) // self.n

    def encrypt(self, plaintext: int) -> int:
        if plaintext < 0 or plaintext >= self.n:
            raise ValueError("Plaintext out of range")
        
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        
        ciphertext = (pow(self.g, plaintext, self.n ** 2) * pow(r, self.n, self.n ** 2)) % (self.n ** 2)
        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        if ciphertext < 0 or ciphertext >= self.n ** 2:
            raise ValueError("Ciphertext out of range")
        
        x = pow(ciphertext, self.lmbda, self.n ** 2)
        plaintext = (self._l(x) * self.mu) % self.n
        return plaintext

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        return (ciphertext1 * ciphertext2) % (self.n ** 2)

    def multiply(self, ciphertext: int, scalar: int) -> int:
        return pow(ciphertext, scalar, self.n ** 2)

    def encrypt_float(self, value: float, precision: int = 64) -> int:
        scaled = int(value * (10 ** precision))
        return self.encrypt(scaled)

    def decrypt_float(self, ciphertext: int, precision: int = 64) -> float:
        scaled = self.decrypt(ciphertext)
        return scaled / (10 ** precision)

class SecureMultiPartyComputation:
    def __init__(self, paillier: Paillier):
        self.paillier = paillier

    def secure_sum(self, encrypted_values: List[int]) -> int:
        result = encrypted_values[0]
        for val in encrypted_values[1:]:
            result = self.paillier.add(result, val)
        return result

    def secure_mean(self, encrypted_values: List[int]) -> int:
        n = len(encrypted_values)
        total = self.secure_sum(encrypted_values)
        return self.paillier.multiply(total, pow(n, -1, self.paillier.n))

    def secure_dot_product(self, encrypted_vector: List[int], plain_vector: List[int]) -> int:
        if len(encrypted_vector) != len(plain_vector):
            raise ValueError("Vectors must have same length")
        
        products = [self.paillier.multiply(enc_val, plain_val) 
                    for enc_val, plain_val in zip(encrypted_vector, plain_vector)]
        return self.secure_sum(products)

class EncryptedGradientAggregator:
    def __init__(self, paillier: Paillier):
        self.paillier = paillier
        self.gradients = []

    def add_gradient(self, encrypted_gradient: List[int]) -> None:
        self.gradients.append(encrypted_gradient)

    def aggregate(self) -> List[int]:
        if not self.gradients:
            raise ValueError("No gradients to aggregate")
        
        num_parties = len(self.gradients)
        num_dimensions = len(self.gradients[0])
        
        aggregated = []
        for dim in range(num_dimensions):
            dim_gradients = [g[dim] for g in self.gradients]
            summed = self._secure_sum(dim_gradients)
            averaged = self.paillier.multiply(summed, pow(num_parties, -1, self.paillier.n))
            aggregated.append(averaged)
        
        return aggregated

    def _secure_sum(self, encrypted_values: List[int]) -> int:
        result = encrypted_values[0]
        for val in encrypted_values[1:]:
            result = self.paillier.add(result, val)
        return result

    def decrypt_gradient(self, encrypted_gradient: List[int]) -> List[float]:
        return [self.paillier.decrypt_float(g) for g in encrypted_gradient]