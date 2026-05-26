import random
import hashlib
from typing import List, Tuple, Any

class ABY3Protocol:
    def __init__(self, security_parameter: int = 128):
        self.security_parameter = security_parameter
        self.modulus = 2 ** 61 - 1

    def share_secret(self, secret: int, num_parties: int = 3) -> List[int]:
        shares = []
        for _ in range(num_parties - 1):
            shares.append(random.randint(0, self.modulus - 1))
        
        last_share = secret
        for share in shares:
            last_share = (last_share - share) % self.modulus
        
        shares.append(last_share)
        return shares

    def reconstruct_secret(self, shares: List[int]) -> int:
        return sum(shares) % self.modulus

    def add_shares(self, shares_a: List[int], shares_b: List[int]) -> List[int]:
        if len(shares_a) != len(shares_b):
            raise ValueError("Share lists must have same length")
        
        return [(a + b) % self.modulus for a, b in zip(shares_a, shares_b)]

    def multiply_shares(self, shares_a: List[int], shares_b: List[int], 
                       beaver_triplets: List[Tuple[int, int, int]]) -> List[int]:
        if len(shares_a) != len(shares_b):
            raise ValueError("Share lists must have same length")
        
        result = []
        for i, (a, b) in enumerate(zip(shares_a, shares_b)):
            t, t_a, t_b = beaver_triplets[i]
            
            d_a = (a - t_a) % self.modulus
            d_b = (b - t_b) % self.modulus
            
            d = (d_a * d_b) % self.modulus
            d_a_b = (d_a * t_b) % self.modulus
            d_b_a = (d_b * t_a) % self.modulus
            
            share = (t + d + d_a_b + d_b_a) % self.modulus
            result.append(share)
        
        return result

    def generate_beaver_triplets(self, num_triplets: int) -> List[Tuple[int, int, int]]:
        triplets = []
        for _ in range(num_triplets):
            a = random.randint(0, self.modulus - 1)
            b = random.randint(0, self.modulus - 1)
            c = (a * b) % self.modulus
            triplets.append((a, b, c))
        return triplets

    def secure_comparison(self, shares_a: List[int], shares_b: List[int]) -> int:
        diff = self.add_shares(shares_a, [(self.modulus - b) % self.modulus for b in shares_b])
        msb = self._extract_msb(diff)
        return msb

    def _extract_msb(self, shares: List[int]) -> int:
        reconstructed = self.reconstruct_secret(shares)
        msb = (reconstructed >> 60) & 1
        return msb

    def truncate(self, shares: List[int], bits: int) -> List[int]:
        return [(s >> bits) % self.modulus for s in shares]

class PrivacyPreservingProtocol:
    def __init__(self):
        self.aby3 = ABY3Protocol()

    def private_set_intersection(self, set_a: List[int], set_b: List[int]) -> List[int]:
        hash_a = [int(hashlib.sha256(str(x).encode()).hexdigest(), 16) for x in set_a]
        hash_b = [int(hashlib.sha256(str(x).encode()).hexdigest(), 16) for x in set_b]
        
        intersection = []
        for i, h_a in enumerate(hash_a):
            for h_b in hash_b:
                if h_a == h_b:
                    intersection.append(set_a[i])
                    break
        
        return intersection

    def secure_mean(self, values: List[int]) -> float:
        if not values:
            return 0.0
        
        shares_list = [self.aby3.share_secret(v) for v in values]
        
        summed_shares = shares_list[0]
        for shares in shares_list[1:]:
            summed_shares = self.aby3.add_shares(summed_shares, shares)
        
        n = len(values)
        n_shares = self.aby3.share_secret(n)
        
        result_shares = []
        for s, n_s in zip(summed_shares, n_shares):
            result_shares.append((s * pow(n_s, -1, self.aby3.modulus)) % self.aby3.modulus)
        
        return self.aby3.reconstruct_secret(result_shares) / n

    def secure_variance(self, values: List[int]) -> float:
        if len(values) < 2:
            return 0.0
        
        mean = self.secure_mean(values)
        squared_diffs = [(v - mean) ** 2 for v in values]
        return self.secure_mean(squared_diffs)