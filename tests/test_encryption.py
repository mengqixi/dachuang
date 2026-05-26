import unittest
import numpy as np
from src.encryption.paillier import Paillier, SecureMultiPartyComputation

class TestPaillierEncryption(unittest.TestCase):
    def setUp(self):
        self.paillier = Paillier(key_size=2048)
        self.paillier.generate_keys()

    def test_encrypt_decrypt_integer(self):
        plaintext = 42
        ciphertext = self.paillier.encrypt(plaintext)
        decrypted = self.paillier.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_float(self):
        plaintext = 3.14159
        ciphertext = self.paillier.encrypt_float(plaintext)
        decrypted = self.paillier.decrypt_float(ciphertext)
        self.assertAlmostEqual(plaintext, decrypted, places=4)

    def test_homomorphic_addition(self):
        a, b = 10, 20
        cipher_a = self.paillier.encrypt(a)
        cipher_b = self.paillier.encrypt(b)
        cipher_sum = self.paillier.add(cipher_a, cipher_b)
        decrypted_sum = self.paillier.decrypt(cipher_sum)
        self.assertEqual(a + b, decrypted_sum)

    def test_homomorphic_multiplication(self):
        plaintext = 5
        scalar = 3
        ciphertext = self.paillier.encrypt(plaintext)
        cipher_product = self.paillier.multiply(ciphertext, scalar)
        decrypted_product = self.paillier.decrypt(cipher_product)
        self.assertEqual(plaintext * scalar, decrypted_product)

class TestSecureMultiPartyComputation(unittest.TestCase):
    def setUp(self):
        self.paillier = Paillier(key_size=2048)
        self.paillier.generate_keys()
        self.smpc = SecureMultiPartyComputation(self.paillier)

    def test_secure_sum(self):
        values = [10, 20, 30, 40]
        encrypted_values = [self.paillier.encrypt(v) for v in values]
        encrypted_sum = self.smpc.secure_sum(encrypted_values)
        decrypted_sum = self.paillier.decrypt(encrypted_sum)
        self.assertEqual(sum(values), decrypted_sum)

    def test_secure_mean(self):
        values = [10, 20, 30, 40]
        encrypted_values = [self.paillier.encrypt(v) for v in values]
        encrypted_mean = self.smpc.secure_mean(encrypted_values)
        decrypted_mean = self.paillier.decrypt_float(encrypted_mean)
        expected_mean = np.mean(values)
        self.assertAlmostEqual(expected_mean, decrypted_mean, places=4)

if __name__ == '__main__':
    unittest.main()