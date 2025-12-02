#!/usr/bin/env python3
"""
Unit tests for Paillier cryptosystem
Tests encryption, decryption, homomorphic operations, and negative number handling
"""

import unittest
import sys
import os
import random
import gmpy2

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from security.paillier import Paillier


class TestPaillier(unittest.TestCase):
    """Test cases for Paillier cryptosystem"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Use smaller bit length for faster testing
        self.bit_length = 32
        self.paillier = Paillier(self.bit_length)
        self.paillier.key_gen()
        
        # Get public key for testing
        self.pkey = self.paillier.get_pkey()
        
        # Test values including negative numbers
        self.test_values = [
            0, 1, -1, 2, -2, 5, -5, 10, -10, 
            100, -100, 1000, -1000,
            # Edge cases around n/2
            self.pkey.u // 2 - 1,  # Just below n/2
            self.pkey.u // 2,      # Exactly n/2
            self.pkey.u // 2 + 1,  # Just above n/2
        ]
    
    def test_basic_encryption_decryption(self):
        """Test basic encryption and decryption"""
        print("\n=== Testing Basic Encryption/Decryption ===")
        
        for value in self.test_values:
            smod_result = self.paillier.smod(value, self.pkey)
            with self.subTest(value=value):
                # Encrypt
                ciphertext = self.paillier.encrypt(value)
                self.assertIsInstance(ciphertext, type(gmpy2.mpz(0)))
                
                # Decrypt
                decrypted, _ = self.paillier.decrypt(ciphertext)
                
                # Check if decrypted value matches original
                self.assertEqual(smod_result, decrypted, 
                               f"Encryption/decryption failed for value {value}")
    
    def test_negative_numbers(self):
        """Test negative number handling with smod"""
        print("\n=== Testing Negative Number Handling ===")
        
        # Test smod function directly
        for value in self.test_values:
            with self.subTest(value=value):
                smod_result = self.paillier.smod(value, self.pkey)
                
                # Check smod properties
                if value >= self.pkey.u // 2:
                    expected = value - self.pkey.u
                    self.assertEqual(smod_result, expected,
                                   f"smod failed for {value}, expected {expected}, got {smod_result}")
                else:
                    self.assertEqual(smod_result, value,
                                   f"smod failed for {value}, expected {value}, got {smod_result}")
                
                print(f"Value: {value}, smod: {smod_result}")
    
    def test_homomorphic_addition(self):
        """Test homomorphic addition (ciphertext multiplication)"""
        print("\n=== Testing Homomorphic Addition ===")
        
        # Test with various pairs of values
        test_pairs = [
            (5, 3),      # Both positive
            (-5, 3),     # Negative + positive
            (5, -3),     # Positive + negative
            (-5, -3),    # Both negative
            (0, 10),     # Zero + positive
            (10, 0),     # Positive + zero
            (0, 0),      # Both zero
        ]
        
        for v1, v2 in test_pairs:
            with self.subTest(v1=v1, v2=v2):
                # Encrypt both values
                c1 = self.paillier.encrypt(v1)
                c2 = self.paillier.encrypt(v2)
                
                # Homomorphic addition (multiply ciphertexts)
                c_sum = gmpy2.mul(c1, c2)
                c_sum = gmpy2.f_mod(c_sum, self.paillier.usquare)
                
                # Decrypt result
                result, _ = self.paillier.decrypt(c_sum)
                
                # Expected result
                expected = gmpy2.f_mod(v1 + v2, self.paillier.u)
                expected = self.paillier.smod(expected, self.pkey)
                
                print(f"{v1} + {v2} = {result} (expected: {expected})")
                self.assertEqual(result, expected,
                               f"Homomorphic addition failed: {v1} + {v2} = {result}, expected {expected}")
    
    def test_homomorphic_scalar_multiplication(self):
        """Test homomorphic scalar multiplication (exponentiation)"""
        print("\n=== Testing Homomorphic Scalar Multiplication ===")
        
        # Test with various scalar values
        scalars = [0, 1, 2, 3, 5, -1, -2, -3]
        base_values = [5, -5, 10, -10, 0]
        
        for base_val in base_values:
            for scalar in scalars:
                with self.subTest(base=base_val, scalar=scalar):
                    # Encrypt base value
                    c_base = self.paillier.encrypt(base_val)
                    
                    # Homomorphic scalar multiplication (exponentiation)
                    if scalar >= 0:
                        c_result = gmpy2.powmod(c_base, scalar, self.paillier.usquare)
                    else:
                        # For negative scalars, we need to compute inverse
                        c_inv = gmpy2.invert(c_base, self.paillier.usquare)
                        c_result = gmpy2.powmod(c_inv, -scalar, self.paillier.usquare)
                    
                    # Decrypt result
                    result, _ = self.paillier.decrypt(c_result)
                    
                    # Expected result
                    expected = gmpy2.f_mod(base_val * scalar, self.paillier.u)
                    expected = self.paillier.smod(expected, self.pkey)
                    
                    print(f"{scalar} * {base_val} = {result} (expected: {expected})")
                    self.assertEqual(result, expected,
                                   f"Homomorphic scalar multiplication failed: {scalar} * {base_val} = {result}, expected {expected}")
    
    def test_homomorphic_subtraction(self):
        """Test homomorphic subtraction (using addition with negative)"""
        print("\n=== Testing Homomorphic Subtraction ===")
        
        test_pairs = [
            (10, 3),     # Positive - positive
            (3, 10),     # Positive - larger positive
            (-10, 3),    # Negative - positive
            (10, -3),    # Positive - negative
            (-10, -3),   # Negative - negative
            (0, 5),      # Zero - positive
            (5, 0),      # Positive - zero
        ]
        
        for v1, v2 in test_pairs:
            with self.subTest(v1=v1, v2=v2):
                # Encrypt both values
                c1 = self.paillier.encrypt(v1)
                c2 = self.paillier.encrypt(v2)
                
                # Homomorphic subtraction: c1 * c2^(-1)
                c2_inv = gmpy2.invert(c2, self.paillier.usquare)
                c_diff = gmpy2.mul(c1, c2_inv)
                c_diff = gmpy2.f_mod(c_diff, self.paillier.usquare)
                
                # Decrypt result
                result, _ = self.paillier.decrypt(c_diff)
                
                # Expected result
                expected = gmpy2.f_mod(v1 - v2, self.paillier.u)
                expected = self.paillier.smod(expected, self.pkey)
                
                print(f"{v1} - {v2} = {result} (expected: {expected})")
                self.assertEqual(result, expected,
                               f"Homomorphic subtraction failed: {v1} - {v2} = {result}, expected {expected}")
    
    def test_edge_cases(self):
        """Test edge cases around the modulus boundary"""
        print("\n=== Testing Edge Cases ===")
        
        # Test values around n/2 boundary
        n = self.pkey.u
        boundary_values = [
            n // 2 - 1,  # Just below boundary
            n // 2,      # Exactly on boundary
            n // 2 + 1,  # Just above boundary
            n - 1,       # Maximum value
        ]
        
        for value in boundary_values:
            with self.subTest(value=value):
                # Test smod behavior
                # smod_result = self.paillier.smod(value, self.pkey)
                # Test encryption/decryption
                smod_result = self.paillier.smod(value, self.pkey)
                ciphertext = self.paillier.encrypt(value)
                decrypted, _ = self.paillier.decrypt(ciphertext)
                
                print(f"Value: {value}, decrypted: {decrypted}")
                
                # Check that encryption/decryption preserves the value
                self.assertEqual(smod_result, decrypted,
                               f"Edge case failed for value {value}")
    
    def test_random_values(self):
        """Test with random values"""
        print("\n=== Testing Random Values ===")
        
        # Generate random values within the valid range
        for _ in range(10):
            # Generate random value in range [-n/2, n/2)
            max_val = self.pkey.u // 2
            value = random.randint(-max_val, max_val - 1)
            
            with self.subTest(value=value):
                # Test encryption/decryption
                ciphertext = self.paillier.encrypt(value)
                decrypted, _ = self.paillier.decrypt(ciphertext)
                
                print(f"Random value: {value}, decrypted: {decrypted}")
                self.assertEqual(value, decrypted,
                               f"Random test failed for value {value}")
    
    def test_multiple_operations(self):
        """Test complex operations combining multiple homomorphic operations"""
        print("\n=== Testing Complex Operations ===")
        
        # Test: (a + b) * c - d
        a, b, c, d = 5, -3, 2, 1
        
        # Encrypt all values
        c_a = self.paillier.encrypt(a)
        c_b = self.paillier.encrypt(b)
        c_c = self.paillier.encrypt(c)
        c_d = self.paillier.encrypt(d)
        
        # Compute (a + b) homomorphically
        c_sum = gmpy2.mul(c_a, c_b)
        c_sum = gmpy2.f_mod(c_sum, self.paillier.usquare)
        
        # Compute (a + b) * c homomorphically
        c_product = gmpy2.powmod(c_sum, c, self.paillier.usquare)
        
        # Compute final result: (a + b) * c - d
        c_d_inv = gmpy2.invert(c_d, self.paillier.usquare)
        c_result = gmpy2.mul(c_product, c_d_inv)
        c_result = gmpy2.f_mod(c_result, self.paillier.usquare)
        
        # Decrypt result
        result, _ = self.paillier.decrypt(c_result)
        
        # Expected result
        expected = (a + b) * c - d
        expected = gmpy2.f_mod(expected, self.paillier.u)
        expected = self.paillier.smod(expected, self.pkey)
        
        print(f"Complex operation: ({a} + {b}) * {c} - {d} = {result} (expected: {expected})")
        self.assertEqual(result, expected,
                       f"Complex operation failed: expected {expected}, got {result}")
    
    def test_encrypt_grad_decrypt_grad(self):
        """Test gradient encryption/decryption functions"""
        print("\n=== Testing Gradient Functions ===")
        
        test_values = [5, -5, 0, 100, -100]
        
        for value in test_values:
            with self.subTest(value=value):
                # Generate random r
                r = self.paillier.gen_r()
                
                # Encrypt gradient
                ciphertext = self.paillier.encrypt_grad([value, r])
                
                # Decrypt gradient
                decrypted_grad = self.paillier.decrypt_grad([None, ciphertext])
                
                print(f"Gradient value: {value}, decrypted: {decrypted_grad[1]}")
                self.assertEqual(value, decrypted_grad[1],
                               f"Gradient test failed for value {value}")


def run_performance_test():
    """Run performance tests"""
    print("\n=== Performance Tests ===")
    
    import time
    
    # Test with different bit lengths
    bit_len = 45
    
    # Initialize Paillier
    start_time = time.time()
    paillier = Paillier(bit_len)
    paillier.key_gen()
    init_time = time.time() - start_time
    
    # Test encryption/decryption speed
    test_value = 42
    iterations = 100
    
    # Encryption test
    start_time = time.time()
    for _ in range(iterations):
        ciphertext = paillier.encrypt(test_value)
    encrypt_time = (time.time() - start_time) / iterations
    
    # Decryption test
    start_time = time.time()
    for _ in range(iterations):
        decrypted, _ = paillier.decrypt(ciphertext)
    decrypt_time = (time.time() - start_time) / iterations
    
    print(f"  Key generation: {init_time:.4f}s")
    print(f"  Encryption: {encrypt_time*1000:.2f}ms per operation")
    print(f"  Decryption: {decrypt_time*1000:.2f}ms per operation")
    print(f"  Decrypted value: {decrypted}")


if __name__ == '__main__':
    # Run unit tests
    print("Starting Paillier Cryptosystem Unit Tests")
    print("=" * 50)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPaillier)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    # Run performance tests
    run_performance_test()
    
    print("\nTesting completed!")
