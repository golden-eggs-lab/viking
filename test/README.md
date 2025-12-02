# ComparativeMixnetID Test Suite

This test suite provides comprehensive testing for the ComparativeMixnetID functionality, including the Paillier->ElGamal->Rerandomize->Decrypt encryption chain used in the deduplication process.

## Test Files

### 1. `test_comparative_mixnet_id.py`
**Comprehensive unit test suite** using Python's unittest framework
- Tests empty heap scenarios
- Tests non-empty heap scenarios  
- Tests middle worker processing
- Tests last worker duplicate detection
- Tests last worker new ID detection
- Tests Paillier->ElGamal->Rerandomize->Decrypt process
- Tests multiple entries processing
- Tests performance timing

### 2. `test_encryption_chain.py`
**Focused test for encryption/decryption chain**
- Tests Paillier->ElGamal->Rerandomize->Decrypt process
- Tests ID comparison simulation
- Tests equality check generation
- Detailed step-by-step verification

### 3. `test_worker_roles.py`
**Worker role-specific tests**
- Tests first worker scenarios (empty/non-empty heap)
- Tests middle worker processing
- Tests last worker scenarios (duplicate/new ID detection)
- Tests complete encryption/decryption chain

### 4. `test_three_worker_flow.py`
**Complete 3-worker flow test**
- Tests ID encrypted by all 3 workers' ElGamal public keys
- Tests each worker's specific ComparativeMixnetID operation
- Tests complete encryption/decryption chain through all workers
- Tests duplicate ID detection in real scenario
- Tests multiple scenarios with different IDs and values

### 5. `run_tests.py`
**Test runner script** for easy execution
- Run all tests or specific test suites
- Provides summary of results
- Handles timeouts and errors

## Usage

### Run All Tests
```bash
cd test
python run_tests.py --test all
```

### Run Specific Test Suite
```bash
# Run comprehensive unit tests
python run_tests.py --test comprehensive

# Run encryption chain tests
python run_tests.py --test encryption

# Run worker role tests
python run_tests.py --test workers

# Run 3-worker flow tests
python test_three_worker_flow.py
```

### Run Individual Test Files
```bash
# Run comprehensive unit tests
python test_comparative_mixnet_id.py

# Run encryption chain tests
python test_encryption_chain.py

# Run worker role tests
python test_worker_roles.py

# Run 3-worker flow tests
python test_three_worker_flow.py
```

## Test Scenarios Covered

### 1. First Worker Tests
- **Empty Heap**: Tests behavior when ID_store.heap is empty
- **Non-Empty Heap**: Tests comparison with existing entries in heap
- **Multiple Entries**: Tests processing multiple entries simultaneously

### 2. Middle Worker Tests
- **Processing**: Tests decryption, re-encryption, and re-randomization
- **Comparison Data**: Tests handling of comparison data from first worker

### 3. Last Worker Tests
- **Duplicate Detection**: Tests detection of duplicate IDs (m_rec == 1)
- **New ID Detection**: Tests detection of new IDs (m_rec != 1)
- **Break Logic**: Tests the break logic when duplicates are found

### 4. Encryption Chain Tests
- **Paillier Encryption**: Tests Paillier encryption of values
- **ElGamal Encryption**: Tests ElGamal encryption of Paillier results
- **Rerandomization**: Tests the rerandomization process
- **Decryption**: Tests ElGamal and Paillier decryption
- **End-to-End**: Tests complete encryption/decryption chain

## Key Features Tested

### Cryptographic Operations
- Paillier encryption/decryption
- ElGamal encryption/decryption
- Re-encryption with sk_2
- Re-randomization with random values
- Equality check generation

### ID Comparison Logic
- Inverse calculation (gr_inv, m_inv)
- Multiplication and modular operations
- Decryption of comparison results
- Duplicate detection (m_rec == 1)
- New ID detection (m_rec != 1)

### Worker Role Behavior
- First worker: Empty vs non-empty heap handling
- Middle worker: Processing comparison data
- Last worker: Final duplicate/new ID determination

## Expected Output

### Successful Test Run
```
ComparativeMixnetID Test Runner
============================================================

============================================================
RUNNING: Comprehensive ComparativeMixnetID Test Suite
============================================================
✓ Empty heap test passed: newID=True, noEncID=123
✓ Non-empty heap test passed: comparisons=2
✓ Middle worker test passed: processed 2 entries
✓ Last worker duplicate detection test passed
✓ Last worker new ID detection test passed
✓ Full encryption/decryption process test passed: 42 -> 42
✓ Multiple entries processing test passed: processed 5 entries
✓ Performance test completed in 0.0234 seconds

============================================================
TEST SUMMARY
============================================================
Tests run: 3
Tests passed: 3
Tests failed: 0
✓ ALL TESTS PASSED!
```

### Test Structure
Each test file includes:
- Detailed logging of each step
- Verification of expected results
- Error handling and reporting
- Performance timing
- Clear pass/fail indicators

## Dependencies

The tests require the following modules from the src directory:
- `messages.py` (EntryStorage class)
- `mixnet_helper.py` (Mixnet class)
- `security/elgamal.py` (ElGamal class)
- `security/paillier.py` (Paillier class)
- `mixnet_heap.py` (SecureTopKHeap class)

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure the src directory is in the Python path
2. **Cryptographic Errors**: Check that ElGamal and Paillier parameters are valid
3. **Timeout Errors**: Some tests may take longer with larger key sizes

### Debug Mode
Add debug prints to see detailed intermediate values:
```python
print(f"DEBUG: gr_inv={gr_inv}, m_inv={m_inv}")
print(f"DEBUG: grT={grT}, mT={mT}")
print(f"DEBUG: comparison_decrypted={comparison_decrypted}")
```

## Contributing

When adding new tests:
1. Follow the existing test structure
2. Include detailed logging
3. Test both success and failure cases
4. Add performance timing where appropriate
5. Update this README with new test descriptions
