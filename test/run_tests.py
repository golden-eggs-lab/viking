#!/usr/bin/env python3
"""
Test runner for ComparativeMixnetID tests
Run all tests or specific test suites
"""

import sys
import os
import subprocess
import argparse

def run_test(test_file, description):
    """Run a specific test file"""
    print(f"\n{'='*60}")
    print(f"RUNNING: {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=True, text=True, timeout=60)
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        if result.returncode == 0:
            print(f"✓ {description} PASSED")
            return True
        else:
            print(f"✗ {description} FAILED (exit code: {result.returncode})")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"✗ {description} TIMED OUT")
        return False
    except Exception as e:
        print(f"✗ {description} ERROR: {e}")
        return False

def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description='Run ComparativeMixnetID tests')
    parser.add_argument('--test', choices=['all', 'comprehensive', 'encryption', 'workers', 'three-worker', 'simplified'], 
                       default='all', help='Which test to run')
    
    args = parser.parse_args()
    
    # Get test directory
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define tests
    tests = {
        'comprehensive': {
            'file': os.path.join(test_dir, 'test_comparative_mixnet_id.py'),
            'description': 'Comprehensive ComparativeMixnetID Test Suite'
        },
        'encryption': {
            'file': os.path.join(test_dir, 'test_encryption_chain.py'),
            'description': 'Paillier->ElGamal->Rerandomize->Decrypt Chain Test'
        },
        'workers': {
            'file': os.path.join(test_dir, 'test_worker_roles.py'),
            'description': 'Worker Role Scenarios Test'
        },
        'three-worker': {
            'file': os.path.join(test_dir, 'test_three_worker_flow.py'),
            'description': 'Complete 3-Worker Flow Test'
        },
        'simplified': {
            'file': os.path.join(test_dir, 'test_simplified_three_worker.py'),
            'description': 'Simplified 3-Worker Flow Test'
        }
    }
    
    print("ComparativeMixnetID Test Runner")
    print("=" * 60)
    
    success_count = 0
    total_count = 0
    
    if args.test == 'all':
        # Run all tests
        for test_name, test_info in tests.items():
            total_count += 1
            if run_test(test_info['file'], test_info['description']):
                success_count += 1
    else:
        # Run specific test
        if args.test in tests:
            total_count = 1
            test_info = tests[args.test]
            if run_test(test_info['file'], test_info['description']):
                success_count = 1
        else:
            print(f"Unknown test: {args.test}")
            return 1
    
    # Print summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {total_count}")
    print(f"Tests passed: {success_count}")
    print(f"Tests failed: {total_count - success_count}")
    
    if success_count == total_count:
        print("✓ ALL TESTS PASSED!")
        return 0
    else:
        print("✗ SOME TESTS FAILED!")
        return 1

if __name__ == '__main__':
    sys.exit(main())
