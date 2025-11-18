#!/bin/bash
# Full CI Test Suite Runner
# Run this script locally before pushing to ensure all CI tests will pass

set -e  # Exit on first failure

echo "═══════════════════════════════════════════════════════════════════════════"
echo "                   RUST V-HSM CAN - LOCAL CI TEST SUITE"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILED=0

# Function to print test status
print_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $1"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}: $1"
        FAILED=1
        return 1
    fi
}

# Test 1: Code Formatting
echo "→ Running rustfmt..."
cargo fmt -- --check
print_status "Code Formatting"
echo ""

# Test 2: Clippy Linting
echo "→ Running clippy..."
cargo clippy -- -D warnings
print_status "Clippy Linting"
echo ""

# Test 3: Build
echo "→ Building project..."
cargo build --verbose
print_status "Build"
echo ""

# Test 4: Unit Tests
echo "→ Running unit tests..."
cargo test --workspace --lib --verbose
UNIT_RESULT=$?
print_status "Unit Tests"
echo ""

# Test 5: Integration Tests
echo "→ Running integration tests..."
cargo test --workspace --test integration_tests --verbose
INTEGRATION_RESULT=$?
print_status "Integration Tests"
echo ""

# Test 6: Binary Tests (Monitor UI)
echo "→ Running binary tests (monitor UI)..."
cargo test --package autonomous_vehicle_sim --bin monitor --verbose
MONITOR_RESULT=$?
print_status "Monitor UI Tests"
echo ""

# Test 7: Attack Detection Regression Tests
echo "→ Running attack detection regression tests..."
cargo test --package rust-v-hsm-can --test attack_regression_tests -- --ignored --test-threads=1 --nocapture
ATTACK_RESULT=$?
print_status "Attack Detection Tests"
echo ""

# Test 8: Access Control Regression Tests
echo "→ Running access control regression tests..."
cargo test --package rust-v-hsm-can --test access_control_regression_tests -- --ignored --test-threads=1 --nocapture
ACCESS_RESULT=$?
print_status "Access Control Tests"
echo ""

# Test 9: Replay Protection Regression Tests
echo "→ Running replay protection regression tests..."
cargo test --package rust-v-hsm-can --test replay_protection_regression_tests -- --ignored --test-threads=1 --nocapture
REPLAY_RESULT=$?
print_status "Replay Protection Tests"
echo ""

# Test 10: Anomaly IDS Regression Tests
echo "→ Running anomaly IDS regression tests..."
cargo test --package autonomous_vehicle_sim --test anomaly_ids_regression_tests -- --ignored --test-threads=1 --nocapture
ANOMALY_RESULT=$?
print_status "Anomaly IDS Tests"
echo ""

# Final Summary
echo "═══════════════════════════════════════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}                        ALL TESTS PASSED ✓${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "You are ready to push your changes!"
    echo ""
    exit 0
else
    echo -e "${RED}                     SOME TESTS FAILED ✗${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Please fix the failing tests before pushing."
    echo ""
    exit 1
fi
