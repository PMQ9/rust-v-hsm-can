# Tests

## Integration Tests

**File**: [integration_tests.rs](integration_tests.rs)

Basic CAN bus communication tests:
- Single ECU communication
- Multiple ECU communication
- Bus capacity limits

Run: `cargo test`

## Attack Regression Tests

**File**: [attack_regression_tests.rs](attack_regression_tests.rs)

Validates MAC error threshold detection with realistic CAN traffic:

- **Short cycle attack** (2 frames/cycle): Should NOT trigger attack mode
- **Burst attack** (4 frames/cycle): Should trigger attack mode

Run: `cargo test --test attack_regression_tests -- --ignored --test-threads=1`

### Test Architecture

Each test spawns isolated processes:
1. Bus server (TCP hub)
2. Brake controller (monitors for attacks)
3. Legitimate sender (sends valid brake commands at 10Hz)
4. Attack binary (injects malicious frames)

The legitimate sender is critical - it resets consecutive error counters between attack cycles, allowing the short cycle attack to stay below the 3-frame MAC error threshold.
