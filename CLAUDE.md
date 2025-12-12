# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Virtual Hardware Security Module (V-HSM) for CAN Bus security. This repository contains two implementations:

1. **basic/** - Original simple CAN bus simulator with basic ECU emulation
2. **autonomous_controller/** - Full autonomous vehicle system with 9 ECUs (**MAIN PROJECT**)

**HARDWARE DEPLOYMENT:** The autonomous_controller project is deployed on **Raspberry Pi 4 Model B** (4x ARM Cortex-A72 cores) with multi-core architecture and CPU affinity pinning. This is NOT a simulation - it runs on real hardware with:
- Process-per-ECU model (10 processes total)
- CPU core assignment for deterministic performance
- Centralized HSM service on dedicated Core 3
- Hardware-based RNG (Linux getrandom syscall)
- AES-256-GCM hardware-accelerated encryption

## Build and Test Commands

### Autonomous Vehicle System (Main Project - Raspberry Pi 4)

```bash
cd autonomous_controller

# Run complete multi-core system with single command (RECOMMENDED)
cargo run
# This starts:
# - HSM service on Core 3 (dedicated crypto)
# - Bus server on Core 0
# - 9 ECUs on Cores 1-2 with CPU affinity
# - Monitor dashboard on Core 0
# Press 'q' to quit

# Run with HSM performance metrics
cargo run -- --perf

# Build all components (optimized for ARM64)
cargo build --release

# Build specific binaries
cargo build --bin hsm_service          # HSM service (Core 3)
cargo build --bin bus_server           # CAN bus server
cargo build --bin monitor              # Dashboard
cargo build --bin autonomous_controller
cargo build --bin wheel_fl
cargo build --bin brake_controller

# Run tests
cargo test

# Verify CPU affinity (on Pi4)
ps -eLo pid,psr,comm | grep -E "hsm_service|wheel_|engine|autonomous|brake|steering"
# psr column shows which CPU core the process is running on
```

### Basic CAN Bus Simulator

```bash
cd basic

# Build all components
cargo build --release

# Run individual components (multi-terminal mode)
cargo run --bin bus_server    # Start first, runs on 127.0.0.1:9000
cargo run --bin monitor        # Monitor CAN traffic
cargo run --bin input_ecu      # Interactive frame sender
cargo run --bin output_ecu     # Frame receiver

# Quick demo (single process)
cargo run --bin demo
```

## Repository Structure

```
rust-v-hsm-can/
├── basic/               # Original simple implementation
│   ├── src/
│   │   ├── can_bus.rs
│   │   ├── ecu.rs
│   │   ├── network.rs
│   │   └── bin/         # Basic ECU binaries
│   └── Cargo.toml
│
├── autonomous_controller/  # MAIN PROJECT - Autonomous vehicle on Pi4
│   ├── src/
│   │   ├── main.rs                  # Multi-core launcher with CPU affinity
│   │   ├── types.rs                 # Automotive CAN IDs, encoding/decoding
│   │   ├── can_bus.rs
│   │   ├── ecu.rs
│   │   ├── network.rs
│   │   ├── core_affinity_config.rs  # CPU core assignment (Pi4)
│   │   ├── hsm_service/             # Centralized HSM (Unix socket IPC)
│   │   │   ├── mod.rs
│   │   │   ├── protocol.rs          # HsmRequest/HsmResponse
│   │   │   ├── server.rs            # HSM service server
│   │   │   └── client.rs            # HsmClient (IPC wrapper)
│   │   └── bin/
│   │       ├── hsm_service.rs           # HSM service (Core 3)
│   │       ├── bus_server.rs            # CAN bus TCP server (Core 0)
│   │       ├── monitor.rs               # Grouped dashboard (Core 0)
│   │       ├── wheel_fl/fr/rl/rr.rs     # 4x wheel sensors (Core 1)
│   │       ├── engine_ecu.rs            # Engine ECU (Core 1)
│   │       ├── steering_sensor.rs       # Steering sensor (Core 1)
│   │       ├── autonomous_controller.rs # Autonomous brain (Core 2)
│   │       ├── brake_controller.rs      # Brake actuator (Core 2)
│   │       └── steering_controller.rs   # Steering actuator (Core 2)
│   ├── Cargo.toml
│   └── README.md
│
├── CLAUDE.md          # This file
├── CHANGELOG.md
└── README.md
```

## Autonomous Vehicle Architecture (Raspberry Pi 4 Hardware)

**Hardware Platform:**
- **CPU**: 4x ARM Cortex-A72 @ 1.5GHz (ARMv8-A 64-bit)
- **Architecture**: aarch64 (ARM64)
- **OS**: Linux 6.12.34+rpt-rpi-v8

**Multi-Core Assignment:**
```
Core 0: bus_server + monitor          (Infrastructure)
Core 1: 6x sensor ECUs                (Data producers - wheels, engine, steering)
Core 2: 3x controller/actuator ECUs   (Data consumers - autonomous, brake, steering)
Core 3: HSM service                   (Dedicated crypto engine)
```

The autonomous_controller project runs a complete autonomous vehicle on real hardware with:

- **6 Sensor ECUs** (Core 1): 4x wheel speed, engine, steering sensor
- **1 Controller ECU** (Core 2): Autonomous driving controller (receives sensor data, sends control commands)
- **2 Actuator ECUs** (Core 2): Brake controller, steering controller
- **1 HSM Service** (Core 3): Centralized cryptographic operations via Unix socket IPC
- **1 Bus Server** (Core 0): TCP hub for CAN communication (127.0.0.1:9000)
- **1 Monitor** (Core 0): Grouped dashboard showing real-time CAN traffic

### Grouped Dashboard Monitor

The monitor displays CAN traffic organized by function:

1. **SENSORS (Sending)**: Shows latest data from all sensor ECUs
2. **CONTROLLER (Autonomous)**:
   - TX: Commands sent to actuators
   - RX: Sensor data received
3. **ACTUATORS (Receiving)**: Shows commands received by actuators

Features:
- Alternate screen buffer (like vim/htop)
- Rate-limited updates (10 Hz) to prevent scrolling
- Press 'q' to quit and shutdown all components
- Real-time visualization of CAN traffic

## Communication Architecture

Both projects support **two communication modes**:

### 1. In-Process Mode (VirtualCanBus)
- **Location**: [src/can_bus.rs](src/can_bus.rs)
- Uses Tokio broadcast channels for communication
- All ECUs share the same process and memory space
- Used by the `demo` binary for quick testing
- Pattern: ECUs call `bus.send()` and `bus.subscribe()` directly

### 2. Networked Mode (BusClient/BusServer) - DEVELOPMENT/TESTING ONLY

**SECURITY WARNING:** Networked mode is designed for **development and testing only**. Do NOT use in production without additional security measures.

- **Location**: [src/network.rs](src/network.rs) and [src/bin/bus_server.rs](src/bin/bus_server.rs)
- TCP-based communication with JSON-serialized messages
- Bus server runs on port 9000 as central hub (localhost only)
- Each component (monitor, ECUs) connects as a client
- Used by multi-terminal setup for distributed simulation

**Network Security Model:**
- **NO transport-layer authentication** - TCP connections are unauthenticated
- **NO encryption** - Network traffic is plaintext JSON (for debugging/observability)
- **Self-declared ECU names** - Clients register with any name (no verification)
- **Real security boundary**: MAC verification with shared keys (application layer)
  - Even if an attacker connects and spoofs an ECU name, they cannot generate valid MACs without the symmetric key
  - Invalid MACs trigger attack detection and fail-safe mode
- **Defense-in-depth**: Replay protection, access control, and anomaly detection provide additional layers

**Production Recommendations:**
1. **Use in-process mode** (`VirtualCanBus`) for production - eliminates network attack surface
2. **If networked mode is required**, add:
   - TLS with mutual authentication (client certificates)
   - Pre-shared key verification during registration
   - Network segmentation (firewall rules, VLANs)
   - VPN or secure tunnel for inter-ECU communication

**Key distinction**: In-process uses `VirtualCanBus` directly; networked mode uses `BusClient` to communicate with `bus_server` via TCP.

## Core Components

### Data Structures ([src/types.rs](src/types.rs))

- **CanId**: Standard (11-bit) or Extended (29-bit) CAN identifiers
- **CanFrame**: Contains ID, data (0-8 bytes), timestamp, source ECU name
- **EcuConfig**: ECU configuration with name, bus address, ARM variant
- **ArmVariant**: Emulated ARM processors (Cortex-M4, M7, A53)

### VirtualCanBus ([src/can_bus.rs](src/can_bus.rs))

- In-process broadcast implementation
- Uses `tokio::sync::broadcast` channel
- Methods:
  - `send()`: Broadcast CAN frame to all subscribers
  - `subscribe()`: Get a receiver for frames
- **Validation**: Enforces 8-byte maximum data length

### ECU Emulator ([src/ecu.rs](src/ecu.rs))

- Represents an Electronic Control Unit
- Automatically subscribes to VirtualCanBus on creation
- Methods:
  - `send_frame()`: Send CAN frame with automatic source tagging
  - `receive_frame()`: Async receive from bus
  - `try_receive_frame()`: Non-blocking receive

### Network Layer ([src/network.rs](src/network.rs))

**NetMessage**: Serializable enum for TCP communication
- `CanFrame(CanFrame)`: CAN frame data
- `Register { client_name }`: Client registration
- `Ack`: Acknowledgment
- `Error(String)`: Error message

**BusClient**: Full duplex TCP client
- Connects to bus server, sends registration
- Can split into `BusReader` and `BusWriter` for concurrent read/write

**Protocol**: JSON messages with newline delimiters (`\n`)

### Bus Server ([src/bin/bus_server.rs](src/bin/bus_server.rs))

- Central TCP hub for networked mode
- Listens on `127.0.0.1:9000`
- Maintains client registry (`HashMap<String, OwnedWriteHalf>`)
- Broadcasts `SecuredCanFrame` messages to all connected clients (supports legacy `CanFrame` with conversion)
- **Flow**: Client sends secured frame → Server broadcasts to all clients (including monitor)

### Error Handling ([src/error_handling.rs](src/error_handling.rs), [src/hsm/](src/hsm/))

**Structured Error Types**:
- `VerifyError`: Type-safe verification errors (UnsecuredFrame, CrcMismatch, MacMismatch)
- `MacFailureReason`: Distinguishes NoKeyRegistered vs CryptoFailure
- `ValidationError`: Maps VerifyError to AttackDetector error categories

**AttackDetector**: Threshold-based attack detection used by all ECUs
- CRC errors: Tolerates 5 consecutive failures
- MAC errors: Tolerates 3 consecutive failures
- Unsecured frames: Triggers immediately (threshold=1)
- Resets consecutive counters on successful frame validation
- State machine: Normal → Warning → UnderAttack

All ECUs (autonomous_controller, brake_controller, steering_controller) use identical AttackDetector pattern for consistent security enforcement.

## Automotive CAN IDs (autonomous_controller/)

The autonomous vehicle project uses standard automotive CAN ID ranges:

### Sensor Messages (0x100 - 0x1FF)
- 0x100-0x103: Wheel Speed (FL, FR, RL, RR)
- 0x110-0x111: Engine (RPM, Throttle Position)
- 0x120-0x121: Steering (Angle, Torque)

### Control Commands (0x300 - 0x3FF)
- 0x300: Brake Command
- 0x301: Throttle Command
- 0x302: Steering Command

Data encoding/decoding helpers are in [autonomous_controller/src/types.rs](autonomous_controller/src/types.rs)

## Single-Command Launcher (autonomous_controller/)

The main.rs launcher (`cargo run`) provides a streamlined experience:

1. Starts bus_server in background (stdout/stderr suppressed)
2. Launches all 6 sensor ECUs (stdout/stderr suppressed)
3. Starts autonomous_controller (stdout/stderr suppressed)
4. Launches 2 actuator ECUs (stdout/stderr suppressed)
5. Waits 3 seconds for ECUs to connect
6. Starts monitor displaying the grouped dashboard (visible output)
7. Waits for user to press 'q'
8. Cleanly shuts down all background processes

This eliminates the need for 12 separate terminals and provides a clean dashboard view.

## Adding New Features

### Adding a New ECU Type
1. Create new binary in `src/bin/` or use existing ECU binaries
2. Configure `EcuConfig` with unique name and ARM variant
3. For in-process: Create `Ecu::new(config, bus.clone())`
4. For networked: Use `BusClient::connect()` then send/receive via `NetMessage`

### Adding HSM Functionality
The V-HSM component is designed to sit between ECUs and the bus:
1. Intercept CAN frames (subscribe to bus)
2. Apply cryptographic operations (CMAC/HMAC, encryption)
3. Forward authenticated/encrypted frames
4. Implement key management and attack detection

### Modifying CAN Frame Format
- Edit `CanFrame` struct in [src/types.rs](src/types.rs)
- Update `is_valid()` validation logic
- Ensure JSON serialization still works for networked mode

## Network Protocol Details

All network messages follow this pattern:
```
<JSON message>\n
```

Example frame transmission:
```json
{"CanFrame":{"id":{"Standard":123},"data":[1,2,3,4],"timestamp":"2024-01-01T12:00:00Z","source":"INPUT_ECU"}}
```

Registration:
```json
{"Register":{"client_name":"INPUT_ECU"}}
```

## Important Constants

- **BUS_ADDRESS**: `127.0.0.1:9000` (defined in bus_server.rs and client binaries)
- **BUFFER_SIZE**: 1000 frames (bus_server.rs)
- **CAN_DATA_MAX**: 8 bytes (enforced in CanFrame validation)

## Code Style Guidelines

**IMPORTANT**: Do NOT use emojis in terminal output, UI messages, code, or code comments
- Emojis look unprofessional and inconsistent across different terminals
- Use simple ASCII characters instead: `⚠` for warnings, `✓` for success, `✗` for errors, `→` for actions
- Exception: The `ℹ` character is acceptable for informational messages
- Keep terminal output clean and professional

## Testing Requirements

**CRITICAL**: After making ANY code changes, you MUST run the full CI test suite to ensure nothing is broken.

### Quick Start: Run Full CI Suite

```bash
./run_ci_tests.sh
```

This single command runs all 9 test categories (formatting, linting, build, unit tests, integration tests, 4 regression suites) with colored output and comprehensive summary. **Use this before committing any changes.**

### Manual Test Execution (if needed)

Run all CI tests in order:
```bash
# 1. Format check (fails fast)
cargo fmt -- --check

# 2. Linting
cargo clippy -- -D warnings

# 3. Build
cargo build --verbose

# 4. Unit tests (133 tests)
cargo test --workspace --lib --verbose

# 5. Integration tests (14 tests)
cargo test --workspace --test integration_tests --verbose

# 6. Regression tests (run all four suites)
cargo test --package rust-v-hsm-can --test attack_regression_tests -- --ignored --test-threads=1 --nocapture
cargo test --package rust-v-hsm-can --test access_control_regression_tests -- --ignored --test-threads=1 --nocapture
cargo test --package rust-v-hsm-can --test replay_protection_regression_tests -- --ignored --test-threads=1 --nocapture
cargo test --package autonomous_vehicle_sim --test anomaly_ids_regression_tests -- --ignored --test-threads=1 --nocapture
```

**Total Test Count:** 159+ tests

**DO NOT** consider your work complete until all CI tests pass. If any test fails, fix it before moving on.

### Test Design Methodology

**CRITICAL**: After implementing ANY feature, you MUST design and implement comprehensive tests covering:

#### 1. Normal Operation Tests (Should PASS)
- Identify all expected/valid use cases for the feature
- Test typical inputs and common scenarios
- Verify the feature behaves correctly under normal conditions
- Example: Valid CAN frame with correct MAC should be accepted

#### 2. Failure Operation Tests (Should FAIL)
- Identify all invalid/malicious use cases
- Test inputs that should be rejected
- Verify the feature fails gracefully with appropriate errors
- Example: CAN frame with corrupted MAC should be rejected

#### 3. Edge Case Tests (Threshold Boundaries)
- **MOST CRITICAL**: Identify ALL thresholds, limits, and boundary conditions in your implementation
- For each threshold, test BOTH sides of the boundary:
  - **Just below threshold**: Should PASS (or maintain current state)
  - **Exactly at threshold**: Document expected behavior
  - **Just above threshold**: Should FAIL (or transition to new state)

**Threshold Testing Examples:**

```rust
// Example: AttackDetector with MAC error threshold = 3
#[test]
fn test_mac_errors_below_threshold() {
    // 2 consecutive MAC errors (< 3) - should stay in Normal state
    assert_eq!(detector.state(), DetectorState::Normal);
}

#[test]
fn test_mac_errors_at_threshold() {
    // 3 consecutive MAC errors (== 3) - should transition to Warning
    assert_eq!(detector.state(), DetectorState::Warning);
}

#[test]
fn test_mac_errors_above_threshold() {
    // 4+ consecutive MAC errors (> 3) - should be in UnderAttack
    assert_eq!(detector.state(), DetectorState::UnderAttack);
}
```

```rust
// Example: Anomaly detection with 3-sigma threshold (99% confidence)
#[test]
fn test_anomaly_below_threshold() {
    // 2.9 sigma deviation - should return Warning (80-99%)
    assert!(matches!(result, AnomalyResult::Warning(_)));
}

#[test]
fn test_anomaly_at_threshold() {
    // Exactly 3.0 sigma - should return Attack (>99%)
    assert!(matches!(result, AnomalyResult::Attack(_)));
}

#[test]
fn test_anomaly_above_threshold() {
    // 5.0 sigma deviation - should return Attack (>99%)
    assert!(matches!(result, AnomalyResult::Attack(_)));
}
```

#### 4. Test Organization

**Unit Tests** (`#[cfg(test)] mod tests`):
- Test individual functions and methods in isolation
- Cover edge cases and boundary conditions
- Fast execution (< 1ms per test)
- Location: Same file as implementation

**Regression Tests** (`tests/*.rs` with `#[ignore]`):
- End-to-end integration tests
- Simulate real attack scenarios
- Test multi-component interactions
- May take longer to execute
- Location: `tests/` directory

#### 5. Required Test Coverage for New Features

When implementing a new feature, you MUST:

1. **Identify all thresholds**: List every numeric threshold, limit, or boundary condition
2. **Test normal cases**: At least 3 tests for typical valid inputs
3. **Test failure cases**: At least 3 tests for invalid/malicious inputs
4. **Test each threshold**: Minimum 3 tests per threshold (below/at/above)
5. **Document edge cases**: Add comments explaining boundary behavior

**Example Checklist:**
- [ ] Normal operation tests written and passing
- [ ] Failure operation tests written and failing correctly
- [ ] All thresholds identified and documented
- [ ] Edge cases tested (below threshold passes, above threshold fails)
- [ ] Unit tests added to source file
- [ ] Regression tests added if needed
- [ ] Full CI test suite passes

## Development Workflow

**IMPORTANT**: Do not use `git add` or `git commit` on your own. The user will review all changes.

After making code changes:
1. Run the full CI test suite (see Testing Requirements above)
2. Add a very very concise summary of the changes to [CHANGELOG.md](CHANGELOG.md)
3. Do not create new markdown files unless explicitly requested
4. Wait for the user to review and commit

## Anomaly-Based Intrusion Detection System (IDS)

### What is Anomaly-Based IDS?

Anomaly-based IDS detects attacks by identifying deviations from "normal" CAN bus behavior. Unlike signature-based detection (known attack patterns), it uses statistical profiling to establish a baseline of normal operation, then flags behavior that deviates significantly.

**Key Benefits:**
- Detects zero-day attacks and novel attack patterns
- Identifies compromised ECUs with valid credentials
- Catches behavioral anomalies MAC/CRC can't detect
- No machine learning required - simple statistics (mean, std dev)

### How It Works

**1. Factory Calibration (Training Phase)**
```bash
# Run vehicle simulation in background
cargo run &

# Collect baseline (5000+ samples per CAN ID)
cargo run --bin calibrate_anomaly_baseline -- \
    --ecu BRAKE_CTRL \
    --samples 5000 \
    --duration 300 \
    --output baseline_brake_ctrl.json
```

This collects normal CAN traffic and calculates:
- Message frequency statistics (mean interval, std dev)
- Data range statistics (min/max/mean/std dev per byte)
- Expected source ECUs per CAN ID
- Message rate (msgs/second)

**2. Baseline Storage**

Baselines are signed with HSM and saved as JSON:
```json
{
  "baseline": { ... },
  "signature": [u8; 32],
  "fingerprint": [u8; 32]
}
```

- Signature prevents tampering
- Fingerprint verifies baseline integrity
- Uses SHA256 + HMAC-SHA256

**3. Production Deployment**

ECUs load baseline on boot:
```rust
// In brake_controller.rs
let baseline = baseline_persistence::load_baseline("baseline_brake_ctrl.json", &hsm)?;
hsm.load_anomaly_baseline(baseline)?;
```

**4. Detection Phase**

After successful MAC/CRC verification, HSM detects anomalies:
```rust
let anomaly_result = hsm.detect_anomaly(&secured_frame);
match anomaly_result {
    AnomalyResult::Normal => { /* Process normally */ }
    AnomalyResult::Warning(report) => { /* 80-99% confidence - log warning */ }
    AnomalyResult::Attack(report) => { /* >99% confidence - reject frame */ }
}
```

### Graduated Response Levels

| Confidence | Sigma (σ) | Action | Use Case |
|------------|-----------|--------|----------|
| < 80% | < 1.3σ | **ALLOW** | Within normal variance |
| 80-99% | 1.3-3σ | **WARNING** | Unusual but tolerable, log for investigation |
| > 99% | > 3σ | **ATTACK** | High confidence anomaly, trigger fail-safe |

### Anomaly Types Detected

1. **Unknown CAN ID**: Message on CAN ID not seen during training
2. **Unexpected Source**: ECU sending on CAN ID it doesn't normally use
3. **Interval Anomaly**: Message arriving too fast/slow (frequency)
4. **Rate Anomaly**: Too many/few messages per second
5. **Data Range Anomaly**: Byte value outside expected range (e.g., wheel speed > 300 rad/s)

### Retraining Baselines

**When to retrain:**
- Vehicle configuration changes (new ECU, software update)
- Operational mode changes (city vs highway profiles)
- After maintenance/repairs

**How to retrain:**
1. Run calibration tool in controlled environment
2. Verify baseline with test scenarios
3. Sign with HSM
4. Deploy to production ECUs

**Security Note:** Always train in secure factory/lab environment. Never retrain in production - this creates attack vector during startup.

### Integration Points

**Location**: `src/anomaly_detection.rs`, `src/baseline_persistence.rs`

**ECU Integration**:
- Brake Controller: `src/bin/brake_controller.rs:44-67, 156-197`
- Steering Controller: `src/bin/steering_controller.rs:53-76, 164-206`
- Autonomous Controller: `src/bin/autonomous_controller.rs:69-92, 193-235`

**HSM Methods**:
- `hsm.load_anomaly_baseline()` - Load pre-trained baseline
- `hsm.start_anomaly_training()` - Start training mode (factory only)
- `hsm.detect_anomaly()` - Detect anomalies in frame

### Testing

**Unit Tests**: `cargo test --lib anomaly_detection` (9 tests)
**Regression Tests**: `cargo test --test anomaly_ids_regression_tests -- --ignored` (3 tests)

