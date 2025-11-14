# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Virtual Hardware Security Module (V-HSM) for CAN Bus security. This repository contains two implementations:

1. **basic/** - Original simple CAN bus simulator with basic ECU emulation
2. **autonomous_controller/** - Full autonomous vehicle simulation with 9 ECUs (**MAIN PROJECT**)

The autonomous_controller project is the primary focus, featuring a realistic automotive system with sensor ECUs, an autonomous driving controller, and actuator ECUs communicating over a virtual CAN bus.

## Build and Test Commands

### Autonomous Vehicle Simulation (Main Project)

```bash
cd autonomous_controller

# Run complete simulation with single command (RECOMMENDED)
cargo run
# This starts all 9 ECUs and displays a grouped dashboard
# Press 'q' to quit

# Build all components
cargo build --release

# Build specific binaries
cargo build --bin bus_server
cargo build --bin monitor
cargo build --bin autonomous_controller
cargo build --bin wheel_fl
cargo build --bin brake_controller

# Run tests
cargo test
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
├── autonomous_controller/  # MAIN PROJECT - Autonomous vehicle simulation
│   ├── src/
│   │   ├── main.rs         # Single-command launcher
│   │   ├── types.rs        # Automotive CAN IDs, encoding/decoding
│   │   ├── can_bus.rs
│   │   ├── ecu.rs
│   │   ├── network.rs
│   │   └── bin/
│   │       ├── bus_server.rs            # CAN bus TCP server
│   │       ├── monitor.rs               # Grouped dashboard monitor
│   │       ├── wheel_fl/fr/rl/rr.rs     # 4x wheel speed sensors
│   │       ├── engine_ecu.rs            # Engine ECU
│   │       ├── steering_sensor.rs       # Steering sensor
│   │       ├── autonomous_controller.rs # Autonomous brain
│   │       ├── brake_controller.rs      # Brake actuator
│   │       └── steering_controller.rs   # Steering actuator
│   ├── Cargo.toml
│   └── README.md
│
├── CLAUDE.md          # This file
├── CHANGELOG.md
└── README.md
```

## Autonomous Vehicle Architecture

The autonomous_controller project simulates a complete autonomous vehicle with:

- **6 Sensor ECUs**: 4x wheel speed, engine, steering sensor
- **1 Controller ECU**: Autonomous driving controller (receives sensor data, sends control commands)
- **2 Actuator ECUs**: Brake controller, steering controller
- **1 Bus Server**: TCP hub for CAN communication (127.0.0.1:9000)
- **1 Monitor**: Grouped dashboard showing real-time CAN traffic

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

### 2. Networked Mode (BusClient/BusServer)
- **Location**: [src/network.rs](src/network.rs) and [src/bin/bus_server.rs](src/bin/bus_server.rs)
- TCP-based communication with JSON-serialized messages
- Bus server runs on port 9000 as central hub
- Each component (monitor, ECUs) connects as a client
- Used by multi-terminal setup for distributed simulation

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

### Error Handling ([src/error_handling.rs](src/error_handling.rs), [src/hsm.rs](src/hsm.rs))

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

Run all CI tests in order:
```bash
# 1. Format check (fails fast)
cargo fmt -- --check

# 2. Linting
cargo clippy -- -D warnings

# 3. Build
cargo build --verbose

# 4. Unit tests
cargo test --workspace --lib --verbose

# 5. Regression tests (run all three)
cargo test --test attack_regression_tests -- --ignored --test-threads=1 --nocapture
cargo test --test access_control_regression_tests -- --ignored --test-threads=1 --nocapture
cargo test --test replay_protection_regression_tests -- --ignored --test-threads=1 --nocapture
```

**DO NOT** consider your work complete until all CI tests pass. If any test fails, fix it before moving on.

## Development Workflow

**IMPORTANT**: Do not use `git add` or `git commit` on your own. The user will review all changes.

After making code changes:
1. Run the full CI test suite (see Testing Requirements above)
2. Add a very very concise summary of the changes to [CHANGELOG.md](CHANGELOG.md)
3. Do not create new markdown files unless explicitly requested
4. Wait for the user to review and commit
