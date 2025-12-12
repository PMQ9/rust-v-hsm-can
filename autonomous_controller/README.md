# Autonomous Vehicle CAN Bus System

**Running on Raspberry Pi 4 Hardware**

A realistic CAN bus implementation for autonomous vehicle development and security research, deployed on **Raspberry Pi 4** with multi-core architecture. This project demonstrates a complete autonomous vehicle system with sensor ECUs, actuator controllers, and an autonomous driving controller communicating over a virtual CAN bus with hardware security.

## Hardware Platform

**Raspberry Pi 4 Model B**
- **CPU**: 4x ARM Cortex-A72 @ 1.5GHz (ARMv8-A 64-bit)
- **Architecture**: aarch64 (ARM64)
- **Memory**: 4GB LPDDR4-3200
- **OS**: Linux 6.12.34+rpt-rpi-v8

## Multi-Core Architecture

**Process-per-ECU model with CPU affinity pinning:**

```
┌──────────────────────────────────────────────────────────────────┐
│  Raspberry Pi 4: 4x ARM Cortex-A72 Cores                         │
├──────────┬──────────┬──────────┬────────────────────────────────┤
│  Core 0  │  Core 1  │  Core 2  │         Core 3                 │
│          │          │          │                                │
│  Bus     │ Sensors  │ Controls │  HSM Service (Crypto Engine)   │
│  Server  │  (TX)    │ (TX+RX)  │  ┌──────────────────────────┐  │
│          │          │          │  │ • MAC generation/verify  │  │
│  Monitor │ 6 ECUs:  │ 3 ECUs:  │  │ • CRC calculation/verify │  │
│          │ • Wheels │ • Auto   │  │ • Replay protection      │  │
│          │   (4x)   │   Ctrl   │  │ • Anomaly detection      │  │
│          │ • Engine │ • Brake  │  │ • Session counters       │  │
│          │ • Steer  │   Ctrl   │  │ • Access control         │  │
│          │   Sensor │ • Steer  │  │ • AES-256-GCM crypto     │  │
│          │          │   Ctrl   │  │ • Hardware RNG           │  │
│          │          │          │  └──────────────────────────┘  │
└──────────┴──────────┴──────────┴────────────────────────────────┘
           │          │          │            │
           └──────────┴──────────┴────────────┘
                      │
           ┌──────────▼──────────┐
           │   CAN BUS SERVER    │
           │  (127.0.0.1:9000)   │
           │  TCP Broadcast Hub  │
           └─────────────────────┘
```

**IPC Architecture:**
- ECUs communicate via TCP (CAN bus server)
- HSM service uses Unix Domain Sockets (`/tmp/vsm_hsm_service.sock`)
- All ECUs connect to centralized HSM service for cryptographic operations
- Typical HSM latency: 35-70µs (including IPC overhead)

## ECU Components

### Infrastructure
- **bus_server**: Central TCP hub for CAN communication (port 9000)
- **monitor**: Real-time CAN traffic monitor with message decoding

### Sensor ECUs (Broadcast periodic data)
- **wheel_fl**: Front Left wheel speed sensor (10 Hz)
- **wheel_fr**: Front Right wheel speed sensor (10 Hz)
- **wheel_rl**: Rear Left wheel speed sensor (10 Hz)
- **wheel_rr**: Rear Right wheel speed sensor (10 Hz)
- **engine_ecu**: Engine RPM and throttle position (20 Hz)
- **steering_sensor**: Steering angle and torque (20 Hz)

### Controller ECU (Decision-making)
- **autonomous_controller**: Processes sensor data and generates control commands (10 Hz)
  - Reads: Wheel speeds, engine state, steering state
  - Outputs: Brake, throttle, and steering commands
  - Features: Speed control, anomaly detection, simple path following

### Actuator ECUs (Execute commands)
- **brake_controller**: Receives and executes brake commands
  - Safety features: Pressure limiting, rapid release warnings
- **steering_controller**: Receives and executes steering commands
  - Safety features: Rate limiting, angle constraints, sensor feedback validation

## CAN Message IDs

### Sensor Messages (0x100 - 0x1FF)
| ID    | Message Type        | DLC | Rate  |
|-------|-------------------- |-----|-------|
| 0x100 | Wheel Speed FL      | 2   | 10 Hz |
| 0x101 | Wheel Speed FR      | 2   | 10 Hz |
| 0x102 | Wheel Speed RL      | 2   | 10 Hz |
| 0x103 | Wheel Speed RR      | 2   | 10 Hz |
| 0x110 | Engine RPM          | 2   | 20 Hz |
| 0x111 | Engine Throttle Pos | 1   | 20 Hz |
| 0x120 | Steering Angle      | 2   | 20 Hz |
| 0x121 | Steering Torque     | 2   | 20 Hz |

### Control Messages (0x300 - 0x3FF)
| ID    | Message Type        | DLC | Rate       |
|-------|-------------------- |-----|------------|
| 0x300 | Brake Command       | 1   | 10 Hz      |
| 0x301 | Throttle Command    | 1   | 10 Hz      |
| 0x302 | Steering Command    | 2   | 10 Hz      |

## Quick Start (Raspberry Pi 4)

**Hardware Deployment with Multi-Core Processing:**

All ECUs use a **centralized Virtual-HSM service** running on dedicated Core 3 with:
- **MAC**: HMAC-SHA256 message authentication
- **CRC**: CRC32 integrity verification
- **Replay Protection**: Sliding window + timestamp validation (100-counter window, 60s max age)
- **Secure Boot**: Firmware signature verification
- **Protected Memory**: Simulated MPU-protected firmware storage
- **Hardware RNG**: Linux getrandom syscall (cryptographically secure)
- **AES-256-GCM**: Hardware-accelerated encryption
- **CPU Affinity**: Process pinning for deterministic performance

### HSM Cryptographic Keys

Each ECU's HSM contains the following 256-bit keys:

| Key Name | Purpose |
|----------|---------|
| **Master Key** | Root key for deriving other keys (key hierarchy root) |
| **Secure Boot Key** | Signs/verifies firmware fingerprints during secure boot |
| **Firmware Update Key** | Authorizes firmware update operations |
| **Symmetric Comm Key** | Generates HMAC-SHA256 MACs for CAN message authentication |
| **Key Encryption Key** | Encrypts keys during secure key exchange/provisioning |
| **RNG Seed Key** | Seeds deterministic RNG for nonces and challenges |
| **Seed/Key Access Token** | Authorization token for diagnostic seed/key access |
| **MAC Verification Keys** | Per-ECU keys for verifying MACs from trusted ECUs |

**Key Distribution**: In this simulation, ECUs share symmetric communication keys to verify each other's MACs. In production, keys would be provisioned during manufacturing and stored in tamper-resistant hardware.

### Single Command Launch (Recommended)

```bash
cd autonomous_controller
cargo run              # Standard mode
cargo run -- --perf    # With HSM performance metrics
```

This automatically launches the complete multi-core system:
1. **Core 3**: Start HSM service (dedicated crypto engine)
2. **Core 0**: Start CAN bus server (TCP hub)
3. **Core 1**: Launch 6 sensor ECUs (wheels, engine, steering)
4. **Core 2**: Launch 3 controller ECUs (autonomous, brake, steering)
5. **Core 0**: Display real-time dashboard with security metrics

**Press 'q' to quit** - all components will shut down cleanly with proper core cleanup.

**Performance Monitoring:**
- Use `htop` or `ps -eLo pid,psr,comm` to verify CPU affinity
- Monitor HSM service performance in `--perf` mode
- Typical system throughput: >10,000 CAN messages/second

### Build All Components

```bash
cd autonomous_controller
cargo build --release
```

### Running the Complete System (Multi-Terminal)

You need **at least 12 terminals** for the full system. Start them in this order:

#### Terminal 1: Bus Server (Required)
```bash
cargo run --bin bus_server
```

#### Terminal 2: Monitor (Recommended)
```bash
cargo run --bin monitor
# Press 'q' to quit
```

#### Terminals 3-8: Sensor ECUs
```bash
# Terminal 3
cargo run --bin wheel_fl

# Terminal 4
cargo run --bin wheel_fr

# Terminal 5
cargo run --bin wheel_rl

# Terminal 6
cargo run --bin wheel_rr

# Terminal 7
cargo run --bin engine_ecu

# Terminal 8
cargo run --bin steering_sensor
```

#### Terminal 9: Autonomous Controller
```bash
cargo run --bin autonomous_controller
```

#### Terminals 10-11: Actuator Controllers
```bash
# Terminal 10
cargo run --bin brake_controller

# Terminal 11
cargo run --bin steering_controller
```

## Dashboard Features

The grouped dashboard monitor displays:

```
SENSORS (Sending):
  - 4x Wheel Speed Sensors (FL, FR, RL, RR)
  - Engine ECU (RPM and throttle)
  - Steering Sensor (angle and torque)

CONTROLLER (Autonomous):
  → Commands Sent:
    - Brake commands
    - Throttle commands
    - Steering commands
  ← Sensor Data Received (sample):
    - Latest wheel speed
    - Latest engine data

ACTUATORS (Receiving):
  - Brake Controller
  - Steering Controller
```

Each line shows:
- ECU name
- CAN ID
- Decoded message data
- Timestamp

The display updates in real-time (10 Hz) showing the most current data from each ECU.

## Data Encoding

### Wheel Speed (2 bytes)
- Range: 0-655.35 rad/s
- Resolution: 0.01 rad/s
- Format: Big-endian u16 (value * 100)

### Engine RPM (2 bytes)
- Range: 0-16383 RPM
- Resolution: 0.25 RPM
- Format: Big-endian u16 (value * 4)

### Throttle/Brake (1 byte)
- Range: 0-100%
- Resolution: 1%
- Format: u8

### Steering Angle (2 bytes)
- Range: -780° to +780°
- Resolution: 0.1°
- Format: Big-endian u16 ((value + 780) * 10)

### Steering Torque (2 bytes)
- Range: -32 to +32 Nm
- Resolution: 0.001 Nm
- Format: Big-endian u16 ((value + 32) * 1000)

## Structure

```
autonomous_controller/
├── src/
│   ├── lib.rs              # Library exports
│   ├── types.rs            # CAN types, IDs, encoding functions
│   ├── can_bus.rs          # Virtual CAN bus implementation
│   ├── ecu.rs              # ECU emulator
│   ├── network.rs          # TCP networking layer
│   └── bin/
│       ├── bus_server.rs            # CAN bus server
│       ├── monitor.rs               # Traffic monitor
│       ├── wheel_fl.rs              # Front left wheel
│       ├── wheel_fr.rs              # Front right wheel
│       ├── wheel_rl.rs              # Rear left wheel
│       ├── wheel_rr.rs              # Rear right wheel
│       ├── engine_ecu.rs            # Engine control
│       ├── steering_sensor.rs       # Steering sensors
│       ├── autonomous_controller.rs # Autonomous brain
│       ├── brake_controller.rs      # Brake actuator
│       └── steering_controller.rs   # Steering actuator
├── Cargo.toml
└── README.md
```

## Message Flow Example

```
1. Wheel Sensors → CAN Bus: Broadcast wheel speeds (0x100-0x103)
2. Engine ECU → CAN Bus: Broadcast RPM and throttle (0x110-0x111)
3. Steering Sensor → CAN Bus: Broadcast angle and torque (0x120-0x121)
4. Autonomous Controller:
   - Reads all sensor messages
   - Computes control commands
   - Sends brake command (0x300)
   - Sends throttle command (0x301)
   - Sends steering command (0x302)
5. Brake Controller: Receives 0x300, actuates brakes
6. Steering Controller: Receives 0x302, actuates steering
7. Monitor: Observes all traffic, decodes and displays
```

## Security Features

### Message Authentication Flow

1. **Sending**: ECU creates CAN frame → HSM generates MAC (HMAC-SHA256) + CRC32 → SecuredCanFrame broadcast
2. **Receiving**: ECU receives SecuredCanFrame → HSM verifies CRC32 (fast check) → HSM verifies MAC (cryptographic) → Accept/Reject
3. **Anti-Replay**: Each message includes a session counter to prevent replay attacks

### Secure Boot Process

Each ECU performs secure boot on startup:
1. Load firmware binary from protected memory
2. Calculate SHA256 fingerprint of firmware
3. Verify HMAC signature using Secure Boot Key
4. If valid, execute firmware; if invalid, halt

### CAN ID Access Control (ISO 21434)

Each ECU has a whitelist defining which CAN IDs it can transmit/receive. HSM enforces authorization before creating or accepting frames.

**Policy enforcement**: TX whitelist (mandatory), RX whitelist (optional filtering)
**Example**: WHEEL_FL can only transmit on 0x100, ENGINE_ECU only on 0x110-0x111

Unauthorized access attempts trigger immediate fail-safe mode and security logging.

### Security Event Logging (ISO 21434)

All ECUs maintain tamper-resistant security logs using chained SHA256 hashing. Each entry includes the hash of the previous entry, making tampering detectable.

**Logged events**: System startup, verification failures, state changes, attacks, frame rejections, fail-safe activations, unauthorized access attempts

**Analyze logs**:
```bash
cargo run --bin security_log_analyzer security_logs/AUTONOMOUS_CTRL_*.jsonl
```

The analyzer verifies hash integrity, chain continuity, and detects tampering. Provides event statistics, attack summaries, and timeline analysis.

## Future Enhancements

- [x] V-HSM integration for message authentication
- [x] Cryptographic key management
- [ ] Attack scenario scripts (replay, spoofing, DoS)
- [ ] Performance metrics and logging
- [ ] GUI-based monitor
- [ ] CAN FD support
- [ ] ISO-TP multi-frame messages

## Dependencies

- **tokio**: Async runtime
- **serde**: Serialization
- **chrono**: Timestamps
- **colored**: Terminal colors
- **crossterm**: Terminal UI

**Note**: This is a simulation. Real automotive systems require ISO 26262 safety validation and extensive testing.
