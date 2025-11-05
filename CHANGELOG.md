# Changelog

## 2025-11-05

### Attack Fallback - Autonomous Controller Shutdown
- Implemented automatic controller deactivation when attack is detected
- **Safe Mode Features**:
  - Controller STOPS sending all commands (brake, throttle, steering) when attack detected
  - Continues monitoring sensor inputs but takes NO ACTION
  - Requires manual restart to resume operation
- **Thread-safe attack detection**: Uses AtomicBool for real-time coordination between receiver and control loop
- **Safety-first design**: Prevents compromised commands from reaching actuators

### Unsecured Frame Attack Detection
- Enhanced attack detection to identify frames with MAC=0 as unsecured frame injection attacks
- **Monitor displays real-time attack**:
  - Provides immediate visual feedback during injection attacks
  - Attack type: "Unsecured Frame Injection"
  - Source ECU identification

### Attack Detection and Error Handling
- Created comprehensive `error_handling` module with `AttackDetector` for CAN bus security monitoring
- Implemented intelligent error tolerance with configurable thresholds:
  - CRC errors: Allow 5 consecutive failures (tolerance for signal degradation/noise)
  - MAC errors: Allow 3 consecutive failures (stricter for cryptographic failures)
- Three-tier security state machine: Normal → Warning → Under Attack
- Automatic error counter reset on successful frame validation (recovery from transient errors)

### Attack Scenario Scripts
- Added four educational attack scenario scripts for security testing:
  - `attack_injection`: Demonstrates malicious frame injection (fake sensor data)
  - `attack_replay`: Captures and replays CAN frames at inappropriate times
  - `attack_flooding`: Bus flooding/DoS attack with high-volume traffic
  - `attack_spoofing`: ECU impersonation with malicious control commands
- Purpose: Test HSM security features and demonstrate CAN bus vulnerabilities

### Monitor Display Improvements
- Added raw data column showing 4 blocks of 2 bytes (standard CAN format)
- Fixed column alignment across all sections

### Fixed Monitor Stopping at ~14k Frames
- Removed mutex contention during network I/O in bus_server (each client owns its writer)
- Added broadcast lag recovery
- Increased buffer sizes (bus: 10k, monitor: 1k)

### SecuredCanFrame Support
- Bus server broadcasts `SecuredCanFrame` instead of `CanFrame`
- Actuator ECUs filter frames by CAN ID before verification

### HSM Security Migration Complete
- All 9 ECUs use HSM with HMAC-SHA256 MAC and CRC32 verification
- Monitor displays security status with CRC/MAC values

### Virtual HSM Implementation
- Key management: MasterKey, SecureBootKey, SymmetricCommKey, etc.
- HMAC-SHA256 MAC generation with anti-replay counters
- CRC32 integrity checking
- Secure boot with firmware signature verification
- Protected memory system (simulated MPU)
- All ECUs perform secure boot before operation

## 2025-11-04

### Enhanced dashboard and single-command launcher
- Implemented grouped dashboard monitor with functional organization:
  - SENSORS section: Shows latest data from all sensor ECUs (wheels, engine, steering)
  - CONTROLLER section: Displays autonomous controller TX (commands sent) and RX (sensor data received)
  - ACTUATORS section: Shows actuator ECUs receiving commands
- Added single-command launcher `cargo run`:
  - Automatically starts all 9 ECUs in background (sensors, controller, actuators)
  - Suppresses individual ECU logs for clean output
- Dashboard:
  - Real-time CAN traffic visualization
  - Press 'q' to quit and cleanly shutdown all components

### b6e91423 - inital implementation of autonomous controller
- Moved original implementation to `basic/` folder
- Created `autonomous_controller/` project with 9-ECU automotive architecture:
  - Sensors: 4x wheel speed, engine, steering
  - Controller: Autonomous decision-making
  - Actuators: Brake and steering control
- Automotive CAN IDs (0x100-0x3FF), data encoding/decoding helpers
- Safety features: Brake/steering limiting, anomaly detection
- Realistic simulation: 10-20 Hz broadcasts, noise injection, smooth actuator transitions
- Enhanced monitor with automotive message decoding
- Comprehensive documentation and security research guide

### 5eeca23 - update readme
- Updated README with architecture diagram, build/run instructions
- Created demo binary

### ad4dc5e - implement multi terminal connection
- Added TCP bus server on port 9000
- Implemented network layer (BusClient, BusReader, BusWriter)
- Enhanced ECU binaries with interactive terminal UIs

### ae5be76 - first imple
- Initial VirtualCanBus using Tokio broadcast channels
- ECU emulator with ARM variant support
- CAN frame types (Standard/Extended)
- Monitor, input_ecu, output_ecu binaries

### cc5c6e3 - Initial commit
- Repository created
