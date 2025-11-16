# Changelog
## 2025-11-16

### Critical Bug Fix: Key Rotation
- Fixed critical MAC generation bug in SecuredCanFrame::new() that bypassed key rotation system
- Bug: Was using hsm.get_symmetric_key() instead of hsm.generate_mac(), causing frames to always use legacy key
- Impact: Key rotation would fail verification (key_version mismatch)
- Fix: Changed to use hsm.generate_mac() which automatically selects session key when rotation enabled
- Added 2 integration tests: test_key_rotation_integration, test_key_rotation_disabled_uses_legacy_key
- All 200 unit tests passing (up from 198)

## 2025-11-15

### Security Fixes
- Fixed CAN frame size validation bypass (data.len() > 8 now rejected)
- Fixed empty anomaly baseline acceptance (empty profiles now rejected)

### Attack Simulation Framework
- Added comprehensive attack simulation framework for security testing (fuzzing, injection, replay)
- New module: attack_framework.rs with 6 attack types (Injection, Replay, Flooding, Spoofing, Fuzzing, Combined)
- CLI tool: attack_simulator binary for running attacks with configurable parameters
- Example configs: 4 JSON config files for common attack scenarios
- Unit tests: 6 tests for attack generation logic
- Integration tests: 7 regression tests for attack execution (attack_framework_tests.rs)

### Test Recovery: Restored 35 Deleted Tests from HSM Refactoring
- Restored all 35 tests deleted during hsm.rs modular refactoring (total: 173 unit tests, up from 138)
- Distributed tests across modules: replay.rs (26), crypto.rs (9), secured_frame.rs (8), core.rs (11), firmware.rs (1)
- Fixed test expectations to match refactored replay protection logic (window_size boundary calculations)
- All CI tests passing: formatting, linting, build, unit tests, integration tests, 4 regression suites

### Code Refactoring: HSM Module Structure
- Refactored monolithic hsm.rs (2,645 lines) into modular architecture (1,844 lines across 8 files)
- New structure: errors.rs, performance.rs, replay.rs, crypto.rs, firmware.rs, secured_frame.rs, core.rs, mod.rs
- Each module follows Single Responsibility Principle for improved maintainability
- Fixed replay protection edge case: counter=0 incorrectly accepted when last_accepted=100 with window_size=100
- All 159+ tests passing, full backward compatibility maintained

### Test Coverage Improvements
- Added 60+ edge case tests for threshold boundaries across all security features
- Enhanced CI pipeline with dynamic test reporting and strict pass/fail enforcement
- Added run_ci_tests.sh for local testing, branch protection guide for PR requirements
- Test count: 159+ (up from ~90)

## 2025-11-14

### Test Design Methodology Guidelines
- Added comprehensive test design methodology to CLAUDE.md: normal/failure cases, threshold boundary testing

### Bug Fix: Interval Anomaly Detection
- Fixed interval anomaly detection not working after loading baselines from disk
- Added runtime interval_trackers HashMap to maintain last-seen timestamps during detection
- Interval detection now properly works alongside rate, data range, source, and CAN ID anomaly detection
- Added baseline JSON files to .gitignore for security (deployment artifacts, not source code)
- Added anomaly_ids_regression_tests to CI pipeline and GitHub Actions (was missing)
- Added CI test summary stage to display comprehensive results table

### Anomaly-Based IDS with Statistical Baseline Profiling
- Implemented behavioral anomaly detection using statistical profiling (no ML, simple statistics)
- Factory calibration mode: Collect CAN traffic to establish normal behavior baseline
- Profiles message frequency, data ranges, source ECUs, and temporal patterns per CAN ID
- Graduated response: < 80% allow, 80-99% warn (1.3σ), >99% attack (3σ)
- Secure baseline storage with HSM signature verification (prevents tampering)
- Integration with VirtualHSM as central security processing unit
- Anomaly detection in brake_controller, steering_controller, autonomous_controller ECUs
- Detects: unknown CAN IDs, unexpected sources, data range anomalies, rate anomalies
- Added calibration binary (calibrate_anomaly_baseline) for baseline generation
- Added 9 unit tests for anomaly detection logic
- Added 3 regression tests: full lifecycle, persistence, tamper detection
- Baseline persistence with SHA256 fingerprinting and HMAC-SHA256 signing

### Rate Limiting and DoS Prevention
- Implemented per-ECU rate limiting with token bucket algorithm (200 msg burst, 100 msg/sec sustained)
- Bus servers drop frames exceeding rate limits and log throttling warnings
- Per-ECU token buckets prevent individual ECU from flooding CAN bus
- Added rate_limiter module with comprehensive unit tests (burst, refill, isolation, reset)
- Integrated into both autonomous_controller and basic bus servers

### Test Fixes and CI Improvements
- Fixed infinite loop in attack_replay test binary (added max replay limit)
- Fixed attack_replay to send SecuredCanFrame instead of CanFrame for proper replay detection
- Fixed rustfmt formatting issues in replay protection code
- Fixed unit test job to use `--workspace --lib` for testing all packages
- Optimized CI pipeline with fail-fast formatting check and sequential execution

### Enhanced Replay Protection (ISO 21434 Compliance)
- Implemented sliding window tracking (100 counters per ECU) with timestamp validation
- 5 replay detection types: duplicate counter, too old, non-increasing, timestamp attacks
- Per-ECU replay state with configurable strictness (lenient/balanced/strict modes)
- Immediate attack mode triggering on replay detection (REPLAY_ERROR_THRESHOLD = 1)
- Added 10 unit tests covering all replay scenarios and end-to-end detection
- Added regression test for replay attack detection
- Integrated with AttackDetector for comprehensive threat response

## 2025-11-13

### CAN ID Access Control (ISO 21434 Compliance)
- Implemented per-ECU TX/RX whitelists for CAN ID authorization
- HSM enforces authorization checks before frame creation/verification
- 9 access control policies defined for all ECUs (wheel sensors, engine, steering, controllers)
- Unauthorized access triggers immediate fail-safe mode
- Added 9 unit tests for authorization logic
- Added 3 regression tests: authorized transmission, unauthorized blocking, full system integration

## 2025-11-12

### Security Event Logging (ISO 21434 Compliance)
- Implemented tamper-resistant audit trail with chained hashing (SHA256)
- SecurityLogger logs 10 event types: verification failures, state changes, attacks, etc.
- JSONL format with automatic timestamped log rotation per ECU session
- Integrated with all critical ECUs (autonomous_controller, brake_controller, steering_controller)
- Added security_log_analyzer tool: verifies integrity, detects tampering, analyzes events
- Usage: `cargo run --bin security_log_analyzer security_logs/AUTONOMOUS_CTRL_*.jsonl`

### Documentation
- Added ISO 21434 roadmap to README with 4-phase implementation plan

## 2025-11-11

### Documentation Enhancements
- **Added professional architecture diagram**: Created Graphviz-based visual diagram showing CAN bus architecture with V-HSM security layers, all 9 ECUs, and data flow
- **Generated assets**: PNG (high-res) and SVG (scalable) versions available in `utils/docs/`

## 2025-11-10

### Regression Test Infrastructure
- **Fixed `test_short_cycle_injection_does_not_trigger_detection` test**: Added legitimate brake command sender to properly test consecutive error counter reset behavior
- **Added `test_legitimate_sender` binary**: Impersonates AUTONOMOUS_CTRL to send valid brake commands at 10Hz during tests
- **Test harness enhancement**: TestHarness now starts legitimate sender alongside brake controller to simulate realistic CAN bus traffic with both valid and malicious frames
- **Key insight**: Short cycle attacks (2 frames/cycle) only stay below threshold when legitimate frames reset the consecutive error counter between cycles

### HSM Performance Evaluation Mode
- **Added `--perf` flag**: Enables HSM performance tracking for all ECUs (sensors, controller, actuators)
- **Metrics tracked**: MAC generation/verification, CRC calculation/verification, frame creation/verification, end-to-end latency (avg/min/max)
- **Usage**: `cargo run -- --perf` (full simulation with integrated dashboard)
- **Monitor display**: Compact table format in PERFORMANCE section, updates every 10 seconds
- **Zero overhead when disabled**: No performance cost without the flag

## 2025-11-05

### Threshold-Testing Attack Scenarios
- Added two new attack injection variants to test MAC error detection thresholds:
  - `attack_injection_short_cycles`: Sends 3 cycles of 2 malicious brake commands each with 2-second delays between cycles (below 3-frame threshold, should NOT trigger error)
  - `attack_injection_burst`: Sends 3 cycles of 4 malicious brake commands (exceeds 3-frame threshold, should trigger error)

### Error Handling Architecture Improvements
- **Fixed autonomous_controller to use AttackDetector**: Replaced simple AtomicBool flag with proper threshold-based AttackDetector like actuator ECUs, ensuring consistent error handling across all ECUs
- **Implemented structured error types**: Replaced string-based error handling with type-safe VerifyError and MacFailureReason enums
  - `VerifyError`: UnsecuredFrame, CrcMismatch, MacMismatch(reason)
  - `MacFailureReason`: NoKeyRegistered, CryptoFailure
- **Enhanced MAC verification diagnostics**: verify_mac() now returns Result with specific failure reason instead of bool
- **Eliminated fragile string matching**: All ECUs now use ValidationError::from_verify_error() for type-safe error classification
- **Key benefits**:
  - Autonomous controller now properly tolerates up to 3 consecutive MAC errors (consistent with actuators)
  - Better debugging: Can distinguish "no key registered" from "crypto failure" MAC errors
  - CRC failures no longer mask MAC verification issues in diagnostics
  - All ECUs use identical threshold-based attack detection patterns

### Attack Fallback - Autonomous Controller Shutdown
- Implemented automatic controller deactivation when attack is detected
- **Safe Mode Features**:
  - Controller STOPS sending all commands (brake, throttle, steering) when attack detected
  - Continues monitoring sensor inputs but takes NO ACTION
  - Displays prominent warning with explanation
  - Requires manual restart to resume operation
- **Thread-safe attack detection**: Uses AtomicBool for real-time coordination between receiver and control loop
- **Safety-first design**: Prevents compromised commands from reaching actuators
- **Launcher enhancement**:
  - Automatic cleanup of old processes before starting new simulation
- **Visible shutdown status**:
  - Controller broadcasts emergency shutdown status on CAN bus (ID 0x400)
  - Indication that restart is required

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
