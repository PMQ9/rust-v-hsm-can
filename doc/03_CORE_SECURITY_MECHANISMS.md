# Core Security Mechanisms - Technical Deep Dive

**Document Version:** 1.0
**Last Updated:** 2025-11-19
**Project:** rust-v-hsm-can - Autonomous Vehicle CAN Bus Security System

---

## Table of Contents

1. [MAC/HMAC Authentication System](#machm

ac-authentication-system)
2. [CRC32 Integrity Protection](#crc32-integrity-protection)
3. [Replay Protection](#replay-protection)
4. [Attack Detection and Fail-Safe](#attack-detection-and-fail-safe)
5. [Access Control Authorization](#access-control-authorization)
6. [Key Rotation and Management](#key-rotation-and-management)
7. [SecuredCanFrame Format](#securedcanframe-format)
8. [Security Event Flow](#security-event-flow)

---

## MAC/HMAC Authentication System

### Overview

Message Authentication Codes (MAC) using HMAC-SHA256 provide cryptographic authentication for CAN frames, ensuring:
- **Authenticity:** Frames come from a trusted ECU with the symmetric key
- **Integrity:** Frame data has not been tampered with
- **Non-repudiation:** Source ECU cannot deny sending the frame

### Algorithm Details

**Algorithm:** HMAC-SHA256 (RFC 2104)
- **Hash Function:** SHA-256 (256-bit output)
- **Key Size:** 256 bits (32 bytes)
- **MAC Output:** 256 bits (32 bytes)
- **Security Level:** 256-bit security (quantum-resistant pre-hash)

### Implementation

**Code Location:** `autonomous_controller/src/hsm/crypto.rs`

#### MAC Generation

```rust
// Line 9-43: generate_mac()
pub fn generate_mac(
    data: &[u8],
    session_counter: u64,
    symmetric_key: &[u8; 32],
    metrics: Option<&Arc<Mutex<PerformanceMetrics>>>,
) -> [u8; 32]
```

**Process:**
1. Initialize HMAC with 256-bit symmetric key
2. Update HMAC with frame data
3. Update HMAC with session counter (little-endian, 8 bytes)
4. Finalize to produce 32-byte MAC
5. Optionally record performance metrics

**Key Security Properties:**
- **Constant-time operations:** HMAC computation time independent of key value
- **Counter binding:** Session counter prevents MAC reuse across sessions
- **Deterministic:** Same inputs always produce same MAC (required for verification)

**Code Reference:**
```rust
// Lines 22-32
let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(symmetric_key)
    .expect("HMAC can take key of any size");

mac.update(data);
mac.update(&session_counter.to_le_bytes());

let result = mac.finalize();
let bytes = result.into_bytes();
```

#### MAC Verification

```rust
// Line 45-78: verify_mac()
pub fn verify_mac(
    data: &[u8],
    mac: &[u8; 32],
    session_counter: u64,
    verification_key: &[u8; 32],
    metrics: Option<&Arc<Mutex<PerformanceMetrics>>>,
) -> Result<(), MacFailureReason>
```

**Process:**
1. Recompute expected MAC using verification key
2. Perform constant-time comparison with received MAC
3. Return Ok(()) if match, Err(MacFailureReason) if mismatch

**Security Properties:**
- **Constant-time comparison:** Line 66-68, prevents timing side-channel attacks
- **Explicit error types:** Distinguishes NoKeyRegistered vs CryptoFailure

**Code Reference:**
```rust
// Lines 65-68: Constant-time MAC verification
let result = expected_mac
    .verify_slice(mac)
    .map_err(|_| MacFailureReason::CryptoFailure);
```

### MAC Failure Reasons

**Defined in:** `autonomous_controller/src/hsm/errors.rs`

```rust
pub enum MacFailureReason {
    NoKeyRegistered,  // No key exists for source ECU
    CryptoFailure,    // MAC mismatch (wrong key or corrupted data)
}
```

**Purpose:**
- **NoKeyRegistered:** ECU not in trusted key registry → may be unauthorized device
- **CryptoFailure:** MAC verification failed → wrong key, tampered data, or attack

**Code Reference:**
- MAC failure types: `hsm/errors.rs:19-23`
- Error mapping: `error_handling.rs:29-37`

### Trusted Key Registry

Each ECU maintains a registry of trusted peer ECUs with their symmetric keys.

**Code Location:** `autonomous_controller/src/hsm/core.rs`

**Data Structure:**
```rust
// HashMap<ECU Name, Symmetric Key>
trusted_ecus: HashMap<String, [u8; 32]>
```

**Operations:**
- **add_trusted_ecu():** Register an ECU's symmetric key
- **verify_mac():** Look up key by source ECU name, fail if not found

**Security Implication:**
- **Closed trust model:** Only pre-registered ECUs can send valid frames
- **No dynamic trust:** Cannot add ECUs at runtime (prevents runtime compromise)

**Code Reference:**
- Registry usage: `hsm/core.rs` (VirtualHSM struct)
- Key lookup: During MAC verification

### Attack Scenarios and Mitigations

| Attack                     | How MAC Prevents                                | Code Reference              |
|----------------------------|------------------------------------------------|-----------------------------|
| Frame Injection            | Attacker cannot generate valid MAC without key | crypto.rs:9-43              |
| ECU Spoofing               | MAC binds frame to specific ECU key            | secured_frame.rs:93-167     |
| Data Tampering             | MAC covers all frame data                      | crypto.rs:26-27             |
| Counter Manipulation       | Session counter included in MAC                | crypto.rs:27                |
| Timing Side-Channel        | Constant-time verification                     | crypto.rs:66-68             |

### Performance Characteristics

**Benchmarked on:** Simulated ARM Cortex-M7 @ 216 MHz

- **MAC Generation:** ~50-100 μs
- **MAC Verification:** ~50-100 μs
- **Total Overhead:** ~100-200 μs per frame

**Performance Metrics Tracking:**
- Enabled via `VirtualHSM::with_performance()`
- Tracks: Operation count, total time, average time
- Code reference: `hsm/performance.rs:1-119`

### Testing

**Test Coverage:** 15+ tests

**Test Categories:**
1. **Normal Operation:** MAC generation and successful verification
   - Test: `hsm/mod.rs:33-45`
2. **MAC Mismatch Detection:** Corrupted MAC triggers CryptoFailure
   - Test: `crypto.rs:391-418`
3. **No Key Registered:** Source ECU not in registry
   - Test: `crypto.rs:367-389`
4. **CRC Before MAC:** CRC checked first (fail-fast)
   - Test: `crypto.rs:420-444`
5. **Data Tampering Detection:** Modified data causes MAC failure
   - Test: `crypto.rs:447-469`
6. **Source Spoofing Detection:** Changed source field detected
   - Test: `crypto.rs:497-527`

**Regression Tests:**
- Attack simulation: `tests/attack_regression_tests.rs`
- End-to-end validation: `tests/integration_tests.rs`

---

## CRC32 Integrity Protection

### Overview

CRC32 provides fast integrity checking to detect:
- **Transmission errors:** Bit flips during communication
- **Data corruption:** Memory errors, EMI interference
- **Early tamper detection:** Fails before expensive MAC verification

### Algorithm Details

**Algorithm:** CRC-32-ISO-HDLC (Polynomial 0x04C11DB7)
- **Polynomial:** x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
- **Initial Value:** 0xFFFFFFFF
- **Final XOR:** 0xFFFFFFFF
- **Output:** 32-bit checksum

### Coverage

CRC protects the following frame fields:
1. **CAN ID** (2 or 4 bytes)
2. **Data Payload** (0-8 bytes)
3. **Source ECU Name** (variable length string)
4. **Session Counter** (8 bytes)

**Code Reference:** `autonomous_controller/src/hsm/secured_frame.rs:51-64`

```rust
// Lines 51-64: CRC calculation over all fields
let mut crc_data = Vec::new();
crc_data.extend_from_slice(&self.can_id.value().to_le_bytes());
crc_data.extend_from_slice(&self.data);
crc_data.extend_from_slice(self.source.as_bytes());
crc_data.extend_from_slice(&self.session_counter.to_le_bytes());

let expected_crc = hsm.calculate_crc(&crc_data);
```

### Implementation

**Code Location:** `autonomous_controller/src/hsm/crypto.rs:81-133`

#### CRC Calculation

```rust
// Line 82-103
pub fn calculate_crc(
    data: &[u8],
    metrics: Option<&Arc<Mutex<PerformanceMetrics>>>,
) -> u32
```

**Code Reference:**
```rust
// Line 92: CRC computation using optimized library
let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(data);
```

#### CRC Verification

```rust
// Line 106-133
pub fn verify_crc(
    data: &[u8],
    expected_crc: u32,
    metrics: Option<&Arc<Mutex<PerformanceMetrics>>>,
) -> bool
```

**Process:**
1. Recalculate CRC over data
2. Compare with expected CRC
3. Return true if match, false if mismatch

**Code Reference:**
```rust
// Line 117: Simple comparison
let result = calculate_crc(data, metrics) == expected_crc;
```

### Fail-Fast Design

CRC is verified **before** MAC to optimize performance:

**Rationale:**
- CRC: ~5-10 μs (fast)
- MAC: ~50-100 μs (expensive)
- Most transmission errors detected by CRC
- Avoids wasting CPU on MAC verification for corrupted frames

**Code Reference:** `autonomous_controller/src/hsm/secured_frame.rs:93-106`

```rust
// Lines 93-106: CRC checked first
let expected_crc = hsm.calculate_crc(&crc_data);
if expected_crc != self.crc {
    return Err(VerifyError::CrcMismatch);  // Fail fast
}

// Then MAC verification (lines 108-167)...
```

### Testing

**Test Coverage:** 8+ tests

**Key Tests:**
1. **CRC Calculation:** Generate and verify CRC
   - Test: `hsm/mod.rs:48-53`
2. **Invalid CRC Detection:** Wrong CRC rejected
   - Test: `hsm/mod.rs:56-62`
3. **Data Corruption Detection:** Modified data fails CRC
   - Test: `crypto.rs:447-469`
4. **CAN ID Tampering Detection:** Changed CAN ID fails CRC
   - Test: `crypto.rs:472-494`
5. **CRC Before MAC:** CRC failure prevents MAC check
   - Test: `crypto.rs:420-444`

---

## Replay Protection

### Overview

Prevents attackers from capturing and replaying legitimate CAN frames by tracking session counters per ECU.

### Design

**Mechanism:** Sliding Window Counter-Based Replay Protection

**Key Parameters:**
- **Window Size:** 100 counters (configurable)
- **Per-ECU State:** Each source ECU has independent counter tracking
- **Out-of-Order Tolerance:** Frames within window can arrive out-of-order
- **Timestamp Validation:** Optional 60-second max age check

### Sliding Window Algorithm

**Data Structure:** `VecDeque<u64>` containing last N accepted counters

**Code Location:** `autonomous_controller/src/hsm/replay.rs:33-104`

```rust
pub struct ReplayProtectionState {
    last_accepted_counter: u64,
    accepted_window: VecDeque<u64>,
    window_size: usize,
    last_frame_timestamp: Option<DateTime<Utc>>,
    allow_reordering: bool,
}
```

### Validation Rules

**Code Location:** `autonomous_controller/src/hsm/replay.rs:106-165`

#### Rule 1: Strict Monotonic Check (Optional)

```rust
// Lines 114-119
if config.strict_monotonic && session_counter <= state.last_accepted_counter {
    return Err(ReplayError::CounterNotIncreasing { ... });
}
```

**When enabled:** Requires strictly increasing counters (no out-of-order)
**Default:** Disabled (allows reordering within window)

#### Rule 2: Duplicate Detection

```rust
// Lines 122-126
if state.accepted_window.contains(&session_counter) {
    return Err(ReplayError::CounterAlreadySeen { counter });
}
```

**Purpose:** Detect exact counter duplication (replay attack)

#### Rule 3: Window Range Check

```rust
// Lines 128-139
let min_acceptable = state.last_accepted_counter
    .saturating_sub(state.window_size.saturating_sub(1) as u64);

if session_counter < min_acceptable && state.last_accepted_counter > 0 {
    return Err(ReplayError::CounterTooOld { ... });
}
```

**Purpose:** Reject counters outside sliding window (too old to replay)

**Example:** If last_accepted_counter = 100 and window_size = 10:
- min_acceptable = 100 - 9 = 91
- Counters 91-100 accepted (within window)
- Counters ≤ 90 rejected (too old)

#### Rule 4: Timestamp Validation (Optional)

```rust
// Lines 142-162
if config.max_frame_age_secs > 0 && let Some(last_timestamp) = state.last_frame_timestamp {
    let time_diff = frame_timestamp.signed_duration_since(last_timestamp);

    // Frame too old
    if time_diff.num_seconds() < -(config.max_frame_age_secs as i64) {
        return Err(ReplayError::TimestampTooOld { ... });
    }

    // Frame too far in future (clock skew attack)
    if time_diff.num_seconds() > config.max_frame_age_secs as i64 {
        return Err(ReplayError::TimestampTooFarInFuture { ... });
    }
}
```

**Purpose:** Detect replays using old timestamps or clock skew attacks

### Configuration

**Code Location:** `autonomous_controller/src/hsm/replay.rs:7-31`

```rust
pub struct ReplayProtectionConfig {
    pub window_size: usize,           // Default: 100
    pub allow_reordering: bool,       // Default: true
    pub max_frame_age_secs: u64,      // Default: 60 seconds
    pub strict_monotonic: bool,       // Default: false
}
```

**Tuning Guidance:**
- **window_size:** Larger = more tolerance for reordering, more memory
- **strict_monotonic:** true = no reordering, simpler but less robust
- **max_frame_age_secs:** Adjust based on clock synchronization accuracy

### State Update

After successful validation, update state:

**Code Reference:** `replay.rs:65-81`

```rust
pub fn accept_counter(&mut self, counter: u64, timestamp: DateTime<Utc>) {
    // Update last accepted counter if newer
    if counter > self.last_accepted_counter {
        self.last_accepted_counter = counter;
    }

    // Add to sliding window
    self.accepted_window.push_back(counter);

    // Maintain window size (pop oldest if full)
    while self.accepted_window.len() > self.window_size {
        self.accepted_window.pop_front();
    }

    // Update timestamp
    self.last_frame_timestamp = Some(timestamp);
}
```

### Attack Scenarios

| Attack                         | Detection Method                    | Code Reference         |
|--------------------------------|-------------------------------------|------------------------|
| Exact Replay                   | Duplicate counter in window         | replay.rs:122-126      |
| Delayed Replay                 | Counter outside window              | replay.rs:128-139      |
| Out-of-Order Injection         | Duplicate detection                 | replay.rs:122-126      |
| Time-based Replay              | Timestamp validation                | replay.rs:142-162      |
| Clock Skew Attack              | Future timestamp check              | replay.rs:156-161      |
| Rapid Exhaustion               | Counter increment rate monitoring   | Future enhancement     |

### Testing

**Test Coverage:** 35+ tests (most comprehensive)

**Test Categories:**
1. **Duplicate Detection:** Same counter twice
   - Test: `replay.rs:177-192`
2. **Out-of-Order Acceptance:** Reordering within window
   - Test: `replay.rs:194-216`
3. **Counter Too Old:** Outside window rejection
   - Test: `replay.rs:218-238`
4. **Timestamp Validation:** Age and clock skew checks
   - Test: `replay.rs:241-266`
5. **Strict Monotonic Mode:** No backwards counters
   - Test: `replay.rs:269-287`
6. **Per-ECU Isolation:** Independent state per source
   - Test: `replay.rs:290-313`
7. **Window Boundary Tests:** Exact threshold validation
   - Test: `replay.rs:409-644`

**Regression Tests:**
- `tests/replay_protection_regression_tests.rs`

---

## Attack Detection and Fail-Safe

### Overview

Threshold-based attack detection with graduated response levels to distinguish between:
- **Transient errors:** Occasional noise/interference (tolerated)
- **Sustained attacks:** Repeated validation failures (triggers fail-safe)

### Security State Machine

**Code Location:** `autonomous_controller/src/error_handling.rs:53-72`

```rust
pub enum SecurityState {
    Normal,      // No threats detected
    Warning,     // Errors approaching threshold
    UnderAttack, // Threshold exceeded, protective measures active
}
```

**State Transitions:**

```
Normal → Warning:    Error count ≥ threshold/2
Warning → Normal:    Successful validation (auto-recovery)
Warning → UnderAttack: Error count ≥ threshold
UnderAttack → Normal: Manual reset only (prevent auto-recovery from attack)
```

### Attack Detection Thresholds

**Code Location:** `autonomous_controller/src/error_handling.rs:10-14`

```rust
pub const CRC_ERROR_THRESHOLD: u32 = 5;           // Tolerate 5 consecutive CRC errors
pub const MAC_ERROR_THRESHOLD: u32 = 3;           // Tolerate 3 consecutive MAC errors
pub const UNSECURED_FRAME_THRESHOLD: u32 = 1;     // Immediate trigger
pub const REPLAY_ERROR_THRESHOLD: u32 = 1;        // Immediate trigger
```

**Rationale:**

| Error Type        | Threshold | Rationale                                                  |
|-------------------|-----------|------------------------------------------------------------|
| CRC Mismatch      | 5         | EMI/noise can cause occasional bit flips                   |
| MAC Mismatch      | 3         | Authentication failures more suspicious                    |
| Unsecured Frame   | 1         | Unauthenticated frame = definite attack                    |
| Replay Attack     | 1         | Duplicate counter = definite attack                        |
| Anomaly (High)    | 1         | >99% confidence anomaly = definite attack                  |

### AttackDetector Implementation

**Code Location:** `autonomous_controller/src/error_handling.rs:75-719`

**Data Structure:**

```rust
pub struct AttackDetector {
    ecu_name: String,
    crc_error_count: u32,            // Consecutive errors
    mac_error_count: u32,
    unsecured_frame_count: u32,
    replay_error_count: u32,
    anomaly_count: u32,
    total_crc_errors: u64,           // Total lifetime errors
    total_mac_errors: u64,
    total_unsecured_frames: u64,
    total_replay_attacks: u64,
    total_unauthorized_access: u64,
    total_anomalies: u64,
    total_valid_frames: u64,
    state: SecurityState,
    security_logger: Option<SecurityLogger>,
}
```

### Error Recording

**Code Location:** `error_handling.rs:156-359`

**Algorithm:**

1. **Increment Consecutive Counter** for error type
2. **Increment Total Counter** for lifetime statistics
3. **Check Warning Threshold** (threshold / 2)
   - Transition Normal → Warning
   - Log warning message
4. **Check Attack Threshold** (threshold)
   - Transition Warning/Normal → UnderAttack
   - Call `trigger_attack_mode()`
   - Log detailed attack report
5. **Return Decision:** true = allow recovery, false = reject frame

**Code Example (MAC Error):**

```rust
// Lines 209-258
ValidationError::MacMismatch => {
    self.mac_error_count += 1;
    self.total_mac_errors += 1;

    println!("{} {} from {} | MAC Error #{} (Total: {})",
        "⚠️".yellow(), "MAC MISMATCH".red(),
        source.bright_black(),
        self.mac_error_count, self.total_mac_errors);

    if self.mac_error_count >= MAC_ERROR_THRESHOLD {
        self.trigger_attack_mode(ValidationError::MacMismatch);
        return false;  // Reject frame
    } else if self.mac_error_count >= MAC_ERROR_THRESHOLD / 2 {
        self.state = SecurityState::Warning;
        println!("{} {} - MAC errors approaching threshold ({}/{})",
            "⚠️".yellow(), "WARNING".yellow().bold(),
            self.mac_error_count, MAC_ERROR_THRESHOLD);
    }
}
```

### Success Recovery

**Code Location:** `error_handling.rs:362-400`

**Algorithm:**

1. **Reset Consecutive Counters** (crc_error_count, mac_error_count, etc.)
2. **Preserve Total Counters** (for statistics)
3. **Transition Warning → Normal** (automatic recovery)
4. **Do NOT recover from UnderAttack** (requires manual reset)
5. **Increment total_valid_frames**

**Code Reference:**

```rust
// Lines 362-400
pub fn record_success(&mut self) {
    // Reset consecutive error counters on successful validation
    let had_errors = self.crc_error_count > 0
        || self.mac_error_count > 0
        || self.unsecured_frame_count > 0
        || self.replay_error_count > 0
        || self.anomaly_count > 0;

    if had_errors && self.state != SecurityState::UnderAttack {
        println!("{} {} - Errors cleared after successful validation",
            "✓".green(), "RECOVERED".green().bold());
    }

    self.crc_error_count = 0;
    self.mac_error_count = 0;
    self.unsecured_frame_count = 0;
    self.replay_error_count = 0;
    self.anomaly_count = 0;

    // Return to normal if we were in warning state
    if self.state == SecurityState::Warning {
        self.state = SecurityState::Normal;
    }

    self.total_valid_frames += 1;
}
```

### Fail-Safe Activation

**Code Location:** `error_handling.rs:402-579`

**Actions:**

1. **Update State** to UnderAttack
2. **Log Attack Details:**
   - ECU name
   - Error type
   - Consecutive error count vs threshold
   - Total error count
   - Attack classification
3. **Display Protective Measures:**
   - Rejecting all unverified frames
   - Entering fail-safe mode
   - Maintaining last known safe state
   - Logging attack details
4. **Security Logger Integration:**
   - Log attack detected event
   - Log state change
   - Log fail-safe activation

**Code Example:**

```rust
// Lines 456-479: Attack display for MAC errors
println!("{}", "═══════════════════════════════════════".red().bold());
println!("{}", "       ATTACK DETECTED             ".red().bold());
println!("{}", "═══════════════════════════════════════".red().bold());
println!();
println!("{} ECU: {}", "→".red(), self.ecu_name.yellow().bold());
println!("{} Error Type: {}", "→".red(), error_type.to_string().red().bold());
println!("{} Consecutive MAC errors: {} (Threshold: {})",
    "→".red(), self.mac_error_count.to_string().red().bold(), MAC_ERROR_THRESHOLD);
println!("{} Total MAC errors: {}", "→".red(), self.total_mac_errors);
```

### Manual Reset

**Code Location:** `error_handling.rs:610-635`

**Purpose:** Allow operator to reset from attack state after investigation

**Actions:**

1. **Reset all consecutive counters** to 0
2. **Transition UnderAttack → Normal**
3. **Log security reset event**
4. **Log lifetime statistics**

**Code Reference:**

```rust
// Lines 610-635
pub fn reset(&mut self) {
    println!("{} {} - Resetting attack detector",
        "→".cyan(), "RESET".cyan().bold());

    // Log security reset
    if let Some(logger) = &self.security_logger {
        logger.log_security_reset("Manual reset".to_string());
        logger.log_statistics(
            self.total_valid_frames,
            self.total_crc_errors,
            self.total_mac_errors,
            self.total_unsecured_frames,
        );
    }

    self.crc_error_count = 0;
    self.mac_error_count = 0;
    self.unsecured_frame_count = 0;
    self.replay_error_count = 0;
    self.anomaly_count = 0;
    self.state = SecurityState::Normal;
}
```

### Integration

**All ECUs use identical AttackDetector pattern:**

**Brake Controller Example:** `autonomous_controller/src/bin/brake_controller.rs:156-197`

```rust
// Frame reception loop
loop {
    match secured_frame.verify(&mut hsm) {
        Ok(()) => {
            attack_detector.record_success();  // Reset consecutive counters
            // Process valid frame...
        }
        Err(e) => {
            let validation_error = ValidationError::from_verify_error(&e);
            let should_continue = attack_detector.record_error(
                validation_error, &secured_frame.source);

            if !should_continue {
                // Fail-safe: Reject frame and continue monitoring
                continue;
            }
        }
    }
}
```

### Testing

**Test Coverage:** 30+ tests

**Threshold Boundary Tests (Critical):**

1. **CRC Errors:**
   - Below threshold (4): `error_handling.rs:773-785`
   - At threshold (5): `error_handling.rs:787-805`
   - Above threshold (6): `error_handling.rs:807-825`

2. **MAC Errors:**
   - Below threshold (2): `error_handling.rs:831-844`
   - At threshold (3): `error_handling.rs:846-864`
   - Above threshold (4): `error_handling.rs:866-883`

3. **Warning Thresholds:**
   - CRC warning (2 errors, threshold/2): `error_handling.rs:901-912`
   - MAC warning (1 error, threshold/2): `error_handling.rs:926-935`

4. **Recovery Tests:**
   - Success resets consecutive counters: `error_handling.rs:942-959`
   - Warning → Normal auto-recovery: `error_handling.rs:962-976`
   - UnderAttack → No auto-recovery: `error_handling.rs:979-994`
   - Manual reset from UnderAttack: `error_handling.rs:997-1013`

5. **Immediate Triggers:**
   - Unsecured frame (threshold=1): `error_handling.rs:1020-1029`
   - Replay attack (threshold=1): `error_handling.rs:1032-1041`

---

## Access Control Authorization

### Overview

Implements principle of least privilege by restricting which CAN IDs each ECU can transmit and receive.

**ISO 21434 Mapping:** CAL-4.1, CAL-4.2

### Policy Model

**Code Location:** `autonomous_controller/src/access_control.rs`

**Policy Structure:**

```rust
pub struct CanIdPermissions {
    pub ecu_id: String,
    pub tx_whitelist: HashSet<u32>,      // CAN IDs allowed for TX
    pub rx_whitelist: Option<HashSet<u32>>, // CAN IDs allowed for RX (None = all)
}
```

### Policy Definition

**Function:** `build_autonomous_vehicle_policies()` (lines 10-78)

**Example Policies:**

```rust
// Wheel FL ECU - can only transmit its wheel speed
let mut wheel_fl = CanIdPermissions::new("WHEEL_FL".to_string());
wheel_fl.allow_tx(can_ids::WHEEL_SPEED_FL.value());  // 0x100

// Brake Controller - cannot transmit, only receives commands
let mut brake_ctrl = CanIdPermissions::new("BRAKE_CTRL".to_string());
brake_ctrl.allow_rx(can_ids::BRAKE_COMMAND.value());  // 0x300

// Autonomous Controller - transmits commands, receives all sensors
let mut auto_ctrl = CanIdPermissions::new("AUTONOMOUS_CTRL".to_string());
auto_ctrl
    .allow_tx(can_ids::BRAKE_COMMAND.value())
    .allow_tx(can_ids::THROTTLE_COMMAND.value())
    .allow_tx(can_ids::STEERING_COMMAND.value());
auto_ctrl.allow_rx_multiple(&[
    can_ids::WHEEL_SPEED_FL.value(),
    can_ids::WHEEL_SPEED_FR.value(),
    // ... all sensor CAN IDs
]);
```

### Authorization Enforcement

**TX Authorization:** Before sending frame

**Code:** `hsm/core.rs` (authorize_transmit method)

```rust
pub fn authorize_transmit(&self, can_id: u32) -> Result<(), VerifyError> {
    if let Some(permissions) = &self.access_control {
        if !permissions.can_transmit(can_id) {
            return Err(VerifyError::UnauthorizedAccess);
        }
    }
    Ok(())
}
```

**RX Authorization:** After receiving frame (optional filtering)

**Code:** `hsm/core.rs` (authorize_receive method)

```rust
pub fn authorize_receive(&self, can_id: u32) -> Result<(), VerifyError> {
    if let Some(permissions) = &self.access_control {
        if !permissions.can_receive(can_id) {
            return Err(VerifyError::UnauthorizedAccess);
        }
    }
    Ok(())
}
```

### Violation Handling

**Unauthorized TX Attempt:**

**Code:** `error_handling.rs:638-713`

1. Increment `total_unauthorized_access` counter
2. Log violation with CAN ID and source
3. Transition state to UnderAttack (immediate)
4. Display attack banner
5. Log to SecurityLogger

**Example Output:**

```
⚠️ UNAUTHORIZED CAN ID ACCESS from ATTACKER on CAN ID 0x300

═══════════════════════════════════════
       ATTACK DETECTED
═══════════════════════════════════════

→ ECU: BRAKE_CTRL
→ Error Type: Unauthorized CAN ID Access
→ Unauthorized attempts: 1

→ ATTACK TYPE: Authorization Violation
   • ECU attempting to use unauthorized CAN ID
   • This indicates compromised or rogue ECU
   • Access control whitelist violated

→ PROTECTIVE MEASURES ACTIVATED:
   • Rejecting all unauthorized frames
   • Entering fail-safe mode
   • Logging violation details

═══════════════════════════════════════
```

### Testing

**Test Coverage:** 10+ tests

**Key Tests:**
1. **Wheel FL Policy:** Can transmit 0x100, cannot transmit 0x300
   - Test: `access_control.rs:90-96`
2. **Autonomous Controller Policy:** Can transmit commands, receive sensors
   - Test: `access_control.rs:99-110`
3. **Brake Controller Policy:** Cannot transmit, can only receive 0x300
   - Test: `access_control.rs:113-120`
4. **All ECUs Have Policies:** Verify policy exists for each ECU
   - Test: `access_control.rs:123-143`

**Regression Tests:**
- `tests/access_control_regression_tests.rs`

---

## Key Rotation and Management

### Overview

Cryptographic key rotation prevents key compromise impact and ensures forward secrecy.

**ISO 21434 Mapping:** CAL-6.1, CAL-6.2

### Key Hierarchy

**Master Key → Session Keys (via HKDF-SHA256)**

```
Master Key (256-bit, long-term)
    |
    ├─ HKDF-Expand(key_id=1, ecu_id, timestamp) → Session Key 1
    ├─ HKDF-Expand(key_id=2, ecu_id, timestamp) → Session Key 2
    ├─ HKDF-Expand(key_id=3, ecu_id, timestamp) → Session Key 3
    └─ ...
```

### HKDF Key Derivation

**Code Location:** `hsm/key_rotation.rs:409-434`

**Algorithm:** HKDF-SHA256 (NIST SP 800-108)

```rust
pub fn derive_session_key_hkdf(
    master_key: &[u8; 32],
    key_id: u32,
    ecu_id: &str,
    timestamp: i64,
) -> [u8; 32] {
    // Build context information
    let mut info = Vec::new();
    info.extend_from_slice(b"CAN-SESSION-KEY-V1");
    info.extend_from_slice(&key_id.to_le_bytes());
    info.extend_from_slice(ecu_id.as_bytes());
    info.extend_from_slice(&timestamp.to_le_bytes());

    // HKDF-Expand (no salt needed, master_key is already high-entropy)
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");

    okm
}
```

**Context Binding:**
- **Protocol:** "CAN-SESSION-KEY-V1"
- **Key ID:** Monotonically increasing identifier
- **ECU ID:** ECU name (prevents cross-ECU key reuse)
- **Timestamp:** Generation time (prevents time-based replay)

### Session Key Lifecycle

**Code Location:** `hsm/key_rotation.rs:16-134`

**States:**

```rust
pub enum KeyState {
    Active,            // Currently used for TX and RX
    PendingRotation,   // New key distributed, old key valid for RX only
    Expired,           // No longer valid
}
```

**Lifecycle Phases:**

1. **Generation:** Derive from master key with HKDF
2. **Activation:** Set as active key for TX/RX
3. **Rotation:** Mark as PendingRotation, new key becomes Active
4. **Grace Period:** Old key valid for RX for 60 seconds
5. **Expiration:** Old key marked Expired and eventually removed

### Rotation Policy

**Code Location:** `hsm/key_rotation.rs:136-209`

**Configuration:**

```rust
pub struct KeyRotationPolicy {
    pub time_based_enabled: bool,
    pub rotation_interval_secs: i64,        // Default: 300 (5 minutes)

    pub counter_based_enabled: bool,
    pub rotation_frame_threshold: u64,      // Default: 10,000 frames

    pub grace_period_secs: i64,             // Default: 60 seconds
    pub max_key_history: usize,             // Default: 10 keys
}
```

**Rotation Triggers:**

1. **Time-Based:** Rotate every N seconds since key activation
2. **Counter-Based:** Rotate every N frames sent with key
3. **Hybrid:** Trigger on either condition (default)

**Check Function:**

```rust
pub fn should_rotate(&self, key: &SessionKey) -> bool {
    let now = Utc::now();

    // Time-based check
    if self.time_based_enabled && let Some(activation_time) = key.activation_time {
        let elapsed = (now - activation_time).num_seconds();
        if elapsed >= self.rotation_interval_secs {
            return true;
        }
    }

    // Counter-based check
    if self.counter_based_enabled && key.frame_count >= self.rotation_frame_threshold {
        return true;
    }

    false
}
```

### Key Rotation Process

**Code Location:** `hsm/key_rotation.rs:293-319`

**Algorithm:**

1. **Mark current key as PendingRotation**
   - Set rotation_time = now
   - Set expiry_time = now + grace_period
   - Change state to PendingRotation
2. **Generate new key ID** (current + 1, skip 0 and u32::MAX)
3. **Derive new session key** using HKDF
4. **Activate new key**
   - State = Active
   - activation_time = now
5. **Cleanup old expired keys** (keep max_key_history)

**Code Reference:**

```rust
pub fn rotate_key(&mut self) -> u32 {
    // Mark current key as pending rotation
    if let Some(current_key) = self.session_keys.get_mut(&self.current_key_id) {
        current_key.mark_pending_rotation(self.policy.grace_period_secs);
    }

    // Generate new key ID (skip 0 and u32::MAX)
    let new_key_id = self.current_key_id.wrapping_add(1);
    if new_key_id == 0 || new_key_id == u32::MAX {
        self.current_key_id = 1;
    } else {
        self.current_key_id = new_key_id;
    }

    // Derive new session key
    let key_material = self.derive_session_key(self.current_key_id);
    let new_key = SessionKey::new(self.current_key_id, key_material);

    // Store new key
    self.session_keys.insert(self.current_key_id, new_key);

    // Cleanup old expired keys
    self.cleanup_expired_keys();

    self.current_key_id
}
```

### Key Distribution

**AES-256-GCM Encrypted Key Export/Import**

**Encryption (Export):** `hsm/key_rotation.rs:448-472`

**SECURITY FIX:** Uses random nonces (V2 format)

```rust
fn encrypt_key_simple(key: &[u8; 32], kek: &[u8; 32], key_id: u32) -> Vec<u8> {
    // Generate cryptographically secure random nonce (96 bits / 12 bytes)
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Additional authenticated data (not encrypted, but authenticated)
    let mut aad = Vec::new();
    aad.extend_from_slice(b"KEY-ENCRYPTION-V2");  // V2 = random nonce
    aad.extend_from_slice(&key_id.to_le_bytes());

    // Encrypt with AES-256-GCM
    let ciphertext = encrypt_aes256_gcm(key, kek, &nonce, &aad)
        .expect("AES-256-GCM encryption should not fail");

    // Prepend nonce to ciphertext for transmission
    // Format: [nonce: 12 bytes] + [encrypted_key + auth_tag: 48 bytes] = 60 bytes
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}
```

**Decryption (Import):** `hsm/key_rotation.rs:485-540`

**Supports V1 (legacy, deterministic nonce) and V2 (random nonce) formats**

**Rollback Protection:** `hsm/key_rotation.rs:385-390`

```rust
// Verify key_id is monotonically increasing (prevent rollback attacks)
if key_id <= self.current_key_id {
    return Err(format!(
        "Key rollback detected: new key_id {} <= current key_id {}",
        key_id, self.current_key_id
    ));
}
```

### Testing

**Test Coverage:** 30+ tests

**Key Tests:**
1. **HKDF Deterministic:** Same inputs → same key
   - Test: `key_rotation.rs:584-590`
2. **HKDF Different Inputs:** Different key_id/ecu_id → different keys
   - Test: `key_rotation.rs:592-608`
3. **Key Encryption/Decryption:** Round-trip successful
   - Test: `key_rotation.rs:610-620`
4. **Wrong KEK Fails:** Different key encryption key fails authentication
   - Test: `key_rotation.rs:623-637`
5. **Rotation Manager:** Initialization with key_id=1
   - Test: `key_rotation.rs:640-647`
6. **Key Rotation:** Old key → PendingRotation, new key → Active
   - Test: `key_rotation.rs:649-669`
7. **Time-Based Rotation Policy:** Trigger after time threshold
   - Test: `key_rotation.rs:672-681`
8. **Counter-Based Rotation Policy:** Trigger after frame threshold
   - Test: `key_rotation.rs:683-699`
9. **Rollback Protection:** Reject key_id <= current_key_id
   - Test: `key_rotation.rs:761-776`
10. **Key Cleanup:** Maintain max_key_history limit
    - Test: `key_rotation.rs:808-826`

---

## SecuredCanFrame Format

### Frame Structure

**Code Location:** `autonomous_controller/src/hsm/secured_frame.rs:10-42`

```rust
pub struct SecuredCanFrame {
    pub can_id: CanId,
    pub data: Vec<u8>,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub mac: [u8; 32],              // HMAC-SHA256 authentication tag
    pub crc: u32,                   // CRC32-ISO-HDLC checksum
    pub session_counter: u64,       // Replay protection counter
    pub key_version: u32,           // Session key ID
}
```

**Field Sizes:**

| Field           | Size (bytes) | Purpose                                  |
|-----------------|--------------|------------------------------------------|
| can_id          | 2 or 4       | Standard (11-bit) or Extended (29-bit)   |
| data            | 0-8          | CAN payload (per CAN spec)               |
| source          | Variable     | ECU name (UTF-8 string)                  |
| timestamp       | 12           | UTC timestamp (chrono::DateTime)         |
| mac             | 32           | HMAC-SHA256 authentication tag           |
| crc             | 4            | CRC32 checksum                           |
| session_counter | 8            | Monotonic counter for replay protection  |
| key_version     | 4            | Session key ID                           |

**Total Overhead:** ~60-70 bytes (vs 8 bytes unsecured CAN)

### Frame Creation

**Code Location:** `secured_frame.rs:44-91`

**Process:**

1. Retrieve current session key from HSM
2. Calculate CRC over: CAN ID + Data + Source + Session Counter
3. Prepare MAC input: Data + Counter
4. Generate MAC using HMAC-SHA256
5. Construct SecuredCanFrame with all fields
6. Increment session counter and key frame count

**Code Reference:**

```rust
pub fn new(
    can_id: CanId,
    data: Vec<u8>,
    source: String,
    hsm: &mut VirtualHSM,
) -> Result<Self, String> {
    // Get current session key
    let (key_material, key_version, session_counter) = {
        if let Some(key_rot) = hsm.get_key_rotation_manager_mut() {
            let active_key = key_rot.get_active_key_mut()
                .ok_or("No active session key available")?;

            let key_material = active_key.key_material;
            let key_version = active_key.key_id;
            let session_counter = hsm.get_session_counter();

            // Increment frame count
            active_key.increment_frame_count();

            (key_material, key_version, session_counter)
        } else {
            // Fallback to legacy symmetric_comm_key
            let key_material = *hsm.get_symmetric_key();
            (key_material, 0, hsm.get_session_counter())
        }
    };

    // Calculate CRC
    let mut crc_data = Vec::new();
    crc_data.extend_from_slice(&can_id.value().to_le_bytes());
    crc_data.extend_from_slice(&data);
    crc_data.extend_from_slice(source.as_bytes());
    crc_data.extend_from_slice(&session_counter.to_le_bytes());
    let crc = hsm.calculate_crc(&crc_data);

    // Generate MAC (data + counter)
    let mac = hsm.generate_mac_with_key(&data, session_counter, &key_material);

    // Increment session counter
    hsm.increment_session();

    Ok(Self {
        can_id,
        data,
        source,
        timestamp: Utc::now(),
        mac,
        crc,
        session_counter,
        key_version,
    })
}
```

### Frame Verification

**Code Location:** `secured_frame.rs:93-167`

**Verification Sequence:**

```
1. Check for unsecured frame (all-zero MAC) → REJECT
2. Verify CRC32 checksum → REJECT if mismatch
3. Verify HMAC-SHA256 MAC → REJECT if mismatch
4. Validate replay protection counter → REJECT if replay
5. ACCEPT frame
```

**Code Reference:**

```rust
pub fn verify(&self, hsm: &mut VirtualHSM) -> Result<(), VerifyError> {
    // Step 1: Check for unsecured frame
    if self.mac == [0u8; 32] {
        return Err(VerifyError::UnsecuredFrame);
    }

    // Step 2: Verify CRC (fail-fast)
    let mut crc_data = Vec::new();
    crc_data.extend_from_slice(&self.can_id.value().to_le_bytes());
    crc_data.extend_from_slice(&self.data);
    crc_data.extend_from_slice(self.source.as_bytes());
    crc_data.extend_from_slice(&self.session_counter.to_le_bytes());

    let expected_crc = hsm.calculate_crc(&crc_data);
    if expected_crc != self.crc {
        return Err(VerifyError::CrcMismatch);
    }

    // Step 3: Verify MAC
    let (verification_key, _key_id) = {
        if let Some(key_rot) = hsm.get_key_rotation_manager() {
            // Try to get key by key_version
            if let Some(session_key) = key_rot.get_key_by_id(self.key_version) {
                if session_key.is_valid_for_rx() {
                    (session_key.key_material, session_key.key_id)
                } else {
                    return Err(VerifyError::MacMismatch(MacFailureReason::NoKeyRegistered));
                }
            } else {
                return Err(VerifyError::MacMismatch(MacFailureReason::NoKeyRegistered));
            }
        } else {
            // Fallback to legacy symmetric_comm_key
            (*hsm.get_symmetric_key(), 0)
        }
    };

    hsm.verify_mac_with_key(&self.data, &self.mac, self.session_counter,
                             &self.source, &verification_key)?;

    // Step 4: Validate replay protection
    hsm.validate_counter(self.session_counter, &self.source, self.timestamp)?;

    // Step 5: All checks passed
    Ok(())
}
```

---

## Security Event Flow

### End-to-End Frame Processing

**Sender ECU → CAN Bus → Receiver ECU**

```
[SENDER ECU]
    ↓
1. Create CAN frame (CAN ID + Data)
    ↓
2. Load current session key
    ↓
3. Calculate CRC (CAN ID + Data + Source + Counter)
    ↓
4. Generate MAC (Data + Counter, using session key)
    ↓
5. Create SecuredCanFrame
    ↓
6. Increment session counter
    ↓
7. Check key rotation policy → Rotate if needed
    ↓
8. Broadcast to CAN Bus
    ↓
[CAN BUS - Untrusted Broadcast Medium]
    ↓
9. All ECUs receive frame
    ↓
[RECEIVER ECU]
    ↓
10. Receive SecuredCanFrame
    ↓
11. Check MAC != all-zeros (unsecured frame check)
    ↓
12. Verify CRC (fail-fast integrity check)
    ↓
13. Look up sender's key (by key_version or source)
    ↓
14. Verify MAC (HMAC-SHA256 authentication)
    ↓
15. Validate replay protection (counter check)
    ↓
16. Check access control (optional RX filtering)
    ↓
17. Check anomaly detection (behavioral IDS)
    ↓
18. AttackDetector.record_success() OR record_error()
    ↓
19. Update security state (Normal/Warning/UnderAttack)
    ↓
20. Process frame OR reject and fail-safe
```

### Security Layer Integration

```
┌─────────────────────────────────────────────────────────────┐
│                  Application Layer (ECU Logic)              │
│           (Brake Control, Steering Control, etc.)           │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│              Security Validation Layer                      │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ MAC/HMAC     │→ │ Replay       │→ │ Access       │      │
│  │ Verification │  │ Protection   │  │ Control      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│            │               │                 │              │
│            └───────────────┴─────────────────┘              │
│                            │                                │
│                    ┌───────▼────────┐                       │
│                    │ Attack         │                       │
│                    │ Detector       │                       │
│                    └───────┬────────┘                       │
│                            │                                │
│        Normal/Warning/UnderAttack State                     │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                CAN Bus Interface Layer                      │
│              (SecuredCanFrame TX/RX)                        │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    CAN Bus (Physical)                       │
│              Broadcast Communication Medium                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Document Change History

| Version | Date       | Author          | Changes                                  |
|---------|------------|-----------------|------------------------------------------|
| 1.0     | 2025-11-19 | Claude (AI)     | Initial technical deep-dive documentation|

---

## References

- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
- NIST FIPS 180-4 - Secure Hash Standard (SHA-2 Family)
- NIST SP 800-108 - Recommendation for Key Derivation Using Pseudorandom Functions
- ISO/IEC 13239 - CRC-32 (ISO-HDLC)
- ISO 11898 - Controller Area Network (CAN) Specification
- ISO 21434:2021 - Road vehicles — Cybersecurity engineering

---

**END OF DOCUMENT**
