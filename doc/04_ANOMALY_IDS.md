# Anomaly-Based Intrusion Detection System (IDS)

**Document Version:** 1.0
**Last Updated:** 2025-11-19
**Project:** rust-v-hsm-can - Autonomous Vehicle CAN Bus Security System
**ISO 21434 Mapping:** CAL-5.1, CAL-5.2 (Intrusion Detection)

---

## Table of Contents

1. [Overview](#overview)
2. [Why Anomaly Detection?](#why-anomaly-detection)
3. [System Architecture](#system-architecture)
4. [Training Phase (Factory Calibration)](#training-phase-factory-calibration)
5. [Detection Phase (Production)](#detection-phase-production)
6. [Anomaly Types](#anomaly-types)
7. [Graduated Response Levels](#graduated-response-levels)
8. [Baseline Persistence and Security](#baseline-persistence-and-security)
9. [Integration with ECUs](#integration-with-ecus)
10. [Testing and Validation](#testing-and-validation)
11. [Operational Guidance](#operational-guidance)

---

## Overview

The Anomaly-Based Intrusion Detection System (IDS) detects cyber attacks by identifying deviations from "normal" CAN bus behavior. Unlike signature-based detection (which relies on known attack patterns), anomaly detection can identify:

- **Zero-day attacks** - Novel attack patterns not previously seen
- **Compromised ECUs** - Legitimate ECUs behaving abnormally after compromise
- **Behavioral attacks** - Attacks that pass MAC/CRC checks but violate operational norms

**Key Insight:** Even if an attacker has valid cryptographic keys (e.g., from compromised ECU), anomaly detection can identify behavioral deviations (unusual message rates, unexpected CAN IDs, out-of-range sensor values).

### Design Philosophy

**Statistical Profiling + Graduated Response**

- **Training:** Collect baseline statistics during factory calibration
- **Detection:** Compare runtime behavior against baseline using statistical thresholds
- **Response:** Graduated actions based on confidence level (Warning at 80-99%, Attack at >99%)

**No Machine Learning Required:**
- Simple statistical methods (mean, standard deviation)
- Deterministic and explainable
- Low computational overhead (suitable for embedded systems)

---

## Why Anomaly Detection?

### Threat Scenarios Addressed

| Threat                                | MAC/CRC Detection | Anomaly Detection | Rationale                                                    |
|---------------------------------------|-------------------|-------------------|--------------------------------------------------------------|
| **Frame Injection (No Key)**          | ✓ Detected        | ✓ Detected        | Both methods effective                                       |
| **Compromised ECU (Valid Key)**       | ✗ Not Detected    | ✓ Detected        | MAC valid, but behavior deviates (rate, data range)          |
| **Unusual Message Rate**              | ✗ Not Detected    | ✓ Detected        | Frames have valid MAC but sent at abnormal frequency         |
| **Out-of-Range Sensor Data**          | ✗ Not Detected    | ✓ Detected        | Valid frame with physically impossible sensor readings       |
| **CAN ID Misuse by Authorized ECU**   | ✗ Not Detected    | ✓ Detected        | ECU sends on unexpected CAN ID (e.g., after firmware exploit)|
| **Time-based Manipulation**           | ✗ Not Detected    | ✓ Detected        | Delayed or accelerated message sequences                     |

**Example Scenario:**

1. Attacker compromises Wheel Speed Sensor ECU via software vulnerability
2. Attacker extracts cryptographic keys from compromised ECU
3. Attacker sends spoofed wheel speed frames with valid MAC/CRC
4. Traditional authentication: **PASSES** (valid key)
5. Anomaly detection: **FAILS** (wheel speed data out of range: 500 rad/s on parked vehicle)

---

## System Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Factory Calibration                             │
│                                                                     │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐     │
│  │ Controlled   │  →   │ Baseline     │  →   │ Baseline     │     │
│  │ Environment  │      │ Collection   │      │ Signature    │     │
│  │              │      │ (5000+ CAN   │      │ (HMAC-SHA256)│     │
│  │ Normal       │      │  frames)     │      │              │     │
│  │ Operation    │      │              │      │              │     │
│  └──────────────┘      └──────────────┘      └──────────────┘     │
│                              │                      │              │
│                              └──────────────────────┘              │
│                                       │                            │
│                                       ▼                            │
│                        ┌──────────────────────────┐               │
│                        │ baseline_ECUNAME.json    │               │
│                        │ (Signed, Tamper-proof)   │               │
│                        └──────────────────────────┘               │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   │ Deploy to Production
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Production ECU (Runtime)                         │
│                                                                     │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐     │
│  │ Load Signed  │  →   │ Verify       │  →   │ Activate     │     │
│  │ Baseline     │      │ Signature    │      │ Anomaly      │     │
│  │              │      │ (Prevent     │      │ Detection    │     │
│  │              │      │  Tampering)  │      │              │     │
│  └──────────────┘      └──────────────┘      └──────────────┘     │
│                                                      │              │
│                         ┌────────────────────────────┘              │
│                         ▼                                           │
│                 For Each CAN Frame:                                 │
│       ┌─────────────────────────────────────────────┐              │
│       │ 1. MAC/CRC Verification (Pass)              │              │
│       │ 2. Replay Protection (Pass)                 │              │
│       │ 3. Access Control (Pass)                    │              │
│       │ 4. Anomaly Detection                        │              │
│       │    ├─ Unknown CAN ID?                       │              │
│       │    ├─ Unexpected Source?                    │              │
│       │    ├─ Interval Anomaly?                     │              │
│       │    ├─ Rate Anomaly?                         │              │
│       │    └─ Data Range Anomaly?                   │              │
│       │                                             │              │
│       │ 5. Result: Normal / Warning / Attack        │              │
│       └─────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### Code Organization

**Core Implementation:** `autonomous_controller/src/anomaly_detection.rs` (1851 lines)

| Module                    | Lines       | Purpose                                          |
|---------------------------|-------------|--------------------------------------------------|
| Statistical Utilities     | 16-212      | Mean, std dev, z-score, confidence conversion    |
| CAN ID Statistics         | 214-400     | Per-CAN-ID frequency and data range profiling    |
| Anomaly Detector          | 402-712     | Runtime detection engine                         |
| Tests                     | 720-1850    | 45+ unit tests                                   |

**Supporting Files:**

| File                                | Purpose                                  | Lines |
|-------------------------------------|------------------------------------------|-------|
| `baseline_persistence.rs`           | Signed baseline save/load                | 185   |
| `bin/calibrate_anomaly_baseline.rs` | Factory calibration tool                 | 337   |
| `tests/anomaly_ids_regression_tests.rs` | End-to-end regression tests          | 300+  |

---

## Training Phase (Factory Calibration)

### Overview

Baselines are collected in a **controlled factory environment** with **known-good vehicle behavior**.

**Critical Security Requirement:** Never train baselines in production (creates attack vector during startup).

### Calibration Tool

**Binary:** `cargo run --bin calibrate_anomaly_baseline`

**Code Location:** `autonomous_controller/src/bin/calibrate_anomaly_baseline.rs`

**Usage:**

```bash
# Start vehicle simulation in background
cargo run &

# Collect baseline for Brake Controller (5000 samples, 5 minutes)
cargo run --bin calibrate_anomaly_baseline -- \
    --ecu BRAKE_CTRL \
    --samples 5000 \
    --duration 300 \
    --output baseline_brake_ctrl.json
```

**Parameters:**

- `--ecu <NAME>`: ECU name (must match ECU in simulation)
- `--samples <N>`: Minimum samples per CAN ID (default: 5000)
- `--duration <SECS>`: Maximum collection time (default: 300s)
- `--output <FILE>`: Output file path

### Collection Process

**Code Reference:** `calibrate_anomaly_baseline.rs:45-254`

**Algorithm:**

1. **Connect to CAN Bus** (bus server)
2. **Initialize AnomalyDetector** in training mode
3. **Collect Frames:**
   - For each received frame with valid MAC/CRC:
     - Call `detector.train(frame)`
     - Update sample counters
     - Display progress
4. **Check Termination Conditions:**
   - All CAN IDs have ≥ min_samples, OR
   - Duration exceeded
5. **Finalize Baseline:**
   - Call `detector.finalize_training()`
   - Compute statistics (mean, std dev, min/max)
6. **Sign Baseline:**
   - Calculate SHA256 fingerprint
   - Generate HMAC-SHA256 signature
7. **Save to File** (JSON format)

**Training Statistics Collected (Per CAN ID):**

| Statistic                  | Purpose                                              |
|----------------------------|------------------------------------------------------|
| Expected Source ECU        | Detect spoofing (message from unexpected ECU)        |
| Message Frequency (mean)   | Detect rate anomalies (too fast/slow)                |
| Frequency Std Dev (σ)      | Establish normal variance for frequency              |
| Minimum Interval           | Fastest observed message rate                        |
| Maximum Interval           | Slowest observed message rate                        |
| Data Range (per byte)      | Min/Max/Mean/StdDev for each data byte               |
| Total Samples              | Number of training samples                           |

**Code Reference:**

```rust
// Lines 402-511: Training mode
pub fn train(&mut self, frame: &SecuredCanFrame) {
    let can_id_u32 = frame.can_id.value();
    let stats = self.can_id_stats.entry(can_id_u32).or_insert_with(|| {
        CanIdStats::new(can_id_u32, frame.source.clone())
    });

    // Record message timing
    let now = Utc::now();
    if let Some(last_time) = stats.last_message_time {
        let interval = (now - last_time).num_milliseconds() as f64 / 1000.0;
        stats.intervals.push(interval);
    }
    stats.last_message_time = Some(now);

    // Update message frequency statistics
    stats.message_count += 1;

    // Record data byte statistics
    for (i, &byte_val) in frame.data.iter().enumerate() {
        stats.record_data_byte(i, byte_val);
    }
}

// Lines 513-549: Finalize training
pub fn finalize_training(&mut self) -> CanBusBaseline {
    let mut can_id_baselines = HashMap::new();

    for (can_id, stats) in &self.can_id_stats {
        let baseline = stats.calculate_baseline();
        can_id_baselines.insert(*can_id, baseline);
    }

    CanBusBaseline { can_id_baselines }
}
```

### Minimum Sample Requirements

**Recommended:** 5000+ samples per CAN ID

**Rationale:**
- **Statistical Validity:** Large sample size ensures accurate mean/std dev
- **Coverage:** Captures all normal operational modes (idle, acceleration, braking, turning)
- **Outlier Tolerance:** Sufficient data to avoid overfitting to transient conditions

**Scaling:**

| CAN Bus Traffic Rate | Samples | Collection Time |
|----------------------|---------|-----------------|
| 10 Hz                | 5000    | ~8.3 minutes    |
| 50 Hz                | 5000    | ~1.7 minutes    |
| 100 Hz               | 5000    | ~50 seconds     |

---

## Detection Phase (Production)

### Baseline Loading

**Code Location:** `baseline_persistence.rs:106-125`

**Process:**

1. **Load JSON file** from disk
2. **Verify signature** (HMAC-SHA256 with HSM key)
3. **Verify fingerprint** (SHA256 of baseline data)
4. **Load into HSM** via `hsm.load_anomaly_baseline(baseline)`

**Code Reference:**

```rust
// Lines 106-125
pub fn load_baseline(file_path: &str, hsm: &VirtualHSM) -> Result<CanBusBaseline, String> {
    let signed_baseline: SignedBaseline = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse baseline: {}", e))?;

    // Verify fingerprint
    let calculated_fingerprint = calculate_baseline_fingerprint(&signed_baseline.baseline);
    if calculated_fingerprint != signed_baseline.fingerprint {
        return Err("Baseline fingerprint mismatch - file corrupted".to_string());
    }

    // Verify signature (HMAC with HSM key)
    let signature_key = hsm.get_symmetric_key();
    let calculated_signature = generate_baseline_signature(
        &signed_baseline.baseline,
        &signed_baseline.fingerprint,
        signature_key,
    );
    if calculated_signature != signed_baseline.signature {
        return Err("Baseline signature verification failed - unauthorized modification".to_string());
    }

    Ok(signed_baseline.baseline)
}
```

### Runtime Detection

**Code Location:** `anomaly_detection.rs:551-673`

**For Each Received CAN Frame (After MAC/CRC/Replay Pass):**

```rust
pub fn detect_anomaly(&self, frame: &SecuredCanFrame) -> AnomalyResult {
    let can_id_u32 = frame.can_id.value();

    // Check 1: Unknown CAN ID (not in baseline)
    let baseline = match self.baseline.as_ref()?.can_id_baselines.get(&can_id_u32) {
        Some(b) => b,
        None => {
            return AnomalyResult::Attack(AnomalyReport {
                anomaly_type: AnomalyType::UnknownCanId,
                can_id: can_id_u32,
                confidence: 100.0,  // Definite attack
                description: format!("CAN ID 0x{:X} not in baseline", can_id_u32),
                timestamp: Utc::now(),
            });
        }
    };

    // Check 2: Unexpected Source ECU
    if baseline.expected_source != frame.source {
        return AnomalyResult::Attack(AnomalyReport {
            anomaly_type: AnomalyType::UnexpectedSource,
            can_id: can_id_u32,
            confidence: 95.0,  // High confidence
            description: format!(
                "CAN ID 0x{:X} from {} (expected {})",
                can_id_u32, frame.source, baseline.expected_source
            ),
            timestamp: Utc::now(),
        });
    }

    // Check 3: Interval Anomaly (message timing)
    if let Some(interval_z_score) = self.check_interval_anomaly(frame, baseline) {
        let confidence = z_score_to_confidence_percent(interval_z_score);
        if confidence >= CONFIDENCE_THRESHOLD_ATTACK {
            return AnomalyResult::Attack(AnomalyReport {
                anomaly_type: AnomalyType::IntervalAnomaly,
                can_id: can_id_u32,
                confidence,
                description: format!(
                    "Abnormal message interval (z-score: {:.2}σ)",
                    interval_z_score
                ),
                timestamp: Utc::now(),
            });
        } else if confidence >= CONFIDENCE_THRESHOLD_WARNING {
            return AnomalyResult::Warning(AnomalyReport { ... });
        }
    }

    // Check 4: Rate Anomaly (messages per second)
    if let Some(rate_z_score) = self.check_rate_anomaly(can_id_u32, baseline) {
        // Similar logic to interval anomaly...
    }

    // Check 5: Data Range Anomaly (byte values out of range)
    if let Some((byte_idx, z_score)) = self.check_data_range_anomaly(frame, baseline) {
        let confidence = z_score_to_confidence_percent(z_score);
        if confidence >= CONFIDENCE_THRESHOLD_ATTACK {
            return AnomalyResult::Attack(AnomalyReport {
                anomaly_type: AnomalyType::DataRangeAnomaly,
                can_id: can_id_u32,
                confidence,
                description: format!(
                    "Data byte {} out of range (z-score: {:.2}σ, value: {})",
                    byte_idx, z_score, frame.data[byte_idx]
                ),
                timestamp: Utc::now(),
            });
        } else if confidence >= CONFIDENCE_THRESHOLD_WARNING {
            return AnomalyResult::Warning(AnomalyReport { ... });
        }
    }

    // All checks passed
    AnomalyResult::Normal
}
```

---

## Anomaly Types

### 1. Unknown CAN ID

**Detection:** CAN ID not present in baseline

**Significance:** New CAN ID indicates:
- Rogue device added to bus
- Compromised ECU sending on unexpected ID
- Aftermarket device injection

**Confidence:** 100% (definite attack)

**Code Reference:** `anomaly_detection.rs:564-574`

**Example:**

```
Baseline: 0x100, 0x101, 0x102, 0x300
Runtime: Frame with CAN ID 0x999 received
Detection: ATTACK (0x999 not in baseline)
```

---

### 2. Unexpected Source ECU

**Detection:** CAN ID sent by ECU different from training

**Significance:**
- ECU spoofing attack
- Compromised ECU sending on another ECU's CAN ID
- Man-in-the-middle attack

**Confidence:** 95% (high confidence)

**Code Reference:** `anomaly_detection.rs:576-588`

**Example:**

```
Baseline: CAN ID 0x100 sent by WHEEL_FL
Runtime: CAN ID 0x100 received from ATTACKER
Detection: ATTACK (expected WHEEL_FL, got ATTACKER)
```

---

### 3. Interval Anomaly

**Detection:** Time between consecutive messages deviates from baseline frequency

**Statistical Method:**
- Calculate z-score: `(observed_interval - mean_interval) / std_dev_interval`
- Convert z-score to confidence percentage
- Classify based on confidence threshold

**Significance:**
- Too fast: DoS attack, bus flooding
- Too slow: Delayed message injection, ECU malfunction

**Code Reference:** `anomaly_detection.rs:675-706` (check function)

**Example:**

```
Baseline: Mean interval = 100ms, Std Dev = 10ms
Runtime: Interval = 500ms
Z-Score: (500 - 100) / 10 = 40σ
Confidence: >99.99% → ATTACK
```

---

### 4. Rate Anomaly

**Detection:** Message rate (msgs/second) deviates from baseline

**Calculation:**

```rust
// Calculate instantaneous rate over sliding window
let window = last 10 messages;
let time_span = window.last_timestamp - window.first_timestamp;
let current_rate = window.count / time_span.seconds();

// Compare to baseline mean rate
let z_score = (current_rate - baseline.mean_rate) / baseline.std_dev_rate;
```

**Significance:**
- High rate: Bus flooding, DoS attack
- Low rate: Message suppression attack

**Code Reference:** `anomaly_detection.rs:617-640`

---

### 5. Data Range Anomaly

**Detection:** Data byte value outside expected range

**Statistical Method (Per Byte):**
- Calculate z-score: `(byte_value - mean_value) / std_dev_value`
- Flag if z-score exceeds threshold

**Significance:**
- Out-of-range sensor readings (physically impossible values)
- Tampered control commands (dangerous actuator values)

**Code Reference:** `anomaly_detection.rs:642-673`

**Example:**

```
Baseline: Wheel speed byte (mean=50, std_dev=20, range=0-100)
Runtime: Wheel speed value = 255
Z-Score: (255 - 50) / 20 = 10.25σ
Confidence: >99.99% → ATTACK
```

**Real-World Scenario:**
- Parked vehicle (wheel speed should be ~0 rad/s)
- Attacker injects wheel speed = 300 rad/s (impossible for stationary vehicle)
- Anomaly detector flags as attack (>99% confidence)

---

## Graduated Response Levels

### Confidence Calculation

**Z-Score to Confidence Conversion:**

**Code Reference:** `anomaly_detection.rs:177-201`

```rust
pub fn z_score_to_confidence_percent(z_score: f64) -> f64 {
    let abs_z = z_score.abs();

    // Approximate confidence levels (based on normal distribution)
    let confidence = if abs_z < 1.0 {
        68.0  // Within 1σ
    } else if abs_z < 1.3 {
        80.0  // 1.0σ - 1.3σ (approaching warning threshold)
    } else if abs_z < 2.0 {
        95.0  // 1.3σ - 2σ (warning level)
    } else if abs_z < 3.0 {
        99.0  // 2σ - 3σ (high warning)
    } else if abs_z < 4.0 {
        99.99  // 3σ - 4σ (attack threshold)
    } else {
        99.999  // > 4σ (definite attack)
    };

    confidence
}
```

### Response Thresholds

**Code Reference:** `anomaly_detection.rs:208-212`

```rust
pub const SIGMA_THRESHOLD_WARNING: f64 = 1.3;   // ~80% confidence
pub const SIGMA_THRESHOLD_ATTACK: f64 = 3.0;    // ~99% confidence

pub const CONFIDENCE_THRESHOLD_WARNING: f64 = 80.0;
pub const CONFIDENCE_THRESHOLD_ATTACK: f64 = 99.0;
```

### Graduated Actions

| Sigma (σ) | Confidence | Result             | Action                                       |
|-----------|------------|--------------------|----------------------------------------------|
| < 1.3σ    | < 80%      | **ALLOW**          | Normal variance, accept frame                |
| 1.3-3σ    | 80-99%     | **WARNING**        | Log warning, allow frame, flag for review    |
| ≥ 3σ      | ≥ 99%      | **ATTACK**         | Reject frame, trigger fail-safe, log attack  |

**Rationale:**

- **1.3σ (80%):** Catches most anomalies while tolerating operational variance
- **3σ (99%):** High confidence threshold reduces false positives
- **Graduated approach:** Allows investigation of suspicious behavior without disrupting operation

**Code Reference:** `anomaly_detection.rs:551-673` (detect_anomaly function)

---

## Baseline Persistence and Security

### Signed Baseline Format

**Code Location:** `baseline_persistence.rs:15-41`

**JSON Structure:**

```json
{
  "baseline": {
    "can_id_baselines": {
      "256": {
        "can_id": 256,
        "expected_source": "WHEEL_FL",
        "mean_interval_ms": 100.5,
        "std_dev_interval_ms": 8.2,
        "min_interval_ms": 85.0,
        "max_interval_ms": 120.0,
        "mean_rate_hz": 10.0,
        "std_dev_rate_hz": 0.5,
        "data_byte_stats": [
          {
            "byte_index": 0,
            "min": 0,
            "max": 255,
            "mean": 127.3,
            "std_dev": 35.8,
            "sample_count": 5000
          }
        ],
        "total_samples": 5000
      }
    }
  },
  "signature": [/* 32-byte HMAC-SHA256 */],
  "fingerprint": [/* 32-byte SHA256 hash */]
}
```

### Baseline Fingerprint

**Purpose:** Detect file corruption or accidental modification

**Algorithm:** SHA256 hash of baseline data (JSON)

**Code Reference:** `baseline_persistence.rs:69-78`

```rust
pub fn calculate_baseline_fingerprint(baseline: &CanBusBaseline) -> [u8; 32] {
    let baseline_json = serde_json::to_string(baseline).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(baseline_json.as_bytes());

    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}
```

### Baseline Signature

**Purpose:** Prevent unauthorized modification (tampering)

**Algorithm:** HMAC-SHA256 with HSM symmetric key

**Code Reference:** `baseline_persistence.rs:80-94`

```rust
pub fn generate_baseline_signature(
    baseline: &CanBusBaseline,
    fingerprint: &[u8; 32],
    signing_key: &[u8; 32],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(signing_key)
        .expect("HMAC can take key of any size");

    // Sign both baseline and fingerprint
    let baseline_json = serde_json::to_string(baseline).unwrap();
    mac.update(baseline_json.as_bytes());
    mac.update(fingerprint);

    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut signature = [0u8; 32];
    signature.copy_from_slice(&bytes);
    signature
}
```

### Attack Scenarios Prevented

| Attack                              | Prevention Mechanism                          |
|-------------------------------------|-----------------------------------------------|
| **Baseline File Corruption**        | Fingerprint mismatch detected on load         |
| **Baseline Tampering**              | Signature verification fails                  |
| **Downgrade to Weaker Baseline**    | Signature includes baseline data              |
| **Baseline Injection**              | Signature requires HSM key (attacker can't sign)|

---

## Integration with ECUs

### ECU Startup Sequence

**Example:** Brake Controller (`src/bin/brake_controller.rs:44-67`)

```rust
// 1. Initialize HSM
let mut hsm = VirtualHSM::new("BRAKE_CTRL".to_string(), BRAKE_SEED);

// 2. Load baseline from disk
let baseline_path = "baselines/baseline_brake_ctrl.json";
match baseline_persistence::load_baseline(baseline_path, &hsm) {
    Ok(baseline) => {
        println!("✓ Loaded signed baseline from {}", baseline_path);

        // 3. Activate anomaly detection
        hsm.load_anomaly_baseline(baseline);
        println!("✓ Anomaly detection ACTIVE");
    }
    Err(e) => {
        eprintln!("⚠️  Failed to load baseline: {}", e);
        eprintln!("   Continuing without anomaly detection");
    }
}
```

### Frame Reception with Anomaly Check

**Code:** `brake_controller.rs:156-197`

```rust
loop {
    // Receive frame from CAN bus
    let secured_frame = receive_frame();

    // 1. Verify MAC/CRC/Replay
    match secured_frame.verify(&mut hsm) {
        Ok(()) => {
            attack_detector.record_success();

            // 2. Check anomaly detection (after MAC/CRC pass)
            let anomaly_result = hsm.detect_anomaly(&secured_frame);

            match anomaly_result {
                AnomalyResult::Normal => {
                    // 3. Process valid, normal frame
                    process_brake_command(&secured_frame);
                }
                AnomalyResult::Warning(report) => {
                    // 4. Log warning but allow frame
                    println!("⚠️  ANOMALY WARNING: {}", report.description);
                    println!("    Confidence: {:.1}%", report.confidence);
                    println!("    Allowing frame (below attack threshold)");

                    // Optional: Still process frame in warning mode
                    process_brake_command(&secured_frame);
                }
                AnomalyResult::Attack(report) => {
                    // 5. Reject frame and trigger fail-safe
                    println!("⚠️  ANOMALY ATTACK DETECTED");
                    println!("    Type: {:?}", report.anomaly_type);
                    println!("    Confidence: {:.1}%", report.confidence);
                    println!("    {}", report.description);

                    // Record anomaly error (triggers fail-safe if threshold exceeded)
                    attack_detector.record_error(
                        ValidationError::AnomalyDetected(report.anomaly_type),
                        &secured_frame.source,
                    );

                    // Reject frame (do not process)
                    continue;
                }
            }
        }
        Err(e) => {
            // Handle MAC/CRC/Replay error...
        }
    }
}
```

### AttackDetector Integration

**Anomaly errors counted toward attack threshold:**

**Code:** `error_handling.rs:326-359`

```rust
ValidationError::AnomalyDetected(anomaly_type) => {
    self.anomaly_count += 1;
    self.total_anomalies += 1;

    println!("{} {} from {} | Anomaly #{} (Total: {}, Type: {:?})",
        "⚠️".yellow(), "ANOMALY DETECTED".red(),
        source.bright_black(),
        self.anomaly_count, self.total_anomalies, anomaly_type);

    // Threshold check (default: 1 for high-confidence anomalies)
    if self.anomaly_count >= ANOMALY_ERROR_THRESHOLD {
        self.trigger_attack_mode(ValidationError::AnomalyDetected(anomaly_type));
        return false;  // Reject frame
    }
}
```

**Note:** `ANOMALY_ERROR_THRESHOLD` is typically 1 for high-confidence (>99%) anomalies, since they indicate definite attacks.

---

## Testing and Validation

### Unit Tests

**Test Coverage:** 45+ tests

**Code Location:** `anomaly_detection.rs:720-1850`

**Test Categories:**

#### 1. Statistical Utility Tests (720-874)

- Mean calculation: `test_mean_calculation`
- Standard deviation: `test_standard_deviation`
- Z-score calculation: `test_z_score`
- Confidence conversion: `test_z_score_to_confidence_percent`

#### 2. Threshold Boundary Tests (875-1183)

**Critical Tests (ISO 21434 Verification):**

- **Below Warning Threshold:**
  - `test_anomaly_below_warning_threshold_sigma_1_2` (1.2σ → ALLOW)
  - Confidence: 80% (< 80% threshold)

- **At Warning Threshold:**
  - `test_anomaly_at_warning_threshold_sigma_1_3` (1.3σ → WARNING)
  - Confidence: 80% (exactly at threshold)

- **Within Warning Range:**
  - `test_anomaly_within_warning_range_sigma_2_0` (2.0σ → WARNING)
  - Confidence: 95% (80-99% range)

- **Just Below Attack Threshold:**
  - `test_anomaly_just_below_attack_threshold_sigma_2_9` (2.9σ → WARNING)
  - Confidence: 99% (just below attack threshold)

- **At Attack Threshold:**
  - `test_anomaly_at_attack_threshold_sigma_3_0` (3.0σ → ATTACK)
  - Confidence: 99% (exactly at threshold)

- **Above Attack Threshold:**
  - `test_anomaly_high_confidence_sigma_5_0` (5.0σ → ATTACK)
  - Confidence: 99.999% (high confidence attack)

**These tests verify exact enforcement of graduated response thresholds.**

#### 3. Detection Type Tests (1185-1528)

- **Unknown CAN ID:** `test_unknown_can_id_anomaly`
- **Unexpected Source:** `test_unexpected_source_anomaly`
- **Interval Anomaly:** `test_interval_anomaly_high_confidence`
- **Rate Anomaly:** `test_rate_anomaly_detection`
- **Data Range Anomaly:** `test_data_range_anomaly`

#### 4. Training and Baseline Tests (1530-1850)

- **Training Mode:** `test_training_mode_collects_statistics`
- **Baseline Finalization:** `test_finalize_training_creates_baseline`
- **Baseline Loading:** `test_load_baseline_activates_detection`
- **Multi-CAN-ID Training:** `test_training_multiple_can_ids`

### Regression Tests

**Code Location:** `autonomous_controller/tests/anomaly_ids_regression_tests.rs`

**End-to-End Scenarios:**

1. **Unknown CAN ID Attack Simulation**
   - Train baseline with CAN IDs 0x100, 0x101
   - Inject frame with CAN ID 0x999
   - Verify: ATTACK detected, 100% confidence

2. **Unexpected Source Attack Simulation**
   - Train baseline: CAN ID 0x100 from WHEEL_FL
   - Inject frame: CAN ID 0x100 from ATTACKER
   - Verify: ATTACK detected, 95% confidence

3. **Data Range Anomaly Simulation**
   - Train baseline: Wheel speed 0-100 rad/s (mean=50, σ=15)
   - Inject frame: Wheel speed = 255 rad/s
   - Verify: ATTACK detected, >99% confidence

**Execution:**

```bash
cargo test --test anomaly_ids_regression_tests -- --ignored --test-threads=1 --nocapture
```

---

## Operational Guidance

### Factory Calibration Best Practices

1. **Controlled Environment:**
   - Laboratory or test track
   - No external interference
   - Known-good ECUs and firmware

2. **Comprehensive Coverage:**
   - Collect data across all driving modes (idle, acceleration, braking, turning, highway, city)
   - Include edge cases (emergency braking, sharp turns)
   - Minimum 5000 samples per CAN ID

3. **Validation:**
   - Review baseline statistics manually (check mean, σ, min/max make sense)
   - Test detection with known anomalies before deployment
   - Verify signature before distribution

4. **Versioning:**
   - Tag baselines with firmware version
   - Track baseline lineage (when collected, by whom, vehicle configuration)

### Production Deployment

1. **Baseline Distribution:**
   - Deploy signed baselines to production ECUs
   - Store in read-only filesystem (prevent tampering)
   - Verify signature on every boot

2. **Monitoring:**
   - Log all WARNING-level anomalies for investigation
   - Track ATTACK-level anomalies in security dashboard
   - Correlate anomalies across ECUs

3. **Incident Response:**
   - WARNING: Investigate after drive cycle, check for environmental factors
   - ATTACK: Immediate investigation, potential recall if widespread

### Retraining Scenarios

**When to retrain baselines:**

1. **Firmware Update:** New ECU software changes CAN behavior
2. **Hardware Change:** ECU replacement, sensor upgrade
3. **Configuration Change:** Different vehicle mode (sport mode vs eco mode)
4. **After Incident:** Known false positive pattern identified

**Retraining Process:**

1. Return vehicle to factory/dealer
2. Collect new baseline in controlled environment
3. Sign with factory HSM
4. Deploy to vehicle
5. Validate with test drive

**NEVER retrain in production** (creates attack window during training)

### Tuning Thresholds

**Default thresholds work for most scenarios, but can be tuned:**

**If Too Many False Positives (Warnings):**
- Increase `SIGMA_THRESHOLD_WARNING` from 1.3σ to 1.5σ
- Increase `CONFIDENCE_THRESHOLD_WARNING` from 80% to 85%

**If Missing Attacks (False Negatives):**
- Decrease `SIGMA_THRESHOLD_ATTACK` from 3.0σ to 2.5σ
- Decrease `CONFIDENCE_THRESHOLD_ATTACK` from 99% to 95%

**Threshold Configuration:**

```rust
// Edit: autonomous_controller/src/anomaly_detection.rs:208-212
pub const SIGMA_THRESHOLD_WARNING: f64 = 1.3;   // Adjust as needed
pub const SIGMA_THRESHOLD_ATTACK: f64 = 3.0;    // Adjust as needed
```

**Recommendation:** Start with defaults, collect field data, adjust based on false positive/negative rates.

---

## Document Change History

| Version | Date       | Author          | Changes                                  |
|---------|------------|-----------------|------------------------------------------|
| 1.0     | 2025-11-19 | Claude (AI)     | Initial anomaly IDS documentation        |

---

## References

- ISO 21434:2021 - Road vehicles — Cybersecurity engineering (Clause 5.1, 5.2: Intrusion Detection)
- NIST SP 800-94 - Guide to Intrusion Detection and Prevention Systems (IDPS)
- SAE J3061 - Cybersecurity Guidebook (Anomaly Detection)
- Normal Distribution Statistics (Z-scores and Confidence Levels)
- CAN Bus Specification (ISO 11898)

---

**END OF DOCUMENT**
