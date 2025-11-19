# Cybersecurity Overview - Virtual HSM for CAN Bus Security

**Document Version:** 1.0
**Last Updated:** 2025-11-19
**ISO 21434 Compliance:** Automotive Cybersecurity Engineering
**Project:** rust-v-hsm-can - Autonomous Vehicle CAN Bus Security System

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Security Features Overview](#security-features-overview)
4. [ISO 21434 Compliance](#iso-21434-compliance)
5. [Threat Model](#threat-model)
6. [Documentation Structure](#documentation-structure)
7. [Traceability Matrix](#traceability-matrix)

---

## Executive Summary

This project implements a comprehensive cybersecurity solution for automotive CAN bus systems, specifically designed for autonomous vehicle applications. The system provides defense-in-depth protection against a wide range of automotive cyber threats as defined in ISO 21434 and NIST Cybersecurity Framework.

### Key Security Capabilities

1. **Message Authentication (MAC/HMAC)** - HMAC-SHA256 authentication prevents spoofing and tampering
2. **Integrity Protection (CRC32)** - Detects transmission errors and data corruption
3. **Replay Protection** - Sliding window counter-based anti-replay mechanism
4. **Access Control** - CAN ID-based authorization with TX/RX whitelists
5. **Anomaly Detection** - Statistical baseline profiling for behavioral IDS
6. **Cryptographic Key Management** - HKDF-based key rotation with session keys
7. **Attack Detection & Fail-Safe** - Threshold-based attack detection with protective modes
8. **Secure Boot & Firmware Verification** - HMAC-signed firmware with integrity checks
9. **Security Logging & Auditing** - Comprehensive event logging for incident response
10. **Encrypted Communication** - AES-256-GCM authenticated encryption (optional)

### Security Assurance

- **159+ automated security tests** covering normal and attack scenarios
- **Regression test suites** for MAC/CRC attacks, replay attacks, access control violations, and anomaly detection
- **Threshold boundary testing** ensuring exact security enforcement at defined limits
- **Attack simulation framework** for validation and testing

---

## System Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   CAN Bus (Virtual)                         │
│              Broadcast Communication Medium                 │
└─────────────────┬───────────────────────────────────────────┘
                  │
        ┌─────────┴─────────┬─────────────────┬───────────────┐
        │                   │                 │               │
┌───────▼────────┐  ┌───────▼────────┐  ┌────▼──────┐  ┌────▼──────┐
│  Sensor ECUs   │  │ Controller ECU │  │ Actuator  │  │  Monitor  │
│  (6 units)     │  │  (1 unit)      │  │ ECUs      │  │           │
│                │  │                │  │ (2 units) │  │           │
│ • Wheel FL/FR  │  │ • Autonomous   │  │           │  │           │
│ • Wheel RL/RR  │  │   Controller   │  │ • Brake   │  │           │
│ • Engine       │  │                │  │ • Steering│  │           │
│ • Steering     │  │                │  │           │  │           │
└───────┬────────┘  └───────┬────────┘  └────┬──────┘  └────┬──────┘
        │                   │                 │               │
┌───────▼───────────────────▼─────────────────▼───────────────▼──────┐
│              Virtual Hardware Security Module (V-HSM)              │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ Cryptography │  │ Key Rotation │  │  Anomaly IDS │            │
│  │   Engine     │  │   Manager    │  │              │            │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤            │
│  │ • HMAC-SHA256│  │ • HKDF-SHA256│  │ • Statistical│            │
│  │ • CRC32      │  │ • Session    │  │   Profiling  │            │
│  │ • AES-256-GCM│  │   Keys       │  │ • Graduated  │            │
│  │ • SHA256     │  │ • Grace      │  │   Response   │            │
│  └──────────────┘  │   Period     │  └──────────────┘            │
│                    └──────────────┘                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ Replay       │  │ Access       │  │ Attack       │            │
│  │ Protection   │  │ Control      │  │ Detector     │            │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤            │
│  │ • Sliding    │  │ • TX/RX      │  │ • Threshold  │            │
│  │   Window     │  │   Whitelists │  │   Based      │            │
│  │ • Counter    │  │ • CAN ID     │  │ • Fail-Safe  │            │
│  │   Tracking   │  │   Permissions│  │   Modes      │            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

1. **Network Boundary:** CAN bus (untrusted broadcast medium)
2. **Application Boundary:** ECU software/firmware
3. **Cryptographic Boundary:** Virtual HSM (trusted computing base)
4. **Trust Boundary:** Symmetric key distribution (pre-shared keys)

---

## Security Features Overview

### 1. Message Authentication Code (MAC/HMAC)

**Purpose:** Authenticate CAN frame origin and prevent spoofing attacks

**Implementation:**
- Algorithm: HMAC-SHA256
- Output: 256-bit authentication tag
- Constant-time verification (timing attack resistant)

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/crypto.rs:9-78`
- Integration: `autonomous_controller/src/hsm/secured_frame.rs:66-91`
- Testing: `autonomous_controller/src/hsm/mod.rs:33-45`

**ISO 21434 Mapping:** CAL-3.1, CAL-3.2 (Cryptographic authentication)

---

### 2. Cyclic Redundancy Check (CRC32)

**Purpose:** Detect transmission errors and data integrity violations

**Implementation:**
- Algorithm: CRC-32-ISO-HDLC
- Coverage: CAN ID + Data + Source + Session Counter
- Fast-fail verification (checked before MAC)

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/crypto.rs:81-133`
- Integration: `autonomous_controller/src/hsm/secured_frame.rs:93-106`
- Testing: `autonomous_controller/src/hsm/mod.rs:48-62`

**ISO 21434 Mapping:** CAL-2.1 (Integrity protection)

---

### 3. Replay Protection

**Purpose:** Prevent replay attacks using captured CAN frames

**Implementation:**
- Sliding window counter (configurable window size: 100)
- Per-ECU counter tracking
- Out-of-order tolerance within window
- Timestamp validation (optional, 60-second max age)

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/replay.rs:1-166`
- Configuration: `autonomous_controller/src/hsm/replay.rs:7-31`
- Testing: `autonomous_controller/src/hsm/replay.rs:168-923`

**ISO 21434 Mapping:** CAL-3.3 (Anti-replay mechanisms)

---

### 4. Access Control

**Purpose:** Enforce principle of least privilege for CAN ID usage

**Implementation:**
- TX whitelist: CAN IDs authorized for transmission
- RX whitelist: CAN IDs authorized for reception
- Per-ECU policy enforcement
- Violation triggers immediate fail-safe

**Code Location:**
- Policy Definition: `autonomous_controller/src/access_control.rs:10-78`
- Enforcement: `autonomous_controller/src/hsm/core.rs` (authorize_transmit/authorize_receive)
- Testing: `autonomous_controller/src/access_control.rs:86-144`

**ISO 21434 Mapping:** CAL-4.1, CAL-4.2 (Authorization mechanisms)

**Access Control Matrix:**

| ECU                | TX Whitelist (CAN IDs)                          | RX Whitelist (CAN IDs)                                                    |
|--------------------|-------------------------------------------------|---------------------------------------------------------------------------|
| WHEEL_FL           | 0x100 (Wheel Speed FL)                          | Any (sensors don't filter RX)                                             |
| WHEEL_FR           | 0x101 (Wheel Speed FR)                          | Any                                                                       |
| WHEEL_RL           | 0x102 (Wheel Speed RL)                          | Any                                                                       |
| WHEEL_RR           | 0x103 (Wheel Speed RR)                          | Any                                                                       |
| ENGINE_ECU         | 0x110 (RPM), 0x111 (Throttle)                   | 0x301 (Throttle Command)                                                  |
| STEERING_SENSOR    | 0x120 (Angle), 0x121 (Torque)                   | Any                                                                       |
| AUTONOMOUS_CTRL    | 0x200-0x201 (Status/Trajectory), 0x300-0x302 (Commands) | 0x100-0x103, 0x110-0x111, 0x120-0x121 (All sensors)                       |
| BRAKE_CTRL         | None (actuator, RX only)                        | 0x300 (Brake Command)                                                     |
| STEERING_CTRL      | None (actuator, RX only)                        | 0x302 (Steering Command)                                                  |

---

### 5. Anomaly-Based Intrusion Detection System (IDS)

**Purpose:** Detect zero-day attacks and behavioral deviations

**Implementation:**
- Statistical baseline profiling (factory calibration)
- Graduated response levels (80% warning, 99% attack)
- Anomaly types: Unknown CAN ID, unexpected source, interval anomaly, rate anomaly, data range anomaly
- Training requirement: 1000+ samples per CAN ID

**Code Location:**
- Core Implementation: `autonomous_controller/src/anomaly_detection.rs:1-1851`
- Baseline Persistence: `autonomous_controller/src/baseline_persistence.rs`
- Calibration Tool: `autonomous_controller/src/bin/calibrate_anomaly_baseline.rs`
- Integration: `autonomous_controller/src/bin/brake_controller.rs:156-197`

**ISO 21434 Mapping:** CAL-5.1, CAL-5.2 (Intrusion detection)

**Anomaly Detection Thresholds:**

| Confidence Level | Sigma (σ) | Action        | Use Case                                      |
|------------------|-----------|---------------|-----------------------------------------------|
| < 80%            | < 1.3σ    | ALLOW         | Within normal variance                        |
| 80-99%           | 1.3-3σ    | WARNING       | Unusual but tolerable, log for investigation  |
| > 99%            | > 3σ      | ATTACK        | High confidence anomaly, trigger fail-safe    |

---

### 6. Cryptographic Key Management

**Purpose:** Secure key lifecycle and rotation

**Implementation:**
- HKDF-SHA256 key derivation from master key
- Session key rotation (time-based: 5 min, counter-based: 10k frames)
- Grace period for key transition (60 seconds)
- Key versioning and rollback protection
- AES-256-GCM encrypted key distribution

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/key_rotation.rs:1-858`
- Key Derivation: `autonomous_controller/src/hsm/key_rotation.rs:409-434`
- Encryption: `autonomous_controller/src/hsm/key_rotation.rs:448-540`
- Testing: `autonomous_controller/src/hsm/key_rotation.rs:543-857`

**ISO 21434 Mapping:** CAL-6.1, CAL-6.2 (Key management)

---

### 7. Attack Detection & Fail-Safe Modes

**Purpose:** Detect sustained attack patterns and enter protective state

**Implementation:**
- Error thresholds: CRC (5), MAC (3), Unsecured (1), Replay (1), Anomaly (1)
- Security states: Normal → Warning → UnderAttack
- Fail-safe actions: Reject frames, maintain last safe state, log events
- Recovery: Automatic recovery from Warning, manual reset from UnderAttack

**Code Location:**
- Implementation: `autonomous_controller/src/error_handling.rs:1-1115`
- State Machine: `autonomous_controller/src/error_handling.rs:53-72`
- Threshold Configuration: `autonomous_controller/src/error_handling.rs:10-14`
- Integration: All ECU binaries (brake_controller.rs, steering_controller.rs, autonomous_controller.rs)

**ISO 21434 Mapping:** CAL-7.1, CAL-7.2 (Attack detection and response)

**Attack Detection Thresholds:**

| Error Type        | Threshold | Rationale                                             | Code Reference                                  |
|-------------------|-----------|-------------------------------------------------------|-------------------------------------------------|
| CRC Mismatch      | 5         | Tolerate occasional noise/interference                | error_handling.rs:11                            |
| MAC Mismatch      | 3         | Lower tolerance for authentication failures           | error_handling.rs:12                            |
| Unsecured Frame   | 1         | Immediate trigger - no tolerance for unauthenticated  | error_handling.rs:13                            |
| Replay Attack     | 1         | Immediate trigger - definitive attack indicator       | error_handling.rs:14                            |
| Anomaly (High)    | 1         | Immediate trigger for >99% confidence anomalies       | error_handling.rs:350                           |

---

### 8. Secure Boot & Firmware Verification

**Purpose:** Ensure firmware integrity and authenticity

**Implementation:**
- SHA256 firmware fingerprinting
- HMAC-SHA256 firmware signature
- Signed firmware packages
- Update authorization tokens

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/crypto.rs:136-208`
- Firmware Structure: `autonomous_controller/src/hsm/firmware.rs`
- Testing: `autonomous_controller/src/hsm/mod.rs:65-96`

**ISO 21434 Mapping:** CAL-8.1 (Secure software updates)

---

### 9. Security Logging & Event Correlation

**Purpose:** Forensic analysis and incident response

**Implementation:**
- Structured event logging (JSON)
- Event types: FrameValidated, FrameRejected, AttackDetected, StateChange, FailSafeActivated, SecurityReset
- Timestamp correlation
- Log persistence to disk

**Code Location:**
- Implementation: `autonomous_controller/src/security_log.rs`
- Log Analysis: `autonomous_controller/src/bin/security_log_analyzer.rs`
- Event Correlation: `autonomous_controller/src/security_correlation.rs`

**ISO 21434 Mapping:** CAL-9.1, CAL-9.2 (Security logging and monitoring)

---

### 10. Authenticated Encryption (AES-256-GCM)

**Purpose:** Optional confidentiality for sensitive CAN data

**Implementation:**
- Algorithm: AES-256-GCM (NIST SP 800-38D)
- Key size: 256 bits
- Nonce: 96 bits (randomized)
- Authentication tag: 128 bits
- Associated data: CAN ID, ECU name

**Code Location:**
- Implementation: `autonomous_controller/src/hsm/crypto.rs:210-305`
- Testing: `autonomous_controller/src/hsm/crypto.rs:308-528`

**ISO 21434 Mapping:** CAL-10.1 (Confidentiality protection)

---

## ISO 21434 Compliance

### Compliance Statement

This system implements cybersecurity controls aligned with ISO 21434:2021 "Road vehicles — Cybersecurity engineering". The following clauses are addressed:

**Clause 9: Cybersecurity Assurance**
- Comprehensive testing with 159+ security tests
- Attack simulation framework
- Regression test coverage

**Clause 10: Production, Operation, Maintenance, and Decommissioning**
- Key rotation and lifecycle management
- Firmware update mechanisms
- Security logging and monitoring

**Clause 11: Threat Analysis and Risk Assessment (TARA)**
- TARA implementation: `autonomous_controller/src/tara.rs`
- TARA report generation: `autonomous_controller/src/bin/generate_tara_report.rs`
- Threat catalog with CVSS scores and mitigations

**Clause 12: Cybersecurity Requirements**
- Requirements traceability (see Section 7)
- Detailed implementation mappings

For detailed ISO 21434 compliance mapping, see: [01_ISO21434_COMPLIANCE.md](01_ISO21434_COMPLIANCE.md)

---

## Threat Model

### Threat Actors

1. **External Attackers** - Remote exploitation via wireless interfaces
2. **Proximity Attackers** - Physical access to OBD-II or internal CAN bus
3. **Supply Chain Attackers** - Compromised components or aftermarket devices
4. **Insider Threats** - Malicious dealer/service center personnel

### Attack Vectors

1. **CAN Bus Injection** - Injecting malicious frames onto the bus
2. **Replay Attacks** - Capturing and replaying legitimate frames
3. **Spoofing Attacks** - Impersonating authorized ECUs
4. **Denial of Service** - Bus flooding or targeted jamming
5. **Data Corruption** - Tampering with frame data
6. **Firmware Tampering** - Malicious firmware updates

### Mitigations

| Threat                     | Mitigation                              | Effectiveness | Code Reference                    |
|----------------------------|-----------------------------------------|---------------|-----------------------------------|
| CAN Frame Injection        | MAC authentication                      | High          | hsm/crypto.rs:9-78                |
| Replay Attack              | Counter-based replay protection         | High          | hsm/replay.rs:106-165             |
| ECU Spoofing               | HMAC-SHA256 + Trusted key registry      | High          | hsm/secured_frame.rs:93-167       |
| Data Corruption            | CRC32 integrity check                   | Medium        | hsm/crypto.rs:81-133              |
| DoS (Bus Flooding)         | Rate limiting (future), Anomaly IDS     | Medium        | anomaly_detection.rs:617-640      |
| Unauthorized CAN ID Access | Access control whitelists               | High          | access_control.rs:10-78           |
| Zero-Day Attacks           | Anomaly-based IDS                       | Medium        | anomaly_detection.rs:552-673      |
| Firmware Tampering         | Signed firmware + Secure boot           | High          | hsm/firmware.rs                   |
| Key Compromise             | Key rotation + Grace periods            | Medium        | hsm/key_rotation.rs:211-407       |

For detailed threat analysis, see: [02_THREAT_MODEL.md](02_THREAT_MODEL.md)

---

## Documentation Structure

This cybersecurity documentation is organized as follows:

```
doc/
├── 00_CYBERSECURITY_OVERVIEW.md          (This document)
├── 01_ISO21434_COMPLIANCE.md             (ISO 21434 detailed compliance mapping)
├── 02_THREAT_MODEL.md                    (TARA and threat analysis)
├── 03_MAC_HMAC_AUTHENTICATION.md         (Message authentication system)
├── 04_REPLAY_PROTECTION.md               (Anti-replay mechanisms)
├── 05_ACCESS_CONTROL.md                  (Authorization and least privilege)
├── 06_ANOMALY_IDS.md                     (Intrusion detection system)
├── 07_KEY_ROTATION.md                    (Cryptographic key management)
├── 08_ATTACK_DETECTION.md                (Attack detection and fail-safe)
├── 09_FIRMWARE_SECURITY.md               (Secure boot and updates)
├── 10_SECURITY_LOGGING.md                (Event logging and forensics)
├── 11_TESTING_VALIDATION.md              (Security testing methodology)
└── 12_DEPLOYMENT_GUIDE.md                (Production deployment guide)
```

---

## Traceability Matrix

### Security Requirements → Implementation

| Requirement ID | Requirement Description                          | Implementation                          | Test Coverage                                     | Code Reference                      |
|----------------|--------------------------------------------------|-----------------------------------------|---------------------------------------------------|-------------------------------------|
| SEC-REQ-001    | CAN frames SHALL be authenticated with MAC       | HMAC-SHA256                             | hsm/mod.rs:33-45, crypto.rs:308-328               | hsm/crypto.rs:9-78                  |
| SEC-REQ-002    | CAN frames SHALL have integrity protection       | CRC32-ISO-HDLC                          | hsm/mod.rs:48-62, crypto.rs:331-444               | hsm/crypto.rs:81-133                |
| SEC-REQ-003    | System SHALL prevent replay attacks              | Sliding window counter                  | hsm/replay.rs:168-923                             | hsm/replay.rs:106-165               |
| SEC-REQ-004    | ECUs SHALL have least privilege CAN ID access    | TX/RX whitelists                        | access_control.rs:86-144                          | access_control.rs:10-78             |
| SEC-REQ-005    | System SHALL detect behavioral anomalies        | Statistical IDS                         | anomaly_detection.rs:720-1850                     | anomaly_detection.rs:402-712        |
| SEC-REQ-006    | Cryptographic keys SHALL be rotated              | HKDF + Session keys                     | key_rotation.rs:543-857                           | key_rotation.rs:211-407             |
| SEC-REQ-007    | System SHALL detect and respond to attacks      | Threshold-based detector                | error_handling.rs:764-1114                        | error_handling.rs:109-719           |
| SEC-REQ-008    | Firmware SHALL be verified before execution      | HMAC-signed firmware                    | hsm/mod.rs:65-96                                  | hsm/firmware.rs                     |
| SEC-REQ-009    | Security events SHALL be logged                  | Structured JSON logging                 | security_log.rs tests                             | security_log.rs                     |
| SEC-REQ-010    | Sensitive data SHALL be encrypted                | AES-256-GCM                             | crypto.rs:308-528                                 | crypto.rs:210-305                   |

### ISO 21434 Requirements → Security Controls

| ISO 21434 Clause | Control Area                    | Implementation                  | Validation                           |
|------------------|---------------------------------|---------------------------------|--------------------------------------|
| CAL-3.1          | Cryptographic authentication    | HMAC-SHA256 MAC                 | 159+ tests, regression suites        |
| CAL-3.2          | Authentication key management   | HKDF-SHA256 key derivation      | key_rotation.rs tests                |
| CAL-3.3          | Anti-replay mechanisms          | Sliding window counters         | replay.rs tests (168-923)            |
| CAL-2.1          | Integrity protection            | CRC32-ISO-HDLC                  | crypto.rs tests                      |
| CAL-4.1          | Authorization mechanisms        | CAN ID whitelists               | access_control.rs tests              |
| CAL-5.1          | Intrusion detection             | Anomaly-based IDS               | anomaly_ids_regression_tests.rs      |
| CAL-6.1          | Key lifecycle management        | Session key rotation            | key_rotation.rs tests                |
| CAL-7.1          | Attack detection and response   | Threshold-based fail-safe       | attack_regression_tests.rs           |
| CAL-8.1          | Secure software updates         | Signed firmware                 | firmware.rs tests                    |
| CAL-9.1          | Security logging                | Structured event logs           | security_log.rs tests                |

---

## Security Testing Summary

### Test Coverage Statistics

- **Total Tests:** 159+ automated security tests
- **Unit Tests:** 133 tests
- **Integration Tests:** 14 tests
- **Regression Test Suites:** 4 suites (12+ tests)

### Regression Test Suites

1. **MAC/CRC Attack Tests** - `tests/attack_regression_tests.rs`
   - Unsecured frame injection
   - MAC corruption attacks
   - CRC tampering detection

2. **Access Control Tests** - `tests/access_control_regression_tests.rs`
   - Unauthorized TX attempts
   - Unauthorized RX filtering
   - Policy enforcement

3. **Replay Attack Tests** - `tests/replay_protection_regression_tests.rs`
   - Counter duplication
   - Out-of-window replays
   - Timestamp validation

4. **Anomaly IDS Tests** - `autonomous_controller/tests/anomaly_ids_regression_tests.rs`
   - Unknown CAN ID detection
   - Unexpected source detection
   - Data range violations

### Test Execution

```bash
# Run all CI tests (recommended)
./run_ci_tests.sh

# Run specific test suites
cargo test --workspace --lib                                    # Unit tests (133)
cargo test --workspace --test integration_tests                 # Integration tests (14)
cargo test --test attack_regression_tests -- --ignored          # Attack tests
cargo test --test anomaly_ids_regression_tests -- --ignored     # Anomaly IDS tests
```

---

## Production Deployment Considerations

### Security Recommendations

1. **Use In-Process Mode for Production**
   - Networked mode (TCP) is for development/testing only
   - In-process `VirtualCanBus` eliminates network attack surface
   - See CLAUDE.md for architecture details

2. **Enable All Security Features**
   - MAC/HMAC authentication (mandatory)
   - Replay protection (mandatory)
   - Access control (mandatory)
   - Anomaly IDS (recommended - requires factory calibration)
   - Key rotation (recommended for long-running systems)

3. **Factory Calibration**
   - Collect anomaly baseline in controlled environment (5000+ samples per CAN ID)
   - Sign baselines with HSM
   - Never retrain baselines in production

4. **Key Management**
   - Use hardware-backed key storage (TPM, Secure Element) in production
   - Implement secure key distribution protocol
   - Enable key rotation for systems with high message rates

5. **Monitoring and Incident Response**
   - Enable security logging
   - Implement log aggregation and correlation
   - Define incident response procedures
   - Regular security log reviews

---

## Document Change History

| Version | Date       | Author          | Changes                              |
|---------|------------|-----------------|--------------------------------------|
| 1.0     | 2025-11-19 | Claude (AI)     | Initial comprehensive documentation  |

---

## References

- ISO 21434:2021 - Road vehicles — Cybersecurity engineering
- NIST SP 800-38D - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
- NIST SP 800-108 - Recommendation for Key Derivation Using Pseudorandom Functions (HKDF)
- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
- CAN Bus Specification (ISO 11898)
- Automotive Cybersecurity Best Practices (SAE J3061)

---

**END OF DOCUMENT**
