# Multi-Core Architecture Implementation Plan

## Progress Tracking

### Phase 1: HSM Service Foundation
- [x] Create protocol module (protocol.rs) - ✓ DONE
- [x] Create server module (server.rs) - ✓ DONE
- [x] Create client library (client.rs) - ✓ DONE
- [x] Create binary entry point (bin/hsm_service.rs) - ✓ DONE
- [x] Create module exports (hsm_service/mod.rs) - ✓ DONE
- [ ] Test standalone HSM service - BLOCKED: Need to update lib.rs first

### Phase 2: Core Affinity Integration
- [ ] Create core affinity config module
- [ ] Update Cargo.toml (add core_affinity, hsm_service binary)
- [ ] Update lib.rs exports
- [ ] Update main.rs launcher (HSM service + core pinning)
- [ ] Verify core pinning with htop

### Phase 3: ECU Migration
- [ ] Migrate wheel_fl.rs to HsmClient
- [ ] Migrate wheel_fr.rs to HsmClient
- [ ] Migrate wheel_rl.rs to HsmClient
- [ ] Migrate wheel_rr.rs to HsmClient
- [ ] Migrate engine_ecu.rs to HsmClient
- [ ] Migrate steering_sensor.rs to HsmClient
- [ ] Migrate autonomous_controller.rs to HsmClient
- [ ] Migrate brake_controller.rs to HsmClient
- [ ] Migrate steering_controller.rs to HsmClient

### Phase 4: Testing & Validation
- [ ] Run full CI test suite (159+ tests)
- [ ] Performance measurement
- [ ] Update CHANGELOG.md

### Blockers / Notes
- **Phase 1 Status**: 5/6 tasks complete. Need to update lib.rs to export hsm_service module before testing.
- **Current compilation error**: `unresolved import autonomous_vehicle_sim::hsm_service` - Expected, will fix in Phase 2 when updating lib.rs
- **Next steps**: Update lib.rs, Cargo.toml, then create core affinity module

---

## User Requirements (Confirmed)
1. ✓ **Keep process-based architecture** with core affinity pinning
2. ✓ **Centralized HSM Service** on dedicated Core 3
3. ✓ **Skip Zephyr integration** initially (focus on multi-core first)

## Target Architecture

### Core Assignment (Raspberry Pi 4 - 4x Cortex-A72)

```
┌──────────┬──────────┬──────────┬────────────────────┐
│  Core 0  │  Core 1  │  Core 2  │      Core 3        │
├──────────┼──────────┼──────────┼────────────────────┤
│  Bus     │ Sensors  │ Controls │  HSM Service       │
│  Server  │ (TX)     │ (TX+RX)  │  (Crypto Engine)   │
│  Monitor │          │          │                    │
│          │ 6 ECUs   │ 3 ECUs   │ • MAC gen/verify   │
│          │ • Wheels │ • Auto   │ • CRC calc/verify  │
│          │   (4x)   │   Ctrl   │ • Replay protect   │
│          │ • Engine │ • Brake  │ • Anomaly detect   │
│          │ • Steer  │   Ctrl   │ • Session counters │
│          │   Sensor │ • Steer  │ • Access control   │
│          │          │   Ctrl   │                    │
└──────────┴──────────┴──────────┴────────────────────┘
```

### Communication Architecture

```
Old: ECU → VirtualHSM (local) → MAC/CRC
New: ECU → Unix Socket → HSM Service (Core 3) → MAC/CRC
```

**IPC Mechanism**: Unix Domain Sockets (`/tmp/vsm_hsm_service.sock`)
- 5-20µs latency vs direct function call
- Connection-oriented, secure, debuggable
- JSON protocol with length-prefixed messages

---

## Implementation Phases

### Phase 1: HSM Service Foundation (Week 1)

**Create new HSM service infrastructure:**

#### New Files
1. `src/hsm_service/mod.rs` - Module exports
2. `src/hsm_service/protocol.rs` - HsmRequest/HsmResponse enums
3. `src/hsm_service/server.rs` - HSM service server (Unix socket listener)
4. `src/hsm_service/client.rs` - HsmClient (mirrors VirtualHSM API)
5. `src/bin/hsm_service.rs` - Binary entry point

#### Protocol Design
```rust
pub enum HsmRequest {
    GenerateMac { ecu_id: String, data: Vec<u8>, session_counter: u64 },
    VerifyFrame { ecu_id: String, frame: SecuredCanFrame },
    GetSessionCounter { ecu_id: String },
    IncrementSession { ecu_id: String },
    AddTrustedEcu { ecu_id: String, trusted_ecu_name: String, mac_key: [u8; 32] },
    DetectAnomaly { ecu_id: String, frame: SecuredCanFrame },
    LoadAnomalyBaseline { ecu_id: String, baseline: AnomalyBaseline },
    CalculateCrc { ecu_id: String, data: Vec<u8> },
    VerifyCrc { ecu_id: String, data: Vec<u8>, expected_crc: u32 },
    AuthorizeTransmit { ecu_id: String, can_id: u32 },
    LoadAccessControl { ecu_id: String, permissions: CanIdPermissions },
    Shutdown,
}

pub enum HsmResponse {
    MacGenerated { mac: [u8; 32] },
    FrameVerified { result: Result<(), VerifyError> },
    SessionCounter { counter: u64 },
    SessionIncremented { new_counter: u64 },
    AnomalyDetected { result: AnomalyResult },
    Error { message: String },
    Ack,
}
```

#### Key Implementation Details
- **Per-ECU HSM instances**: Server maintains `HashMap<String, VirtualHSM>`
- **Async request handling**: Tokio tasks per connection
- **Length-prefixed protocol**: `[4-byte len][JSON payload]`
- **Max message size**: 1MB (DoS prevention)

**Testing**: Unit tests for protocol serialization, integration test with single client

**Deliverable**: Standalone HSM service that handles requests from test client

---

### Phase 2: Core Affinity Integration (Week 2)

**Add CPU core pinning to all processes:**

#### New Files
1. `src/core_affinity_config.rs` - Core assignment configuration

#### Modified Files
1. `src/main.rs` - Launch HSM service first, pin all processes
2. `Cargo.toml` - Add `core_affinity = "0.8"`, add `[[bin]]` for hsm_service
3. `src/lib.rs` - Export hsm_service module

#### Core Pinning Strategy
```rust
pub fn get_assignment(component: &str) -> Option<usize> {
    match component {
        "bus_server" | "monitor" => Some(0),
        "wheel_fl" | "wheel_fr" | "wheel_rl" | "wheel_rr"
        | "engine_ecu" | "steering_sensor" => Some(1),
        "autonomous_controller" | "brake_controller"
        | "steering_controller" => Some(2),
        "hsm_service" => Some(3),
        _ => None,
    }
}
```

#### Launcher Updates (main.rs)
1. Start HSM service **before** bus_server
2. Wait for HSM readiness (2s)
3. Launch bus_server (Core 0)
4. Launch all sensor ECUs (Core 1)
5. Launch controller + actuators (Core 2)
6. Launch monitor (Core 0)
7. Graceful fallback if pinning fails

**Testing**: Verify with `htop` or `ps -eLo pid,psr,comm`

**Deliverable**: All processes pinned to assigned cores

---

### Phase 3: ECU Migration to HsmClient (Weeks 3-4)

**Replace VirtualHSM with HsmClient in all 9 ECUs:**

#### Migration Order (one at a time, test each)
1. **Sensor ECUs** (6 ECUs) - Low risk, stateless
   - wheel_fl.rs, wheel_fr.rs, wheel_rl.rs, wheel_rr.rs
   - engine_ecu.rs, steering_sensor.rs
2. **Controller ECU** (1 ECU) - Medium risk, stateful
   - autonomous_controller.rs
3. **Actuator ECUs** (2 ECUs) - Low risk, receivers
   - brake_controller.rs, steering_controller.rs

#### Migration Pattern (example: wheel_fl.rs:39)
```rust
// OLD CODE (line 39)
let mut hsm = VirtualHSM::with_performance(ECU_NAME.to_string(), HSM_SEED, perf_mode);

// NEW CODE
use autonomous_vehicle_sim::hsm_service::HsmClient;
let hsm_client = HsmClient::connect(
    ECU_NAME.to_string(),
    "/tmp/vsm_hsm_service.sock"
).await?;
```

#### Key Changes Per ECU
- Remove `HSM_SEED` constant (no longer needed)
- Change all HSM operations to async:
  - `hsm.generate_mac()` → `hsm_client.generate_mac().await?`
  - `frame.verify(&mut hsm)` → `hsm_client.verify_frame(&frame).await?`
- Update error handling for IPC failures
- Access control: `hsm.load_access_control()` → `hsm_client.load_access_control().await?`
- Anomaly baseline: `hsm.load_anomaly_baseline()` → `hsm_client.load_anomaly_baseline().await?`

**Testing After Each Migration:**
- Run full simulation: `cargo run`
- Verify CAN bus communication
- Check MAC verification (no false negatives)
- Run CI test suite: `./run_ci_tests.sh`
- Check for replay protection (no false positives)

**Deliverable**: All 9 ECUs use centralized HSM service

---

### Phase 4: Performance Optimization (Week 5)

**Minimize IPC overhead and measure performance:**

#### Optimizations
1. **Connection pooling**: Reuse Unix socket connections
2. **Latency tracking**: Add metrics to HsmClient
   - Track request count, min/max/avg latency
   - Export to performance stats
3. **Priority tuning**: Higher nice priority for HSM service
4. **Optional batching**: `BatchVerify` for multiple frames (future enhancement)

#### Performance Measurement
- **Baseline**: Direct VirtualHSM calls (30-50µs)
- **Target**: HSM service calls (35-70µs, including IPC)
- **Acceptable overhead**: < 20µs

**Tools:**
- `perf stat` - Context switches, cache misses
- `htop` - Core utilization
- `cargo flamegraph` - CPU profiling
- Custom metrics in HsmClient

**Deliverable**: Performance characterized, optimizations applied if needed

---

### Phase 5: Testing & Validation (Week 6)

**Comprehensive testing:**

#### Test Categories
1. **Unit tests**: Protocol serialization, HsmClient error handling, core affinity config
2. **Integration tests**: HSM service + ECUs, stress testing (high message rate)
3. **Regression tests**: All existing attack/anomaly tests must pass (159+ tests)
4. **Performance tests**: Latency, throughput, core utilization

#### Test Files to Create
- `tests/hsm_service_integration_tests.rs` - End-to-end HSM service tests
- `tests/hsm_service_performance_tests.rs` - Latency/throughput benchmarks

#### Success Criteria
- ✓ All 159+ CI tests pass
- ✓ HSM service latency < 70µs (95th percentile)
- ✓ Throughput > 10,000 ops/sec (all ECUs combined)
- ✓ Context switches < 100/sec per ECU
- ✓ Core 3 utilization < 80%
- ✓ Attack detection still works (MAC, CRC, replay, anomaly)

**Deliverable**: Full validation, ready for deployment

---

## Critical Files to Create/Modify

### New Files (5)
1. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/hsm_service/mod.rs`
2. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/hsm_service/protocol.rs`
3. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/hsm_service/server.rs`
4. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/hsm_service/client.rs`
5. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/hsm_service.rs`

### New Files (additional)
6. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/core_affinity_config.rs`
7. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/tests/hsm_service_integration_tests.rs`
8. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/tests/hsm_service_performance_tests.rs`

### Modified Files (12)
1. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/main.rs` - Add HSM service launch
2. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/lib.rs` - Export hsm_service, core_affinity_config
3. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/Cargo.toml` - Add core_affinity, hsm_service binary
4. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/wheel_fl.rs` - Use HsmClient
5. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/wheel_fr.rs` - Use HsmClient
6. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/wheel_rl.rs` - Use HsmClient
7. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/wheel_rr.rs` - Use HsmClient
8. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/engine_ecu.rs` - Use HsmClient
9. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/steering_sensor.rs` - Use HsmClient
10. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/autonomous_controller.rs` - Use HsmClient
11. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/brake_controller.rs` - Use HsmClient
12. `/home/rpi4rust/Project/rust-v-hsm-can/autonomous_controller/src/bin/steering_controller.rs` - Use HsmClient

---

## Expected Performance Impact

| Metric | Before (Current) | After (Multi-Core) | Change |
|--------|------------------|-------------------|--------|
| HSM latency | 30-50µs | 35-70µs | +5-20µs (IPC) |
| Throughput | ~8,000 ops/sec | >10,000 ops/sec | +25% |
| Context switches | 500+/sec | <100/sec | -80% |
| Core 3 utilization | ~10% (mixed) | ~60% (dedicated) | Isolated |
| Cache efficiency | Mixed | Better (locality) | Improved |

---

## Risk Mitigation

1. **HSM service crash**
   - Watchdog: Monitor HSM service, auto-restart on crash
   - ECU fail-safe: Enter fail-safe mode if HSM unreachable (timeout 100ms)
   - Graceful degradation: Allow unsecured operation in emergency (with logging)

2. **IPC bottleneck**
   - Async processing: Use tokio tasks for parallelism
   - Connection pooling: Reuse sockets, avoid reconnect overhead
   - Priority scheduling: Higher priority for HSM service process

3. **Core pinning failure**
   - Graceful fallback: Log warning, continue without pinning
   - Detect core count: Check available cores before pinning
   - Fallback assignment: Map to fewer cores if needed

4. **Protocol versioning**
   - Version field: Add `protocol_version: u32` to requests/responses (future)
   - Backward compatibility: Support old protocol for grace period
   - Feature detection: Negotiate capabilities on connect

---

## Timeline

**Total**: 6 weeks for full implementation and validation

- **Week 1**: HSM service foundation (protocol, server, client)
- **Week 2**: Core affinity integration (pinning all processes)
- **Weeks 3-4**: ECU migration (9 ECUs, one at a time)
- **Week 5**: Performance optimization (metrics, tuning)
- **Week 6**: Testing and validation (159+ tests)

---

## Future Enhancements (Out of Scope)

- Zephyr RTOS integration (native_posix or external MCU)
- Hardware HSM (PKCS#11, TPM, ARM TrustZone)
- Shared memory IPC (lower latency than Unix sockets)
- Real-time scheduling (SCHED_FIFO/SCHED_RR)
- Batch operations (verify multiple frames in single request)
