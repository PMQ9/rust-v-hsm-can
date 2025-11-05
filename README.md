# rust-v-hsm-can

Virtual Hardware Security Module (V-HSM) for CAN Bus security, written in Rust.

## Architecture

```
Input ECU ──┐
            │
            ├──> Virtual CAN Bus ──┬──> Output ECU
            │                      │
            │                      └──> Monitor
            │
More ECUs ──┘
```

The system simulates a complete CAN bus network:

- **Virtual CAN Bus**: Broadcast communication channel that simulates real CAN bus behavior. All connected nodes see all messages with sub-millisecond latency.
- **Input ECU (ARM Cortex-M4)**: Emulates a sensor/actuator ECU that sends CAN frames to the bus. Supports both standard (11-bit) and extended (29-bit) CAN IDs.
- **Output ECU (ARM Cortex-M7)**: Emulates a high-performance control ECU that receives and processes CAN frames from the bus.
- **Monitor**: Observes all bus traffic with color-coded timestamps, IDs, data length, and payload.

All components connect to a shared broadcast bus. Any frame sent by any ECU is received by all other connected components.

## Build

Build all components:
```bash
cargo build --release
```

Build specific binaries:
```bash
cargo build --bin bus_server --bin monitor --bin input_ecu --bin output_ecu
```

## Run

Multi-terminal setup:
```bash
# Terminal 1: Start bus server
cargo run --bin bus_server

# Terminal 2: Start monitor
cargo run --bin monitor

# Terminal 3: Start output ECU
cargo run --bin output_ecu

# Terminal 4: Send frames interactively
cargo run --bin input_ecu
# Format: <CAN_ID> <byte1> <byte2> ... (hex)
# Example: 123 01 02 03 04
```

See [MULTI_TERMINAL_GUIDE.md](MULTI_TERMINAL_GUIDE.md) for details.

## Components

- `vhsm-can` - Main V-HSM application
- `bus_server` - CAN Bus network server
- `input_ecu` / `output_ecu` - Simulated ECUs
- `monitor` - CAN Bus traffic monitor
- `demo` - Demonstration program
