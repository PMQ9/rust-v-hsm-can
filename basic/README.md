# Basic CAN Bus Simulator

This is the basic/original implementation of the Virtual HSM CAN bus simulator. It contains a simple setup with:

- **bus_server**: Central TCP hub for CAN communication
- **monitor**: Observes all CAN traffic
- **input_ecu**: Interactive ECU for sending CAN frames
- **output_ecu**: ECU that receives and displays frames
- **demo**: Single-process demonstration

## Quick Start

```bash
cd basic

# Build all components
cargo build --release

# Run the demo (single process)
cargo run --bin demo

# Or run in multi-terminal mode:
# Terminal 1:
cargo run --bin bus_server

# Terminal 2:
cargo run --bin monitor

# Terminal 3:
cargo run --bin input_ecu

# Terminal 4:
cargo run --bin output_ecu
```

## Architecture

This implementation demonstrates the core CAN bus communication patterns:
- In-process mode using `VirtualCanBus` (tokio broadcast channels)
- Networked mode using TCP with JSON-serialized messages
- Basic ECU emulation with ARM variants

For a more realistic autonomous vehicle simulation, see the `autonomous_controller` project.
