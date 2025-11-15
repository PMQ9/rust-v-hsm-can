# Attack Configuration Files

This directory contains example configuration files for the attack simulator framework.

## File Format

All configuration files are in JSON format with the following structure:

```json
{
  "attack_type": "Fuzzing | Injection | Replay | Flooding | Spoofing | Combined",
  "duration_secs": 60,
  "frames_per_second": 100,
  "target_can_ids": [768, 769],
  "attacker_name": "ATTACKER_NAME",
  "malform_percentage": 50,
  "capture_duration_secs": 10
}
```

## Fields

- `attack_type`: Type of attack to execute
- `duration_secs`: Duration in seconds (null for infinite)
- `frames_per_second`: Number of frames to send per second
- `target_can_ids`: List of CAN IDs to target (empty array = all IDs)
- `attacker_name`: Identifier for the attacker
- `malform_percentage`: Percentage of malformed frames (0-100, fuzzing only)
- `capture_duration_secs`: Capture time before replay (replay only)

## CAN ID Reference

### Sensor Messages (256-289)
- 0x100 (256): Wheel Speed FL
- 0x101 (257): Wheel Speed FR
- 0x102 (258): Wheel Speed RL
- 0x103 (259): Wheel Speed RR
- 0x110 (272): Engine RPM
- 0x111 (273): Engine Throttle
- 0x120 (288): Steering Angle
- 0x121 (289): Steering Torque

### Control Commands (768-770)
- 0x300 (768): Brake Command
- 0x301 (769): Throttle Command
- 0x302 (770): Steering Command

## Example Configurations

### fuzzing_high_intensity.json
High-intensity fuzzing attack with 75% malformed frames at 500 fps for 2 minutes.

### injection_brake_attack.json
Targeted injection attack on brake command CAN ID (0x300).

### replay_control_commands.json
Replay attack capturing and replaying all control commands.

### dos_flooding.json
Denial-of-service attack flooding the bus at 2000 fps for 30 seconds.

## Usage

To use a configuration file with the attack simulator:

```bash
# Note: CLI version does not yet support config files
# This is a placeholder for future enhancement

# Planned usage:
# cargo run --bin attack_simulator -- --config attack_configs/fuzzing_high_intensity.json
```

Currently, use the CLI arguments to configure attacks:

```bash
cargo run --bin attack_simulator -- fuzzing -d 120 -r 500 -m 75
```
