use crate::hsm::{VirtualHSM, SignedFirmware};
use std::sync::{Arc, RwLock};

/// Simulated memory address range for firmware
pub const FIRMWARE_BASE_ADDRESS: usize = 0x0800_0000; // Typical ARM Cortex-M flash start
pub const FIRMWARE_MAX_SIZE: usize = 512 * 1024; // 512 KB

/// Protected memory region for firmware storage
/// In real hardware, this would be enforced by MPU (Memory Protection Unit)
/// and access would trigger hardware faults if violated
#[derive(Clone)]
pub struct ProtectedMemory {
    /// Firmware data stored in "protected" memory
    firmware: Arc<RwLock<Option<SignedFirmware>>>,

    /// Base address of firmware region (simulated)
    base_address: usize,

    /// Maximum size of firmware region
    max_size: usize,

    /// Lock state - when true, prevents all writes except during authorized update
    write_protected: Arc<RwLock<bool>>,

    /// ECU identifier
    ecu_id: String,
}

impl ProtectedMemory {
    /// Create a new protected memory region
    pub fn new(ecu_id: String) -> Self {
        Self {
            firmware: Arc::new(RwLock::new(None)),
            base_address: FIRMWARE_BASE_ADDRESS,
            max_size: FIRMWARE_MAX_SIZE,
            write_protected: Arc::new(RwLock::new(true)),
            ecu_id,
        }
    }

    /// Get base address of firmware region
    pub fn base_address(&self) -> usize {
        self.base_address
    }

    /// Get maximum firmware size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Check if memory is write-protected
    pub fn is_write_protected(&self) -> bool {
        *self.write_protected.read().unwrap()
    }

    /// Load firmware during manufacturing/initialization (secure boot)
    /// This simulates the initial firmware provisioning
    pub fn provision_firmware(
        &mut self,
        firmware: SignedFirmware,
        hsm: &VirtualHSM,
    ) -> Result<(), String> {
        // Verify firmware signature before loading
        firmware.verify(hsm)?;

        // Check size
        if firmware.data.len() > self.max_size {
            return Err(format!(
                "Firmware size {} exceeds maximum {}",
                firmware.data.len(),
                self.max_size
            ));
        }

        // Check target ECU
        if firmware.target_ecu != self.ecu_id {
            return Err(format!(
                "Firmware target ECU '{}' does not match '{}'",
                firmware.target_ecu, self.ecu_id
            ));
        }

        // Load firmware into protected memory
        let mut fw = self.firmware.write().unwrap();
        *fw = Some(firmware.clone());

        Ok(())
    }

    /// Execute firmware (secure boot verification)
    /// This simulates the boot process where firmware signature is verified
    pub fn secure_boot(&self, hsm: &VirtualHSM) -> Result<(), String> {
        let firmware = self.firmware.read().unwrap();

        match firmware.as_ref() {
            None => Err("No firmware loaded in protected memory".to_string()),
            Some(fw) => {
                // Verify firmware signature (secure boot)
                fw.verify(hsm)?;

                println!("✓ Secure boot successful for ECU '{}'", self.ecu_id);
                println!("  Firmware version: {}", fw.version);
                println!(
                    "  Firmware fingerprint: {}",
                    hex::encode(&fw.fingerprint[..8])
                );

                Ok(())
            }
        }
    }

    /// Authorize firmware update (requires HSM authorization token)
    /// This unlocks the protected memory for writing
    pub fn authorize_update(&self, update_token: &[u8; 32], hsm: &VirtualHSM) -> Result<(), String> {
        if !hsm.authorize_firmware_update(update_token) {
            return Err("Firmware update authorization failed - invalid token".to_string());
        }

        // Temporarily unlock write protection
        let mut wp = self.write_protected.write().unwrap();
        *wp = false;

        println!("✓ Firmware update authorized for ECU '{}'", self.ecu_id);
        Ok(())
    }

    /// Update firmware (only allowed after authorization)
    pub fn update_firmware(
        &mut self,
        new_firmware: SignedFirmware,
        hsm: &VirtualHSM,
    ) -> Result<(), String> {
        // Check write protection
        if self.is_write_protected() {
            return Err("Protected memory is write-protected. Authorization required.".to_string());
        }

        // Verify new firmware
        new_firmware.verify(hsm)?;

        // Check size
        if new_firmware.data.len() > self.max_size {
            return Err(format!(
                "Firmware size {} exceeds maximum {}",
                new_firmware.data.len(),
                self.max_size
            ));
        }

        // Check target ECU
        if new_firmware.target_ecu != self.ecu_id {
            return Err(format!(
                "Firmware target ECU '{}' does not match '{}'",
                new_firmware.target_ecu, self.ecu_id
            ));
        }

        // Update firmware
        let mut fw = self.firmware.write().unwrap();
        *fw = Some(new_firmware.clone());

        println!("✓ Firmware updated for ECU '{}'", self.ecu_id);
        println!("  New version: {}", new_firmware.version);

        // Re-lock write protection
        self.lock_write_protection();

        Ok(())
    }

    /// Lock write protection (called after firmware update)
    pub fn lock_write_protection(&self) {
        let mut wp = self.write_protected.write().unwrap();
        *wp = true;
        println!("✓ Protected memory locked for ECU '{}'", self.ecu_id);
    }

    /// Read firmware metadata (allowed without authorization)
    pub fn read_firmware_info(&self) -> Option<FirmwareInfo> {
        let firmware = self.firmware.read().unwrap();
        firmware.as_ref().map(|fw| FirmwareInfo {
            version: fw.version.clone(),
            fingerprint: fw.fingerprint,
            target_ecu: fw.target_ecu.clone(),
            size: fw.data.len(),
        })
    }

    /// Attempt to read from protected address (simulated)
    /// In real hardware, this would be a memory-mapped read
    pub fn read_byte(&self, offset: usize) -> Result<u8, String> {
        if offset >= self.max_size {
            return Err(format!("Address out of bounds: 0x{:08X}", self.base_address + offset));
        }

        let firmware = self.firmware.read().unwrap();
        match firmware.as_ref() {
            None => Err("No firmware loaded".to_string()),
            Some(fw) => {
                if offset < fw.data.len() {
                    Ok(fw.data[offset])
                } else {
                    Ok(0xFF) // Unprogrammed flash reads as 0xFF
                }
            }
        }
    }

    /// Attempt to write to protected address (simulated)
    /// This should fail unless write protection is disabled via authorized update
    pub fn write_byte(&self, offset: usize, _value: u8) -> Result<(), String> {
        if self.is_write_protected() {
            return Err(format!(
                "MEMORY PROTECTION FAULT: Attempted write to protected address 0x{:08X}",
                self.base_address + offset
            ));
        }

        if offset >= self.max_size {
            return Err(format!("Address out of bounds: 0x{:08X}", self.base_address + offset));
        }

        // In real implementation, this would write to flash
        // For simulation, we only allow whole firmware updates via update_firmware()
        Err("Direct byte writes not supported. Use update_firmware() instead.".to_string())
    }
}

/// Firmware information (publicly readable)
#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    pub version: String,
    pub fingerprint: [u8; 32],
    pub target_ecu: String,
    pub size: usize,
}

impl FirmwareInfo {
    pub fn display(&self) {
        println!("Firmware Information:");
        println!("  Version: {}", self.version);
        println!("  Target ECU: {}", self.target_ecu);
        println!("  Size: {} bytes", self.size);
        println!("  Fingerprint: {}", hex::encode(&self.fingerprint[..16]));
    }
}

// Add hex dependency helper (we'll need to add this to Cargo.toml)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_memory_write_protection() {
        let mut memory = ProtectedMemory::new("TEST_ECU".to_string());

        // Should fail to write when protected
        assert!(memory.write_byte(0, 0xAA).is_err());
    }

    #[test]
    fn test_firmware_update_flow() {
        let mut hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let mut memory = ProtectedMemory::new("TEST_ECU".to_string());

        // Create firmware
        let firmware = SignedFirmware::new(
            vec![0x01, 0x02, 0x03, 0x04],
            "1.0.0".to_string(),
            "TEST_ECU".to_string(),
            &hsm,
        );

        // Provision initial firmware
        assert!(memory.provision_firmware(firmware.clone(), &hsm).is_ok());

        // Verify secure boot
        assert!(memory.secure_boot(&hsm).is_ok());

        // Create update
        let update = SignedFirmware::new(
            vec![0x05, 0x06, 0x07, 0x08],
            "2.0.0".to_string(),
            "TEST_ECU".to_string(),
            &hsm,
        );

        // Authorize update
        let token = hsm.generate_update_token();
        assert!(memory.authorize_update(&token, &hsm).is_ok());

        // Update firmware
        assert!(memory.update_firmware(update, &hsm).is_ok());

        // Should be locked again
        assert!(memory.is_write_protected());
    }
}
