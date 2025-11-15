use serde::{Deserialize, Serialize};

/// Firmware with digital signature for secure boot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFirmware {
    /// Firmware binary data
    pub data: Vec<u8>,

    /// Firmware version
    pub version: String,

    /// SHA256 fingerprint of firmware
    pub fingerprint: [u8; 32],

    /// HMAC signature of fingerprint (signed with SecureBootKey)
    pub signature: [u8; 32],

    /// ECU this firmware is intended for
    pub target_ecu: String,
}

impl SignedFirmware {
    /// Create a new signed firmware
    pub fn new(
        data: Vec<u8>,
        version: String,
        target_ecu: String,
        hsm: &super::core::VirtualHSM,
    ) -> Self {
        let fingerprint = hsm.generate_firmware_fingerprint(&data);
        let signature = hsm.sign_firmware(&fingerprint);

        Self {
            data,
            version,
            fingerprint,
            signature,
            target_ecu,
        }
    }

    /// Verify firmware signature (secure boot)
    pub fn verify(&self, hsm: &super::core::VirtualHSM) -> Result<(), String> {
        // Verify the fingerprint matches the data
        if !hsm.verify_firmware_fingerprint(&self.data, &self.fingerprint) {
            return Err("Firmware fingerprint mismatch".to_string());
        }

        // Verify the signature
        if !hsm.verify_firmware_signature(&self.fingerprint, &self.signature) {
            return Err("Firmware signature verification failed".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::core::VirtualHSM;

    #[test]
    fn test_firmware_verification() {
        let hsm = VirtualHSM::new("ECU1".to_string(), 12345);
        let firmware_data = b"firmware binary data";

        let firmware = SignedFirmware::new(
            firmware_data.to_vec(),
            "1.0.0".to_string(),
            "ECU1".to_string(),
            &hsm,
        );

        assert!(firmware.verify(&hsm).is_ok());
    }
}
