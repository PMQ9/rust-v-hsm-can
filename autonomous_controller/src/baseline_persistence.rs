/// Baseline Persistence Module
///
/// Provides secure storage and loading of anomaly detection baselines.
/// Baselines are saved as JSON files with HMAC signatures for integrity verification.
use crate::anomaly_detection::AnomalyBaseline;
use crate::hsm::VirtualHSM;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Signed baseline container for secure storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBaseline {
    /// The anomaly detection baseline
    pub baseline: AnomalyBaseline,

    /// HMAC-SHA256 signature of the baseline (using HSM secure boot key)
    pub signature: [u8; 32],

    /// Fingerprint (SHA256 hash) of the baseline JSON
    pub fingerprint: [u8; 32],
}

impl SignedBaseline {
    /// Create a new signed baseline using HSM
    pub fn new(baseline: AnomalyBaseline, hsm: &VirtualHSM) -> Self {
        // Serialize baseline to JSON for signing (use canonical format for consistency)
        // Use non-pretty format so verification matches
        let baseline_json = serde_json::to_string(&baseline).expect("Failed to serialize baseline");

        // Calculate fingerprint (SHA256 hash of JSON)
        let fingerprint = hsm.generate_firmware_fingerprint(baseline_json.as_bytes());

        // Sign the fingerprint with secure boot key
        let signature = hsm.sign_firmware(&fingerprint);

        // Note: We do NOT store the signature in the baseline itself
        // The signature is only in the SignedBaseline container

        Self {
            baseline,
            signature,
            fingerprint,
        }
    }

    /// Verify the signature using HSM
    pub fn verify(&self, hsm: &VirtualHSM) -> Result<(), String> {
        // Recalculate fingerprint from current baseline
        let baseline_json =
            serde_json::to_string(&self.baseline).expect("Failed to serialize baseline");
        let calculated_fingerprint = hsm.generate_firmware_fingerprint(baseline_json.as_bytes());

        // Check fingerprint match
        if calculated_fingerprint != self.fingerprint {
            return Err("Baseline fingerprint mismatch - baseline has been modified".to_string());
        }

        // Verify signature
        if !hsm.verify_firmware_signature(&self.fingerprint, &self.signature) {
            return Err("Baseline signature verification failed - untrusted baseline".to_string());
        }

        Ok(())
    }

    /// Save to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self).map_err(|e| e.to_string())?;
        fs::write(path.as_ref(), json).map_err(|e| {
            format!(
                "Failed to write baseline to {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        println!(
            "{} Baseline saved to {}",
            "✓".green(),
            path.as_ref().display().to_string().bright_white()
        );
        Ok(())
    }

    /// Load from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let json = fs::read_to_string(path.as_ref()).map_err(|e| {
            format!(
                "Failed to read baseline from {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        let signed_baseline: SignedBaseline =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse baseline: {}", e))?;

        println!(
            "{} Baseline loaded from {}",
            "✓".green(),
            path.as_ref().display().to_string().bright_white()
        );
        Ok(signed_baseline)
    }
}

/// Save a baseline with HSM signature
pub fn save_baseline<P: AsRef<Path>>(
    baseline: AnomalyBaseline,
    path: P,
    hsm: &VirtualHSM,
) -> Result<(), String> {
    println!(
        "{} Signing baseline for {}...",
        "→".cyan(),
        baseline.ecu_id.bright_white()
    );
    println!(
        "   • Total samples: {}",
        baseline.total_samples.to_string().bright_white()
    );
    println!(
        "   • CAN IDs profiled: {}",
        baseline.profiles.len().to_string().bright_white()
    );
    println!(
        "   • Created: {}",
        baseline.created_at.to_rfc3339().bright_black()
    );

    let signed_baseline = SignedBaseline::new(baseline, hsm);
    signed_baseline.save_to_file(path)?;

    println!(
        "{} Baseline signed and saved successfully",
        "✓".green().bold()
    );
    Ok(())
}

/// Load and verify a baseline with HSM signature verification
pub fn load_baseline<P: AsRef<Path>>(path: P, hsm: &VirtualHSM) -> Result<AnomalyBaseline, String> {
    println!(
        "{} Loading baseline from {}...",
        "→".cyan(),
        path.as_ref().display().to_string().bright_white()
    );

    let signed_baseline = SignedBaseline::load_from_file(&path)?;

    println!("{} Verifying baseline signature...", "→".cyan());

    // Verify signature using HSM
    signed_baseline.verify(hsm)?;

    println!(
        "{} Baseline signature verified successfully",
        "✓".green().bold()
    );
    println!(
        "   • ECU: {}",
        signed_baseline.baseline.ecu_id.bright_white()
    );
    println!(
        "   • CAN IDs: {}",
        signed_baseline
            .baseline
            .profiles
            .len()
            .to_string()
            .bright_white()
    );
    println!(
        "   • Samples: {}",
        signed_baseline
            .baseline
            .total_samples
            .to_string()
            .bright_white()
    );
    println!(
        "   • Created: {}",
        signed_baseline
            .baseline
            .created_at
            .to_rfc3339()
            .bright_black()
    );

    Ok(signed_baseline.baseline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_baseline() {
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let baseline = AnomalyBaseline::new("TEST_ECU".to_string());

        let signed = SignedBaseline::new(baseline, &hsm);
        assert!(signed.verify(&hsm).is_ok());
    }

    #[test]
    fn test_tampered_baseline_detection() {
        let hsm = VirtualHSM::new("TEST_ECU".to_string(), 12345);
        let baseline = AnomalyBaseline::new("TEST_ECU".to_string());

        let mut signed = SignedBaseline::new(baseline, &hsm);

        // Tamper with the baseline
        signed.baseline.total_samples = 99999;

        // Verification should fail
        assert!(signed.verify(&hsm).is_err());
    }

    #[test]
    fn test_wrong_hsm_key_detection() {
        let hsm1 = VirtualHSM::new("ECU1".to_string(), 12345);
        let hsm2 = VirtualHSM::new("ECU2".to_string(), 67890); // Different seed = different keys

        let baseline = AnomalyBaseline::new("ECU1".to_string());
        let signed = SignedBaseline::new(baseline, &hsm1);

        // Verification with wrong HSM should fail
        assert!(signed.verify(&hsm2).is_err());
    }
}
