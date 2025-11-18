// Signed Configuration Management
// Provides cryptographic integrity protection for ECU configurations
// Prevents tampering with access control policies, diagnostic configurations, etc.

use crate::hsm::VirtualHSM;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

/// Configuration type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigType {
    AccessControlPolicy,
    DiagnosticConfig,
    NetworkConfig,
    SecurityConfig,
    FirmwareMetadata,
}

/// Signed configuration container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    /// Configuration type
    pub config_type: ConfigType,

    /// ECU that owns this configuration
    pub ecu_id: String,

    /// Configuration version
    pub version: String,

    /// Serialized configuration data
    pub data: Vec<u8>,

    /// HMAC-SHA256 signature
    pub signature: Vec<u8>,

    /// SHA256 fingerprint of data
    pub fingerprint: [u8; 32],

    /// Timestamp when configuration was signed
    pub timestamp: SystemTime,

    /// Authorized signer (e.g., "FACTORY", "FLEET_MANAGER")
    pub signer: String,
}

impl SignedConfig {
    /// Create a new signed configuration
    pub fn new(
        config_type: ConfigType,
        ecu_id: String,
        version: String,
        data: Vec<u8>,
        signer: String,
        hsm: &VirtualHSM,
    ) -> Self {
        // Compute fingerprint (SHA256)
        let fingerprint: [u8; 32] = {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let result = hasher.finalize();
            result.into()
        };

        // Compute signature using HMAC-SHA256
        let signature_input = Self::compute_signature_input(
            &config_type,
            &ecu_id,
            &version,
            &data,
            &fingerprint,
            &signer,
        );

        let signature = {
            let secret = format!("CONFIG_SIGNING_KEY_{}", ecu_id);
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(&signature_input);
            mac.finalize().into_bytes().to_vec()
        };

        Self {
            config_type,
            ecu_id,
            version,
            data,
            signature,
            fingerprint,
            timestamp: SystemTime::now(),
            signer,
        }
    }

    /// Verify configuration signature
    pub fn verify(&self, _hsm: &VirtualHSM) -> Result<(), ConfigError> {
        // Verify fingerprint
        let computed_fingerprint: [u8; 32] = {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(&self.data);
            let result = hasher.finalize();
            result.into()
        };

        if computed_fingerprint != self.fingerprint {
            return Err(ConfigError::FingerprintMismatch);
        }

        // Verify signature
        let signature_input = Self::compute_signature_input(
            &self.config_type,
            &self.ecu_id,
            &self.version,
            &self.data,
            &self.fingerprint,
            &self.signer,
        );

        let secret = format!("CONFIG_SIGNING_KEY_{}", self.ecu_id);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(&signature_input);

        mac.verify_slice(&self.signature)
            .map_err(|_| ConfigError::SignatureInvalid)?;

        Ok(())
    }

    /// Compute signature input bytes
    fn compute_signature_input(
        config_type: &ConfigType,
        ecu_id: &str,
        version: &str,
        data: &[u8],
        fingerprint: &[u8; 32],
        signer: &str,
    ) -> Vec<u8> {
        let mut input = Vec::new();

        // Add config type
        let type_byte = match config_type {
            ConfigType::AccessControlPolicy => 0x01,
            ConfigType::DiagnosticConfig => 0x02,
            ConfigType::NetworkConfig => 0x03,
            ConfigType::SecurityConfig => 0x04,
            ConfigType::FirmwareMetadata => 0x05,
        };
        input.push(type_byte);

        // Add ECU ID
        input.extend_from_slice(ecu_id.as_bytes());
        input.push(0x00); // Separator

        // Add version
        input.extend_from_slice(version.as_bytes());
        input.push(0x00); // Separator

        // Add data length
        input.extend_from_slice(&(data.len() as u32).to_be_bytes());

        // Add fingerprint
        input.extend_from_slice(fingerprint);

        // Add signer
        input.extend_from_slice(signer.as_bytes());

        input
    }

    /// Get configuration data (after verification)
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

/// Configuration errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    FingerprintMismatch,
    SignatureInvalid,
    VersionMismatch,
    UnauthorizedSigner,
    ConfigNotFound,
    DeserializationError,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::FingerprintMismatch => write!(f, "Configuration fingerprint mismatch (data tampered)"),
            ConfigError::SignatureInvalid => write!(f, "Configuration signature invalid"),
            ConfigError::VersionMismatch => write!(f, "Configuration version mismatch"),
            ConfigError::UnauthorizedSigner => write!(f, "Configuration signer not authorized"),
            ConfigError::ConfigNotFound => write!(f, "Configuration not found"),
            ConfigError::DeserializationError => write!(f, "Failed to deserialize configuration"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Configuration manager for ECU
pub struct ConfigManager {
    ecu_id: String,
    configurations: HashMap<ConfigType, SignedConfig>,
    authorized_signers: Vec<String>,
}

impl ConfigManager {
    /// Create new configuration manager
    pub fn new(ecu_id: String) -> Self {
        Self {
            ecu_id,
            configurations: HashMap::new(),
            authorized_signers: vec!["FACTORY".to_string(), "FLEET_MANAGER".to_string()],
        }
    }

    /// Add authorized signer
    pub fn add_authorized_signer(&mut self, signer: String) {
        if !self.authorized_signers.contains(&signer) {
            self.authorized_signers.push(signer);
        }
    }

    /// Load and verify configuration
    pub fn load_config(
        &mut self,
        config: SignedConfig,
        hsm: &VirtualHSM,
    ) -> Result<(), ConfigError> {
        // Verify signer authorization
        if !self.authorized_signers.contains(&config.signer) {
            return Err(ConfigError::UnauthorizedSigner);
        }

        // Verify signature
        config.verify(hsm)?;

        // Store configuration
        self.configurations.insert(config.config_type, config);

        Ok(())
    }

    /// Get configuration
    pub fn get_config(&self, config_type: ConfigType) -> Result<&SignedConfig, ConfigError> {
        self.configurations
            .get(&config_type)
            .ok_or(ConfigError::ConfigNotFound)
    }

    /// Update configuration (requires re-signing)
    pub fn update_config(
        &mut self,
        config_type: ConfigType,
        new_version: String,
        new_data: Vec<u8>,
        signer: String,
        hsm: &VirtualHSM,
    ) -> Result<(), ConfigError> {
        // Create new signed config
        let signed_config = SignedConfig::new(
            config_type,
            self.ecu_id.clone(),
            new_version,
            new_data,
            signer,
            hsm,
        );

        // Load (this will verify signer authorization and signature)
        self.load_config(signed_config, hsm)?;

        Ok(())
    }

    /// Get all configuration types
    pub fn list_configs(&self) -> Vec<ConfigType> {
        self.configurations.keys().copied().collect()
    }

    /// Get ECU ID
    pub fn ecu_id(&self) -> &str {
        &self.ecu_id
    }
}

/// Helper function to sign JSON-serializable configuration
pub fn sign_json_config<T: Serialize>(
    config: &T,
    config_type: ConfigType,
    ecu_id: String,
    version: String,
    signer: String,
    hsm: &VirtualHSM,
) -> Result<SignedConfig, ConfigError> {
    // Serialize configuration
    let data = serde_json::to_vec(config)
        .map_err(|_| ConfigError::DeserializationError)?;

    Ok(SignedConfig::new(
        config_type,
        ecu_id,
        version,
        data,
        signer,
        hsm,
    ))
}

/// Helper function to load and verify JSON configuration
pub fn load_json_config<T: for<'de> Deserialize<'de>>(
    signed_config: &SignedConfig,
    hsm: &VirtualHSM,
) -> Result<T, ConfigError> {
    // Verify signature
    signed_config.verify(hsm)?;

    // Deserialize configuration
    serde_json::from_slice(signed_config.get_data())
        .map_err(|_| ConfigError::DeserializationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hsm() -> VirtualHSM {
        VirtualHSM::new("BRAKE_CTRL".to_string(), 12345)
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        value: u32,
    }

    #[test]
    fn test_sign_and_verify_config() {
        let hsm = create_test_hsm();
        let data = b"test configuration data".to_vec();

        let signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data.clone(),
            "FACTORY".to_string(),
            &hsm,
        );

        // Verification should succeed
        assert!(signed_config.verify(&hsm).is_ok());
        assert_eq!(signed_config.get_data(), &data);
    }

    #[test]
    fn test_tampered_data_rejected() {
        let hsm = create_test_hsm();
        let data = b"test configuration data".to_vec();

        let mut signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data,
            "FACTORY".to_string(),
            &hsm,
        );

        // Tamper with data
        signed_config.data = b"tampered data".to_vec();

        // Verification should fail
        assert_eq!(signed_config.verify(&hsm), Err(ConfigError::FingerprintMismatch));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let hsm = create_test_hsm();
        let data = b"test configuration data".to_vec();

        let mut signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data,
            "FACTORY".to_string(),
            &hsm,
        );

        // Tamper with signature
        signed_config.signature[0] ^= 0xFF;

        // Verification should fail
        assert_eq!(signed_config.verify(&hsm), Err(ConfigError::SignatureInvalid));
    }

    #[test]
    fn test_config_manager_load() {
        let hsm = create_test_hsm();
        let mut manager = ConfigManager::new("BRAKE_CTRL".to_string());

        let data = b"test configuration".to_vec();
        let signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data,
            "FACTORY".to_string(),
            &hsm,
        );

        // Load should succeed
        assert!(manager.load_config(signed_config, &hsm).is_ok());

        // Should be able to retrieve
        let retrieved = manager.get_config(ConfigType::SecurityConfig);
        assert!(retrieved.is_ok());
    }

    #[test]
    fn test_unauthorized_signer_rejected() {
        let hsm = create_test_hsm();
        let mut manager = ConfigManager::new("BRAKE_CTRL".to_string());

        let data = b"test configuration".to_vec();
        let signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data,
            "ATTACKER".to_string(),
            &hsm,
        );

        // Load should fail - unauthorized signer
        assert_eq!(
            manager.load_config(signed_config, &hsm),
            Err(ConfigError::UnauthorizedSigner)
        );
    }

    #[test]
    fn test_add_authorized_signer() {
        let hsm = create_test_hsm();
        let mut manager = ConfigManager::new("BRAKE_CTRL".to_string());

        // Add new authorized signer
        manager.add_authorized_signer("WORKSHOP".to_string());

        let data = b"test configuration".to_vec();
        let signed_config = SignedConfig::new(
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            data,
            "WORKSHOP".to_string(),
            &hsm,
        );

        // Load should now succeed
        assert!(manager.load_config(signed_config, &hsm).is_ok());
    }

    #[test]
    fn test_update_config() {
        let hsm = create_test_hsm();
        let mut manager = ConfigManager::new("BRAKE_CTRL".to_string());

        // Initial config
        let data1 = b"version 1".to_vec();
        manager
            .update_config(
                ConfigType::SecurityConfig,
                "1.0.0".to_string(),
                data1,
                "FACTORY".to_string(),
                &hsm,
            )
            .unwrap();

        // Update to new version
        let data2 = b"version 2".to_vec();
        manager
            .update_config(
                ConfigType::SecurityConfig,
                "2.0.0".to_string(),
                data2.clone(),
                "FACTORY".to_string(),
                &hsm,
            )
            .unwrap();

        // Should have new version
        let config = manager.get_config(ConfigType::SecurityConfig).unwrap();
        assert_eq!(config.version, "2.0.0");
        assert_eq!(config.get_data(), &data2);
    }

    #[test]
    fn test_sign_json_config() {
        let hsm = create_test_hsm();
        let test_config = TestConfig {
            name: "brake_config".to_string(),
            value: 42,
        };

        let signed_config = sign_json_config(
            &test_config,
            ConfigType::SecurityConfig,
            "BRAKE_CTRL".to_string(),
            "1.0.0".to_string(),
            "FACTORY".to_string(),
            &hsm,
        )
        .unwrap();

        // Should verify successfully
        assert!(signed_config.verify(&hsm).is_ok());

        // Should be able to deserialize back
        let loaded_config: TestConfig = load_json_config(&signed_config, &hsm).unwrap();
        assert_eq!(loaded_config, test_config);
    }

    #[test]
    fn test_list_configs() {
        let hsm = create_test_hsm();
        let mut manager = ConfigManager::new("BRAKE_CTRL".to_string());

        // Add multiple configs
        manager
            .update_config(
                ConfigType::SecurityConfig,
                "1.0.0".to_string(),
                b"security".to_vec(),
                "FACTORY".to_string(),
                &hsm,
            )
            .unwrap();

        manager
            .update_config(
                ConfigType::NetworkConfig,
                "1.0.0".to_string(),
                b"network".to_vec(),
                "FACTORY".to_string(),
                &hsm,
            )
            .unwrap();

        let configs = manager.list_configs();
        assert_eq!(configs.len(), 2);
        assert!(configs.contains(&ConfigType::SecurityConfig));
        assert!(configs.contains(&ConfigType::NetworkConfig));
    }
}
