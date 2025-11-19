// Key Rotation Module - Session Key Lifecycle Management
//
// Implements cryptographic key rotation with session key lifecycle:
// - Master key → Session keys (via HKDF-SHA256)
// - Time-based and counter-based rotation policies
// - Multi-key support during rotation windows
// - Secure key distribution protocol

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::crypto::{decrypt_aes256_gcm, encrypt_aes256_gcm};

/// Session key state in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is currently active for TX and RX
    Active,
    /// Key is in grace period (new key distributed, old key still valid for RX)
    PendingRotation,
    /// Key has expired and is no longer valid
    Expired,
}

/// Session key with lifecycle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    /// Unique identifier for this session key (monotonically increasing)
    pub key_id: u32,

    /// Derived key material (256-bit)
    #[serde(with = "serde_bytes_array")]
    pub key_material: [u8; 32],

    /// When this key was generated
    pub generation_time: DateTime<Utc>,

    /// When this key became active
    pub activation_time: Option<DateTime<Utc>>,

    /// When rotation was triggered (new key distributed)
    pub rotation_time: Option<DateTime<Utc>>,

    /// When this key expires (no longer valid)
    pub expiry_time: Option<DateTime<Utc>>,

    /// Current state in lifecycle
    pub state: KeyState,

    /// Frame counter (number of frames sent with this key)
    pub frame_count: u64,
}

/// Serde helper for [u8; 32] arrays
mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

impl SessionKey {
    /// Create a new session key (initially in Active state)
    pub fn new(key_id: u32, key_material: [u8; 32]) -> Self {
        let now = Utc::now();
        Self {
            key_id,
            key_material,
            generation_time: now,
            activation_time: Some(now),
            rotation_time: None,
            expiry_time: None,
            state: KeyState::Active,
            frame_count: 0,
        }
    }

    /// Check if key is currently valid for transmission
    pub fn is_valid_for_tx(&self) -> bool {
        self.state == KeyState::Active
    }

    /// Check if key is currently valid for reception (active or in grace period)
    pub fn is_valid_for_rx(&self) -> bool {
        matches!(self.state, KeyState::Active | KeyState::PendingRotation)
    }

    /// Check if key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_time {
            Utc::now() >= expiry
        } else {
            false
        }
    }

    /// Mark key as pending rotation (enter grace period)
    pub fn mark_pending_rotation(&mut self, grace_period_secs: i64) {
        let now = Utc::now();
        self.rotation_time = Some(now);
        self.expiry_time = Some(now + Duration::seconds(grace_period_secs));
        self.state = KeyState::PendingRotation;
    }

    /// Mark key as expired
    pub fn mark_expired(&mut self) {
        self.expiry_time = Some(Utc::now());
        self.state = KeyState::Expired;
    }

    /// Increment frame counter
    pub fn increment_frame_count(&mut self) {
        self.frame_count = self.frame_count.wrapping_add(1);
    }
}

/// Key rotation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Enable time-based rotation (rotate every N seconds)
    pub time_based_enabled: bool,
    pub rotation_interval_secs: i64,

    /// Enable counter-based rotation (rotate every N frames)
    pub counter_based_enabled: bool,
    pub rotation_frame_threshold: u64,

    /// Grace period for old keys after rotation (seconds)
    pub grace_period_secs: i64,

    /// Maximum number of keys to keep in history
    pub max_key_history: usize,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            time_based_enabled: true,
            rotation_interval_secs: 300, // 5 minutes
            counter_based_enabled: true,
            rotation_frame_threshold: 10_000, // 10k frames
            grace_period_secs: 60,            // 1 minute grace period
            max_key_history: 10,              // Keep last 10 keys
        }
    }
}

impl KeyRotationPolicy {
    /// Create policy with only time-based rotation
    pub fn time_based_only(interval_secs: i64) -> Self {
        Self {
            time_based_enabled: true,
            rotation_interval_secs: interval_secs,
            counter_based_enabled: false,
            ..Default::default()
        }
    }

    /// Create policy with only counter-based rotation
    pub fn counter_based_only(frame_threshold: u64) -> Self {
        Self {
            time_based_enabled: false,
            counter_based_enabled: true,
            rotation_frame_threshold: frame_threshold,
            ..Default::default()
        }
    }

    /// Check if rotation should be triggered for a given key
    pub fn should_rotate(&self, key: &SessionKey) -> bool {
        let now = Utc::now();

        // Time-based check
        if self.time_based_enabled {
            if let Some(activation_time) = key.activation_time {
                let elapsed = (now - activation_time).num_seconds();
                if elapsed >= self.rotation_interval_secs {
                    return true;
                }
            }
        }

        // Counter-based check
        if self.counter_based_enabled && key.frame_count >= self.rotation_frame_threshold {
            return true;
        }

        false
    }
}

/// Key rotation manager - manages session key lifecycle
#[derive(Clone)]
pub struct KeyRotationManager {
    /// Master key for deriving session keys
    master_key: [u8; 32],

    /// ECU identifier (used in key derivation context)
    ecu_id: String,

    /// Current active key ID
    current_key_id: u32,

    /// All session keys (active, pending, expired)
    session_keys: HashMap<u32, SessionKey>,

    /// Key rotation policy
    policy: KeyRotationPolicy,
}

impl KeyRotationManager {
    /// Create a new key rotation manager
    pub fn new(master_key: [u8; 32], ecu_id: String, policy: KeyRotationPolicy) -> Self {
        let mut manager = Self {
            master_key,
            ecu_id,
            current_key_id: 0,
            session_keys: HashMap::new(),
            policy,
        };

        // Generate initial session key (key_id = 1)
        manager.rotate_key();

        manager
    }

    /// Create manager with default policy
    pub fn with_default_policy(master_key: [u8; 32], ecu_id: String) -> Self {
        Self::new(master_key, ecu_id, KeyRotationPolicy::default())
    }

    /// Get current active session key for transmission
    pub fn get_active_key(&self) -> Option<&SessionKey> {
        self.session_keys.get(&self.current_key_id)
    }

    /// Get mutable reference to active session key (for frame counting)
    pub fn get_active_key_mut(&mut self) -> Option<&mut SessionKey> {
        self.session_keys.get_mut(&self.current_key_id)
    }

    /// Get session key by ID (for reception, supports old keys in grace period)
    pub fn get_key_by_id(&self, key_id: u32) -> Option<&SessionKey> {
        self.session_keys.get(&key_id)
    }

    /// Get current active key ID
    pub fn current_key_id(&self) -> u32 {
        self.current_key_id
    }

    /// Get reference to key rotation policy
    pub fn policy(&self) -> &KeyRotationPolicy {
        &self.policy
    }

    /// Update key rotation policy
    pub fn set_policy(&mut self, policy: KeyRotationPolicy) {
        self.policy = policy;
    }

    /// Derive a session key from master key using HKDF-SHA256
    fn derive_session_key(&self, key_id: u32) -> [u8; 32] {
        derive_session_key_hkdf(
            &self.master_key,
            key_id,
            &self.ecu_id,
            Utc::now().timestamp(),
        )
    }

    /// Rotate to a new session key
    pub fn rotate_key(&mut self) -> u32 {
        // Mark current key as pending rotation (if exists)
        if let Some(current_key) = self.session_keys.get_mut(&self.current_key_id) {
            current_key.mark_pending_rotation(self.policy.grace_period_secs);
        }

        // Generate new key ID
        let new_key_id = self.current_key_id.wrapping_add(1);
        if new_key_id == 0 || new_key_id == u32::MAX {
            // Skip 0 (reserved for legacy symmetric_comm_key) and u32::MAX (avoid edge case)
            self.current_key_id = 1;
        } else {
            self.current_key_id = new_key_id;
        }

        // Derive new session key
        let key_material = self.derive_session_key(self.current_key_id);
        let new_key = SessionKey::new(self.current_key_id, key_material);

        // Store new key
        self.session_keys.insert(self.current_key_id, new_key);

        // Cleanup old expired keys
        self.cleanup_expired_keys();

        self.current_key_id
    }

    /// Check if rotation should happen and rotate if needed
    pub fn check_and_rotate(&mut self) -> Option<u32> {
        if let Some(active_key) = self.get_active_key() {
            if self.policy.should_rotate(active_key) {
                return Some(self.rotate_key());
            }
        }
        None
    }

    /// Cleanup expired keys beyond grace period
    fn cleanup_expired_keys(&mut self) {
        let now = Utc::now();

        // Mark expired keys
        for key in self.session_keys.values_mut() {
            if let Some(expiry) = key.expiry_time {
                if now >= expiry && key.state != KeyState::Expired {
                    key.mark_expired();
                }
            }
        }

        // Remove old expired keys (keep max_key_history)
        if self.session_keys.len() > self.policy.max_key_history {
            let mut key_ids: Vec<u32> = self.session_keys.keys().copied().collect();
            key_ids.sort();

            // Keep the most recent max_key_history keys
            let to_remove = key_ids.len().saturating_sub(self.policy.max_key_history);
            for key_id in key_ids.iter().take(to_remove) {
                self.session_keys.remove(key_id);
            }
        }
    }

    /// Get all session keys (for debugging/monitoring)
    pub fn get_all_keys(&self) -> &HashMap<u32, SessionKey> {
        &self.session_keys
    }

    /// Export key for distribution (encrypted with key_encryption_key)
    pub fn export_key(&self, key_id: u32, key_encryption_key: &[u8; 32]) -> Option<Vec<u8>> {
        let key = self.session_keys.get(&key_id)?;

        // Encrypt key material with AES-256-GCM (provides confidentiality + authenticity)
        let encrypted = encrypt_key_simple(&key.key_material, key_encryption_key, key_id);

        Some(encrypted)
    }

    /// Import and activate a distributed key
    pub fn import_key(
        &mut self,
        key_id: u32,
        encrypted_key: &[u8],
        key_encryption_key: &[u8; 32],
    ) -> Result<(), String> {
        // Decrypt key material
        let key_material = decrypt_key_simple(encrypted_key, key_encryption_key, key_id)
            .ok_or("Failed to decrypt key")?;

        // Verify key_id is monotonically increasing (prevent rollback attacks)
        if key_id <= self.current_key_id {
            return Err(format!(
                "Key rollback detected: new key_id {} <= current key_id {}",
                key_id, self.current_key_id
            ));
        }

        // Mark current key as pending rotation
        if let Some(current_key) = self.session_keys.get_mut(&self.current_key_id) {
            current_key.mark_pending_rotation(self.policy.grace_period_secs);
        }

        // Import and activate new key
        let new_key = SessionKey::new(key_id, key_material);
        self.session_keys.insert(key_id, new_key);
        self.current_key_id = key_id;

        // Cleanup
        self.cleanup_expired_keys();

        Ok(())
    }
}

/// Derive session key using HKDF-SHA256
///
/// Context: "CAN-SESSION-KEY" || key_id || ecu_id || timestamp
pub fn derive_session_key_hkdf(
    master_key: &[u8; 32],
    key_id: u32,
    ecu_id: &str,
    timestamp: i64,
) -> [u8; 32] {
    use hkdf::Hkdf;

    // Build context information
    let mut info = Vec::new();
    info.extend_from_slice(b"CAN-SESSION-KEY-V1");
    info.extend_from_slice(&key_id.to_le_bytes());
    info.extend_from_slice(ecu_id.as_bytes());
    info.extend_from_slice(&timestamp.to_le_bytes());

    // HKDF-Expand (no salt needed, master_key is already high-entropy)
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");

    okm
}

/// Encrypt key using AES-256-GCM authenticated encryption (for secure key distribution)
///
/// Uses AES-256-GCM which provides:
/// - Confidentiality: Key material is encrypted
/// - Authenticity: 128-bit authentication tag prevents tampering
/// - Integrity: Detects any modifications to encrypted key
///
/// SECURITY FIX: Uses random nonces to prevent nonce reuse attacks
/// Security properties:
/// - Nonce is randomly generated for each encryption (prevents reuse)
/// - Associated data includes key_id to bind encryption to specific key
/// - Returns [nonce: 12 bytes] + [ciphertext + auth_tag: 48 bytes] = 60 bytes total
fn encrypt_key_simple(key: &[u8; 32], kek: &[u8; 32], key_id: u32) -> Vec<u8> {
    use rand::RngCore;

    // SECURITY FIX: Generate cryptographically secure random nonce (96 bits / 12 bytes)
    // This prevents catastrophic nonce reuse if key_id is ever reused
    // (e.g., after system reset, key rollback, or counter wraparound)
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Additional authenticated data (not encrypted, but authenticated)
    let mut aad = Vec::new();
    aad.extend_from_slice(b"KEY-ENCRYPTION-V2"); // V2 = random nonce format
    aad.extend_from_slice(&key_id.to_le_bytes());

    // Encrypt with AES-256-GCM
    let ciphertext = encrypt_aes256_gcm(key, kek, &nonce, &aad)
        .expect("AES-256-GCM encryption should not fail with valid inputs");

    // Prepend nonce to ciphertext for transmission
    // Format: [nonce: 12 bytes] + [encrypted_key + auth_tag: 48 bytes] = 60 bytes
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt key using AES-256-GCM (inverse of encrypt_key_simple)
///
/// SECURITY FIX: Supports both V1 (deterministic nonce) and V2 (random nonce) formats
/// for backward compatibility during migration
///
/// Verifies authentication tag and decrypts key material.
/// Returns None if:
/// - Wrong KEK
/// - Tampered ciphertext
/// - Wrong key_id (AAD mismatch)
/// - Invalid ciphertext length
fn decrypt_key_simple(encrypted: &[u8], kek: &[u8; 32], key_id: u32) -> Option<[u8; 32]> {
    // Check format based on length
    if encrypted.len() == 60 {
        // V2 format: [nonce: 12 bytes] + [ciphertext + auth_tag: 48 bytes]
        let nonce_bytes = &encrypted[0..12];
        let ciphertext = &encrypted[12..60];

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);

        // Additional authenticated data (must match encryption AAD)
        let mut aad = Vec::new();
        aad.extend_from_slice(b"KEY-ENCRYPTION-V2");
        aad.extend_from_slice(&key_id.to_le_bytes());

        // Decrypt and verify authentication tag
        let decrypted = decrypt_aes256_gcm(ciphertext, kek, &nonce, &aad).ok()?;

        if decrypted.len() != 32 {
            return None;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Some(key)
    } else if encrypted.len() == 48 {
        // V1 format (legacy): deterministic nonce, 48 bytes ciphertext
        // SECURITY WARNING: V1 format vulnerable to nonce reuse - should migrate to V2
        let mut hasher = Sha256::new();
        hasher.update(b"AES-GCM-NONCE-V1");
        hasher.update(kek);
        hasher.update(&key_id.to_le_bytes());
        let hash = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash[0..12]);

        // Additional authenticated data (must match encryption AAD)
        let mut aad = Vec::new();
        aad.extend_from_slice(b"KEY-ENCRYPTION-V1");
        aad.extend_from_slice(&key_id.to_le_bytes());

        // Decrypt and verify authentication tag
        let decrypted = decrypt_aes256_gcm(encrypted, kek, &nonce, &aad).ok()?;

        if decrypted.len() != 32 {
            return None;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Some(key)
    } else {
        // Invalid length
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_creation() {
        let key_material = [0x42u8; 32];
        let key = SessionKey::new(1, key_material);

        assert_eq!(key.key_id, 1);
        assert_eq!(key.key_material, key_material);
        assert_eq!(key.state, KeyState::Active);
        assert_eq!(key.frame_count, 0);
        assert!(key.is_valid_for_tx());
        assert!(key.is_valid_for_rx());
        assert!(!key.is_expired());
    }

    #[test]
    fn test_session_key_pending_rotation() {
        let mut key = SessionKey::new(1, [0x42u8; 32]);
        key.mark_pending_rotation(60);

        assert_eq!(key.state, KeyState::PendingRotation);
        assert!(!key.is_valid_for_tx());
        assert!(key.is_valid_for_rx());
        assert!(key.rotation_time.is_some());
        assert!(key.expiry_time.is_some());
    }

    #[test]
    fn test_session_key_expired() {
        let mut key = SessionKey::new(1, [0x42u8; 32]);
        key.mark_expired();

        assert_eq!(key.state, KeyState::Expired);
        assert!(!key.is_valid_for_tx());
        assert!(!key.is_valid_for_rx());
        assert!(key.is_expired());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let master_key = [0x55u8; 32];
        let key1 = derive_session_key_hkdf(&master_key, 1, "ECU1", 1000);
        let key2 = derive_session_key_hkdf(&master_key, 1, "ECU1", 1000);

        assert_eq!(key1, key2, "Same inputs should produce same key");
    }

    #[test]
    fn test_key_derivation_different_key_id() {
        let master_key = [0x55u8; 32];
        let key1 = derive_session_key_hkdf(&master_key, 1, "ECU1", 1000);
        let key2 = derive_session_key_hkdf(&master_key, 2, "ECU1", 1000);

        assert_ne!(key1, key2, "Different key_id should produce different keys");
    }

    #[test]
    fn test_key_derivation_different_ecu_id() {
        let master_key = [0x55u8; 32];
        let key1 = derive_session_key_hkdf(&master_key, 1, "ECU1", 1000);
        let key2 = derive_session_key_hkdf(&master_key, 1, "ECU2", 1000);

        assert_ne!(key1, key2, "Different ECU ID should produce different keys");
    }

    #[test]
    fn test_key_encryption_decryption() {
        let key = [0xAAu8; 32];
        let kek = [0xBBu8; 32];
        let key_id = 42;

        let encrypted = encrypt_key_simple(&key, &kek, key_id);
        let decrypted = decrypt_key_simple(&encrypted, &kek, key_id).unwrap();

        assert_eq!(key, decrypted, "Decrypt should reverse encrypt");
    }

    #[test]
    fn test_key_encryption_different_kek_fails() {
        let key = [0xAAu8; 32];
        let kek1 = [0xBBu8; 32];
        let kek2 = [0xCCu8; 32];
        let key_id = 42;

        let encrypted = encrypt_key_simple(&key, &kek1, key_id);
        let decrypted = decrypt_key_simple(&encrypted, &kek2, key_id);

        // With AES-256-GCM, wrong KEK should cause authentication failure (return None)
        assert!(
            decrypted.is_none(),
            "Decryption with wrong KEK should fail due to authentication tag mismatch"
        );
    }

    #[test]
    fn test_rotation_manager_initialization() {
        let master_key = [0x99u8; 32];
        let manager = KeyRotationManager::with_default_policy(master_key, "TEST_ECU".to_string());

        assert_eq!(manager.current_key_id(), 1, "Should start with key_id=1");
        assert!(manager.get_active_key().is_some());
        assert_eq!(manager.get_active_key().unwrap().state, KeyState::Active);
    }

    #[test]
    fn test_rotation_manager_rotate() {
        let master_key = [0x99u8; 32];
        let mut manager =
            KeyRotationManager::with_default_policy(master_key, "TEST_ECU".to_string());

        let old_key_id = manager.current_key_id();
        let new_key_id = manager.rotate_key();

        assert_eq!(new_key_id, old_key_id + 1);
        assert_eq!(manager.current_key_id(), new_key_id);

        // Old key should be pending rotation
        let old_key = manager.get_key_by_id(old_key_id).unwrap();
        assert_eq!(old_key.state, KeyState::PendingRotation);

        // New key should be active
        let new_key = manager.get_active_key().unwrap();
        assert_eq!(new_key.state, KeyState::Active);
        assert_eq!(new_key.key_id, new_key_id);
    }

    #[test]
    fn test_rotation_policy_time_based() {
        let policy = KeyRotationPolicy::time_based_only(100); // 100 seconds

        let mut key = SessionKey::new(1, [0x42u8; 32]);
        assert!(!policy.should_rotate(&key), "New key should not rotate");

        // Simulate passage of time by manually setting activation_time
        key.activation_time = Some(Utc::now() - Duration::seconds(101));
        assert!(policy.should_rotate(&key), "Old key should rotate");
    }

    #[test]
    fn test_rotation_policy_counter_based() {
        let policy = KeyRotationPolicy::counter_based_only(1000); // 1000 frames

        let mut key = SessionKey::new(1, [0x42u8; 32]);
        key.frame_count = 999;
        assert!(
            !policy.should_rotate(&key),
            "Below threshold should not rotate"
        );

        key.frame_count = 1000;
        assert!(policy.should_rotate(&key), "At threshold should rotate");

        key.frame_count = 1001;
        assert!(policy.should_rotate(&key), "Above threshold should rotate");
    }

    #[test]
    fn test_rotation_policy_hybrid() {
        let mut policy = KeyRotationPolicy::default();
        policy.rotation_interval_secs = 100;
        policy.rotation_frame_threshold = 1000;

        let mut key = SessionKey::new(1, [0x42u8; 32]);

        // Neither condition met
        key.frame_count = 500;
        key.activation_time = Some(Utc::now() - Duration::seconds(50));
        assert!(!policy.should_rotate(&key));

        // Counter condition met
        key.frame_count = 1000;
        assert!(policy.should_rotate(&key));

        // Time condition met
        key.frame_count = 500;
        key.activation_time = Some(Utc::now() - Duration::seconds(101));
        assert!(policy.should_rotate(&key));
    }

    #[test]
    fn test_key_import_export() {
        let master_key = [0x77u8; 32];
        let kek = [0x88u8; 32];
        let mut manager = KeyRotationManager::with_default_policy(master_key, "ECU1".to_string());

        // Export current key
        let key_id = manager.current_key_id();
        let exported = manager.export_key(key_id, &kek).unwrap();

        // Create second manager and import key
        let master_key2 = [0x66u8; 32]; // Different master key
        let mut manager2 = KeyRotationManager::with_default_policy(master_key2, "ECU2".to_string());

        // Import key with same key_id as export (key_id is part of AES-GCM AAD, must match)
        let result = manager2.import_key(key_id, &exported, &kek);
        assert!(
            result.is_err(),
            "Import should fail due to key_id rollback protection (key_id {} <= current {})",
            key_id,
            manager2.current_key_id()
        );

        // Import with next key_id should work if we use the correct key_id for export/import
        let next_key_id = manager2.current_key_id() + 1;
        manager.rotate_key();
        let exported2 = manager.export_key(next_key_id, &kek).unwrap();
        let result2 = manager2.import_key(next_key_id, &exported2, &kek);
        assert!(
            result2.is_ok(),
            "Import should succeed with matching key_id: {:?}",
            result2.err()
        );
        assert_eq!(manager2.current_key_id(), next_key_id);
    }

    #[test]
    fn test_key_rollback_protection() {
        let master_key = [0x77u8; 32];
        let kek = [0x88u8; 32];
        let mut manager = KeyRotationManager::with_default_policy(master_key, "ECU1".to_string());

        // Rotate to key_id = 2
        manager.rotate_key();
        assert_eq!(manager.current_key_id(), 2);

        // Try to import key_id = 1 (rollback attack)
        let old_key_encrypted = encrypt_key_simple(&[0xFFu8; 32], &kek, 1);
        let result = manager.import_key(1, &old_key_encrypted, &kek);

        assert!(result.is_err(), "Should reject rollback to old key_id");
        assert!(result.unwrap_err().contains("rollback"));
    }

    #[test]
    fn test_multiple_keys_during_rotation() {
        let master_key = [0x99u8; 32];
        let mut manager =
            KeyRotationManager::with_default_policy(master_key, "TEST_ECU".to_string());

        // Initial state: key_id = 1
        assert_eq!(manager.current_key_id(), 1);

        // Rotate: key_id = 2, key 1 is pending
        manager.rotate_key();
        assert_eq!(manager.current_key_id(), 2);

        // Both keys should be retrievable
        let key1 = manager.get_key_by_id(1).unwrap();
        let key2 = manager.get_key_by_id(2).unwrap();

        assert_eq!(key1.state, KeyState::PendingRotation);
        assert!(key1.is_valid_for_rx(), "Old key should be valid for RX");
        assert!(
            !key1.is_valid_for_tx(),
            "Old key should NOT be valid for TX"
        );

        assert_eq!(key2.state, KeyState::Active);
        assert!(key2.is_valid_for_rx());
        assert!(key2.is_valid_for_tx());
    }

    #[test]
    fn test_key_cleanup() {
        let master_key = [0x99u8; 32];
        let mut policy = KeyRotationPolicy::default();
        policy.max_key_history = 3; // Keep only 3 keys

        let mut manager = KeyRotationManager::new(master_key, "TEST_ECU".to_string(), policy);

        // Rotate 5 times (should have keys 1, 2, 3, 4, 5, 6)
        for _ in 0..5 {
            manager.rotate_key();
        }

        assert_eq!(manager.current_key_id(), 6);

        // Should only have 3 keys in history (4, 5, 6)
        assert!(manager.get_all_keys().len() <= 3);
        assert!(manager.get_key_by_id(6).is_some());
        assert!(manager.get_key_by_id(1).is_none());
    }

    #[test]
    fn test_frame_counter_increment() {
        let mut key = SessionKey::new(1, [0x42u8; 32]);
        assert_eq!(key.frame_count, 0);

        key.increment_frame_count();
        assert_eq!(key.frame_count, 1);

        key.increment_frame_count();
        assert_eq!(key.frame_count, 2);
    }

    #[test]
    fn test_key_wrapping_at_u32_max() {
        let master_key = [0x99u8; 32];
        let mut manager =
            KeyRotationManager::with_default_policy(master_key, "TEST_ECU".to_string());

        // Set current key_id to u32::MAX - 1
        manager.current_key_id = u32::MAX - 1;

        // Rotate should wrap to 1 (skip 0)
        manager.rotate_key();
        assert_eq!(
            manager.current_key_id(),
            1,
            "Should wrap to 1 (skip 0 reserved)"
        );
    }
}
