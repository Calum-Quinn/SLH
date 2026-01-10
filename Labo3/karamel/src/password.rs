//! Hachage et vérification des mots de passe

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHashString, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::LazyLock};

static DEFAULT_HASHER: LazyLock<Argon2<'static>> = LazyLock::new(|| Argon2::default());

/// Le hash d'un mot de passe vide, à utiliser quand l'utilisateur n'existe pas
/// pour éviter une attaque par canal auxiliaire
static EMPTY_HASH: LazyLock<PWHash> = LazyLock::new(|| hash(""));

/// Un mot de passe haché
#[derive(Clone, Debug, Display)]
pub struct PWHash(PasswordHashString);

impl std::hash::Hash for PWHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state)
    }
}

impl Serialize for PWHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PWHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hash = PasswordHashString::from_str(&s)
            .map_err(|_| <D::Error as serde::de::Error>::custom("Invalid PHC string"))?;
        Ok(PWHash(hash))
    }
}

pub fn hash(password: &str) -> PWHash {
    // Generate random salt
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    // Hash password
    PWHash(
        argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .serialize(),
    )
}

pub fn verify(password: &str, maybe_hash: Option<&PWHash>) -> bool {
    let hash = maybe_hash.unwrap_or(&*EMPTY_HASH).0.password_hash();

    // Verify password
    let hash_ok = DEFAULT_HASHER
        .verify_password(password.as_bytes(), &hash)
        .is_ok();

    hash_ok && maybe_hash.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "StrongPassword123!";
        let hash = hash(password);
        assert!(verify(password, Some(&hash)));
    }

    #[test]
    fn test_incorrect_password() {
        let password = "StrongPassword123!";
        let hash = hash(password);
        assert!(!verify("WrongPassword", Some(&hash)));
    }

    #[test]
    fn test_empty_password() {
        let password = "";
        let hash = hash(password);
        assert!(verify(password, Some(&hash)));
    }

    #[test]
    fn test_invalid_hash() {
        assert!(!verify("", None))
    }

    #[test]
    fn test_long_password() {
        let password = "a".repeat(1000); // A very long password...
        let hash = hash(&password);
        assert!(verify(&password, Some(&hash)));
    }

    #[test]
    fn test_incorrect_hash() {
        let password = "StrongPassword123!";
        let bad_hash = hash("weakpassword");
        assert!(!verify(password, Some(&bad_hash)));
    }
}
