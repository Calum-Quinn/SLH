use crate::model::*;
use biscuit::{KeyPair, PublicKey};
use biscuit_auth::{self as biscuit, PrivateKey};
use derive_more::derive::{Deref, Display};
use serde::{de::Error, Deserialize, Serialize};

#[derive(Deref, Display, Debug, Clone)]
pub struct Pubkey(pub PublicKey);

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_bytes_hex().serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        let hex = String::deserialize(deserializer)?;
        Ok(Pubkey(PublicKey::from_bytes_hex(&hex).map_err(|_e| {
            D::Error::custom("invalid public key format")
        })?))
    }
}

#[derive(Deref, Debug, Default)]
pub struct Keypair(pub biscuit::KeyPair);

impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.private().to_bytes_hex().serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        let hex = String::deserialize(deserializer)?;
        let private = PrivateKey::from_bytes_hex(&hex).map_err(|e| D::Error::custom(e))?;
        Ok(Keypair(KeyPair::from(&private)))
    }
}

#[derive(Debug, Clone, Copy, Display, Serialize, Deserialize, Eq, PartialEq)]
pub enum NodeType {
    Directory,
    Store,
}

#[derive(Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub pubkey: Pubkey,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct Login {
    pub user: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub uid: UserID,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct PostReport {
    pub meta: ReportMeta,
    pub contents: String,
}
