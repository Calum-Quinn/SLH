use std::collections::BTreeSet;

use biscuit_auth::builder::{Term, ToAnyParam};
use chrono::{DateTime, NaiveDate};

use biscuit_auth as biscuit;
use derive_more::derive::Display;
use rocket::request::FromParam;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use uuid::Uuid;

/// Declares a new wrapper type containing an UUID
macro_rules! uuid_wrapper {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Display, Serialize, Deserialize, Ord, Eq, PartialOrd, PartialEq,
        )]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a random new value based on V4 UUIDs
            pub fn new() -> Self {
                $name(Uuid::new_v4())
            }
        }

        // This lets `rocket`` accept UUIDs as URL parameters
        impl<'a> FromParam<'a> for $name {
            type Error = <Uuid as FromParam<'a>>::Error;

            fn from_param(param: &'a str) -> Result<Self, Self::Error> {
                Uuid::from_param(param).map($name)
            }
        }

        // This lets `biscuit` datalog macros accept the wrappers as-is
        impl ToAnyParam for $name {
            fn to_any_param(&self) -> biscuit_auth::builder::AnyParam {
                self.0.to_any_param()
            }
        }

        // This lets `biscuit` datalog builders accept the wrappers as-is
        impl TryFrom<Term> for $name {
            type Error = biscuit::error::Token;

            fn try_from(value: Term) -> Result<Self, Self::Error> {
                let bytes: Vec<u8> = Vec::try_from(value)?;
                Ok($name(Uuid::from_slice(&bytes).unwrap()))
            }
        }

        // This allows transparent access to the underlying UUID bytes
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
    };
}

uuid_wrapper!(UserID);
uuid_wrapper!(ReportID);

#[derive(Clone, Debug, Display, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct Keyword(SmolStr);

#[derive(Debug, Display, Clone, Copy, Serialize, Deserialize)]
pub enum Gender {
    M,
    F,
    O,
}

#[derive(Debug, Display, Clone, Copy, Serialize, Deserialize)]
pub enum BloodType {
    A,
    B,
    AB,
    O,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatientData {
    pub name: String,
    pub birthday: NaiveDate,
    pub gender: Gender,
    pub blood_type: BloodType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub date: DateTime<chrono::Utc>,
    pub author: UserID,
    pub patient: UserID,
    pub keywords: BTreeSet<Keyword>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: ReportID,
    #[serde(flatten)]
    pub meta: ReportMeta,
    pub contents: String,
}

impl AsRef<str> for Keyword {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for Keyword {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}
