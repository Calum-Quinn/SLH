use biscuit::{macros::authorizer, PublicKey, UnverifiedBiscuit};
use biscuit_auth::{
    self as biscuit,
    builder::{bytes, date, fact, set, string},
    builder_ext::BuilderExt,
};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    State,
};
use smol_str::ToSmolStr;
use tracing::{debug, error, warn};

use crate::model::*;

/// Configuration d'autorisation côté serveur, contenant une clé publique Ed25519
/// et une politique Biscuit
#[derive(Clone)]
pub struct Authorizer {
    pubkey: PublicKey,
    policy: biscuit::Authorizer,
}

impl Authorizer {
    pub fn new(pubkey: PublicKey) -> Self {
        let policy = authorizer!(r#"

        // Patients can read and modify their personal information
        allow if operation("read-patient"), user($u), patient($u);
        allow if operation("write-patient"), user($u), patient($u);

        // Patients can read reports about them
        allow if operation("read-report"), user($u), patient($u);

        // Report authors can read their own reports
        allow if operation("read-report"), user($u), author($u);

        // Doctors can read everyone's personal information
        allow if operation("read-patient"), user($u), is_doctor($u, true);

        // Only doctors can create new reports, and they must be the author
        allow if operation("create-report"), user($u), is_doctor($u, true), author($u);

        "#);

        Self { pubkey, policy }
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    /// Vérifie et injecte un biscuit dans le contexte d'autorisation
    pub fn request(
        &self,
        token: UnverifiedBiscuit,
    ) -> Result<RequestAuthorizer, biscuit::error::Token> {
        let token = token.verify(&self.pubkey)?;
        let mut auth = self.policy.clone();

        auth.add_token(&token)?;
        auth.set_time();

        Ok(RequestAuthorizer(auth))
    }
}

fn add_report_facts(
    auth: &mut biscuit::Authorizer,
    report: &Report,
) -> Result<(), biscuit::error::Token> {
    auth.add_fact(fact("id", &[bytes(report.id.as_ref())]))?;
    auth.add_fact(fact("author", &[bytes(report.meta.author.as_ref())]))?;
    auth.add_fact(fact("patient", &[bytes(report.meta.patient.as_ref())]))?;
    auth.add_fact(fact(
        "report_time",
        &[date(&std::time::SystemTime::from(report.meta.date))],
    ))?;
    auth.add_fact(fact(
        "keyword",
        &[set(report
            .meta
            .keywords
            .iter()
            .cloned()
            .map(|k| string(k.as_ref()))
            .collect())],
    ))?;
    Ok(())
}

fn add_patient_facts(
    auth: &mut biscuit::Authorizer,
    patient_id: UserID,
    patient_data: &PatientData,
) -> Result<(), biscuit::error::Token> {
    auth.add_fact(fact("patient", &[bytes(patient_id.as_ref())]))?;
    auth.add_fact(fact(
        "blood_type",
        &[string(&patient_data.blood_type.to_smolstr())],
    ))?;
    auth.add_fact(fact("gender", &[string(&patient_data.gender.to_smolstr())]))?;
    Ok(())
}

/// Contexte d'autorisation pour une requête, dérivée à partir de l'[`Authorizer`]
/// du serveur, et du biscuit passé en bearer token dans le header `Authorization``.
pub struct RequestAuthorizer(biscuit::Authorizer);

impl RequestAuthorizer {
    pub fn allow_report(&self, operation: &str, report: &Report) -> Result<(), Status> {
        let mut authorizer = self.0.clone();

        if let Err(e) = add_report_facts(&mut authorizer, report) {
            error!("Could not add report facts: {e:?}");
            return Err(Status::InternalServerError);
        };
        authorizer.add_operation(operation);

        Self::allow(authorizer)
    }

    pub fn allow_patient(
        &self,
        operation: &str,
        patient_id: UserID,
        patient_data: &PatientData,
    ) -> Result<(), Status> {
        let mut authorizer = self.0.clone();

        if let Err(e) = add_patient_facts(&mut authorizer, patient_id, patient_data) {
            error!("Could not add patient facts: {e:?}");
            return Err(Status::InternalServerError);
        };

        authorizer.add_operation(operation);
        Self::allow(authorizer)
    }

    fn allow(mut authorizer: biscuit::Authorizer) -> Result<(), Status> {
        debug!("Authorizer: {}", authorizer.dump_code());

        authorizer.authorize().map_err(|e| {
            warn!("Permission denied ({e})");
            Status::Forbidden
        })?;

        Ok(())
    }
}

fn unauthorized<T>(reason: &'static str) -> Outcome<T, &'static str> {
    Outcome::Error((Status::Unauthorized, reason))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestAuthorizer {
    type Error = &'static str;

    async fn from_request(req: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(auth) = req.headers().get("Authorization").next() else {
            warn!("Unauthenticated request");
            return unauthorized("no auth header");
        };

        let Some(bearer_token) = auth.strip_prefix("Bearer") else {
            warn!("Unexpected authorization method");
            return unauthorized("not bearer token");
        };

        let bearer_token = bearer_token.trim();

        let Ok(biscuit) = UnverifiedBiscuit::from_base64(bearer_token) else {
            warn!("Invalid biscuit format");
            return unauthorized("invalid biscuit format");
        };

        req.guard::<&State<Authorizer>>()
            .await
            .map_error(|(s, ())| (s, "no authorizer"))
            .and_then(move |auth| match auth.request(biscuit) {
                Ok(rauth) => Outcome::Success(rauth),
                Err(biscuit_error) => {
                    warn!("Invalid biscuit: {}", biscuit_error);
                    unauthorized("invalid biscuit contents")
                }
            })
    }
}
