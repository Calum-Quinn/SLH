use std::collections::BTreeMap;

use biscuit::macros::biscuit;
use biscuit_auth as biscuit;

use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, launch, post, routes, State};

use serde::{Deserialize, Serialize};

use karamel::db::JsonFile;
use karamel::model::*;
use karamel::password::{hash, verify, PWHash};
use karamel::protocol::{Keypair, Login, LoginResponse, NodeInfo, NodeType, Pubkey};
use tracing::info;
use validator::ValidateEmail;
use zxcvbn::{zxcvbn, Score};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DATABASE_PATH: &str = "./directory.json";
const PUBLIC_KEY_PATH: &str = "./pubkey.bin";

/// Données associées à un nom d'utilisateur
#[derive(Serialize, Deserialize)]
struct UserData {
    id: UserID,
    hash: PWHash,
    /// Si l'utilisateur est médecin, ou seulement patient
    doctor: bool,
}

/// Données stockées par le serveur d'autorité
#[derive(Serialize, Deserialize, Default)]
struct DirectoryState {
    /// Clé privée de l'autorité
    key: Keypair,

    /// Utilisateurs enregistrés (login => données)
    users: BTreeMap<String, UserData>,
}

/* Les fonctions suivantes sont les routes HTTP exposées par le service. */

#[get("/")]
async fn root(state: &State<JsonFile<DirectoryState>>) -> Json<NodeInfo> {
    let state = state.read().await;
    Json(NodeInfo {
        node_type: NodeType::Directory,
        pubkey: Pubkey(state.key.public()),
        version: VERSION.into(),
    })
}

#[get("/users")]
async fn users(state: &State<JsonFile<DirectoryState>>) -> Json<Vec<(UserID, String)>> {
    Json(
        state
            .read()
            .await
            .users
            .iter()
            .map(|(name, data)| (data.id, name.to_owned()))
            .collect(),
    )
}

#[post("/login", data = "<login>")]
async fn login(
    state: &State<JsonFile<DirectoryState>>,
    login: Json<Login>,
) -> Result<Json<LoginResponse>, Status> {
    let state = state.read().await;
    let user = state.users.get(&login.user);

    let maybe_hash = user.map(|d| &d.hash);

    if !verify(&login.password, maybe_hash) {
        return Err(Status::Forbidden);
    }

    let Some(userdata) = user else {
        return Err(Status::Forbidden);
    };

    let uid = userdata.id;
    let is_doctor = userdata.doctor;

    let token = biscuit!(r#" user({uid}); is_doctor({uid}, {is_doctor}); "#)
        .build(&state.key)
        .and_then(|b| b.to_base64())
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(LoginResponse { uid, token }))
}

#[post("/register?<doctor>", data = "<login>")]
async fn register(
    state: &State<JsonFile<DirectoryState>>,
    doctor: Option<bool>,
    login: Json<Login>,
) -> Result<Json<UserID>, Status> {
    let Json(Login { user, password }) = login;

    // C13: Validate that username is a valid email address
    if !user.validate_email() {
        return Err(Status::BadRequest);
    }

    // C14: Reject weak passwords (ZXCVBN score < 3)
    let password_strength = zxcvbn(&password, &[&user]);
    if !matches!(password_strength.score(), Score::Three | Score::Four) {
        return Err(Status::BadRequest);
    }

    let doctor = doctor.unwrap_or_default();

    state
        .transact(move |db| {
            if db.users.contains_key(&user) {
                return Err(Status::Forbidden);
            }

            let id = UserID::new();

            db.users.insert(
                user,
                UserData {
                    id,
                    doctor,
                    hash: hash(&password),
                },
            );

            Ok(Json(id))
        })
        .await
}

/// Point d'entrée du serveur web (se substitue à la fonction `main`)
#[launch]
async fn server() -> _ {
    karamel::utils::init_tracing();

    // Chargement de l'état du directory
    let state: JsonFile<DirectoryState> = JsonFile::open_or_create(DATABASE_PATH).await
        .expect("Cannot load database.");

    // Export de la clé publique
    let pubkey = state.read().await.key.public();
    tokio::fs::write(PUBLIC_KEY_PATH, pubkey.to_bytes())
        .await
        .expect("Cannot export public key");
    info!("Public key written to {PUBLIC_KEY_PATH}");

    // Configuration de Rocket
    let config = rocket::Config {
        port: 8001,
        ..Default::default()
    };

    // Démarrage de Rocket
    rocket::custom(config)
        .mount("/", routes![root, login, register, users])
        .manage(state)
}
