use std::collections::BTreeMap;

use karamel::{
    authorization::{Authorizer, RequestAuthorizer},
    db::JsonFile,
    model::{PatientData, Report, ReportID, UserID},
    protocol::{NodeInfo, NodeType, PostReport, Pubkey},
};
use rocket::{get, http::Status, launch, post, put, routes, serde::json::Json, State};

use biscuit_auth as biscuit;
use serde::{Deserialize, Serialize};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DATABASE_PATH: &str = "./store.json";
const PUBLIC_KEY_PATH: &str = "./pubkey.bin";

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    patients: BTreeMap<UserID, PatientData>,
    reports: BTreeMap<ReportID, Report>,
}

struct StoreState {
    data: JsonFile<StoreData>,
}

/* Les fonctions suivantes sont les routes HTTP exposées par le service. */

#[get("/")]
fn root(auth: &State<Authorizer>) -> Json<NodeInfo> {
    Json(NodeInfo {
        node_type: NodeType::Store,
        pubkey: Pubkey(auth.pubkey().clone()),
        version: VERSION.to_owned(),
    })
}

#[get("/patient/<patient_id>")]
async fn get_patient_data(
    state: &State<StoreState>,
    auth: RequestAuthorizer,
    patient_id: UserID,
) -> Result<Json<PatientData>, Status> {
    let lock = state.data.read().await;

    let data = lock
        .patients
        .get(&patient_id)
        .cloned()
        .ok_or(Status::NotFound)?;

    auth.allow_patient("read-patient", patient_id, &data)?;

    Ok(Json(data))
}

#[put("/patient/<patient_id>", data = "<patient_data>")]
async fn set_patient_data(
    state: &State<StoreState>,
    auth: RequestAuthorizer,
    patient_id: UserID,
    patient_data: Json<PatientData>,
) -> Result<(), Status> {
    auth.allow_patient("write-patient", patient_id, &patient_data)?;

    state
        .data
        .transact(|db| {
            db.patients.insert(patient_id, patient_data.0);
        })
        .await;

    Ok(())
}

#[post("/report", data = "<report>")]
async fn create_report(
    state: &State<StoreState>,
    auth: RequestAuthorizer,
    report: Json<PostReport>,
) -> Result<Json<ReportID>, Status> {
    let id = ReportID::new();
    let new_report = Report {
        id,
        meta: report.0.meta,
        contents: report.0.contents,
    };

    auth.allow_report("create-report", &new_report)?;
    state
        .data
        .transact(|db| {
            db.reports.insert(id, new_report);
        })
        .await;
    Ok(Json(id))
}

#[get("/report")]
async fn list_reports(state: &State<StoreState>) -> Result<Json<Vec<ReportID>>, Status> {
    Ok(Json(
        state.data.read().await.reports.keys().cloned().collect(),
    ))
}

#[get("/report/<report_id>")]
async fn read_report(
    state: &State<StoreState>,
    auth: RequestAuthorizer,
    report_id: ReportID,
) -> Result<Json<Report>, Status> {
    let Some(report) = state.data.read().await.reports.get(&report_id).cloned() else {
        return Err(Status::NotFound);
    };

    auth.allow_report("read-report", &report)?;

    Ok(Json(report))
}
/// Point d'entrée du serveur web (se substitue à la fonction `main`)
#[launch]
async fn server() -> _ {
    karamel::utils::init_tracing();

    let key_bytes = tokio::fs::read(PUBLIC_KEY_PATH)
        .await
        .expect("Cannot load public key file");

    let directory_key =
        biscuit::PublicKey::from_bytes(&key_bytes).expect("Cannot decode public key");
    let data = JsonFile::open_or_create(DATABASE_PATH)
        .await
        .expect("Cannot load database");
    let state = StoreState { data };
    let authorizer = Authorizer::new(directory_key);

    let config = rocket::Config {
        port: 8002,
        ..Default::default()
    };

    rocket::custom(config)
        .manage(state)
        .manage(authorizer)
        .mount(
            "/",
            routes![
                root,
                create_report,
                list_reports,
                read_report,
                get_patient_data,
                set_patient_data
            ],
        )
}
