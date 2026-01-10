use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use biscuit_auth::{self as biscuit, PublicKey, UnverifiedBiscuit};
use chrono::Utc;
use clap::{Parser, Subcommand};
use karamel::{
    model::{Keyword, Report, ReportID, ReportMeta, UserID},
    protocol::{self, LoginResponse, NodeInfo, NodeType, PostReport},
};
use tracing::{error, info};
use ureq::http::StatusCode;

#[derive(Parser)]
struct Args {
    /// URL of the Authority/Directory server
    #[arg(short, long, default_value = "http://localhost:8001")]
    directory_url: String,

    /// URL of the storage node to use
    #[arg(short, long, default_value = "http://localhost:8002")]
    store_url: String,

    /// File containing the authority public key
    #[arg(short, long, default_value = "./pubkey.bin")]
    public_key: String,

    /// File containing a biscuit to use for authentication
    #[arg(short, long, default_value = ".karamel-token")]
    token: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Send credentials to the Directory server, and save the received biscuit.
    Login {
        #[arg(short, long)]
        register: bool,
        user: String,
        password: String,
    },

    /// Delete the stored biscuit
    Logout,

    /// Checks the validity of the stored biscuit against the directory server,
    /// and check that the storage server uses the same public key
    Status,

    /// Reads a report from stdin and send it to storage
    Send {
        patient: String,
        keywords: Vec<String>,
    },

    /// List all available reports
    List,

    /// Read the contents of a report
    Read { id: String },

    /// Adds an attenuation to the biscuit
    Lock { check: String },
}
use Command::*;

fn nodeinfo(url: &str) -> Result<NodeInfo> {
    Ok(ureq::get(url).call()?.into_body().read_json()?)
}

fn load_public(path: &str) -> Result<PublicKey> {
    let key_bytes = std::fs::read(path)?;
    Ok(biscuit::PublicKey::from_bytes(&key_bytes)?)
}

fn load_biscuit(path: &str) -> Result<UnverifiedBiscuit> {
    let token =
        std::fs::read_to_string(path).with_context(|| format!("loading token file {}", path))?;

    let biscuit =
        biscuit::UnverifiedBiscuit::from_base64(token.as_bytes()).context("parsing token")?;

    Ok(biscuit)
}

fn get_biscuit_user_id(auth: &mut biscuit::Authorizer) -> Result<UserID> {
    let r: Vec<(UserID,)> = auth.query("data($user) <- user($user)")?;
    if r.len() != 1 {
        bail!("Biscuit doesn't have unique user id")
    }
    Ok(r[0].0)
}

fn get_users(directory: &str) -> Result<Vec<(UserID, String)>> {
    Ok(ureq::get(format!("{directory}/users"))
        .call()?
        .into_body()
        .read_json()?)
}

fn get_user_id(directory: &str, user: &str) -> Result<UserID> {
    get_users(directory)?
        .iter()
        .find(|(_uid, name)| name == user)
        .map(|(uid, _name)| *uid)
        .ok_or(anyhow!("User `{user}` not found"))
}

fn read_from_stdin() -> Result<String, std::io::Error> {
    use std::io::IsTerminal;

    const EOF_SIGNAL: &str = if cfg!(windows) {
            "Windows: Ctrl+Z, Enter"
        } else {
            "Linux: Enter, Ctrl+D"
        };

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("Enter report contents. Terminate with EOF signal ({EOF_SIGNAL})\n=== Start of Report ===");
    }
    let contents = std::io::read_to_string(std::io::stdin())?;
    if stdin.is_terminal() {
        eprintln!("=== End of Report ===");
    }
    Ok(contents)
}

fn main() -> Result<ExitCode> {
    karamel::utils::init_tracing();

    let args: Args = Args::parse();

    match args.cmd {
        Login {
            register,
            user,
            password,
        } => {
            if register {
                let user = user.clone();
                let password = password.clone();

                ureq::post(args.directory_url.clone() + "/register").send_json(
                    protocol::Login {
                        user: user,
                        password,
                    },
                )?;
                info!("Registration successful.")
            }

            let response = ureq::post(args.directory_url + "/login")
                .send_json(protocol::Login { user, password })?;

            if response.status() == StatusCode::FORBIDDEN {
                error!("Login failed.");
                return Ok(ExitCode::FAILURE);
            };

            let response: LoginResponse = response.into_body().read_json()?;

            info!("Login successful as {}", response.uid);

            std::fs::write(&args.token, response.token)?;
        }

        Logout => std::fs::remove_file(&args.token)?,

        Status => {
            let biscuit = load_biscuit(&args.token)?;

            let pubkey = load_public(&args.public_key)?;

            let mut authorizer = biscuit
                .verify(&pubkey)
                .context("verifying biscuit")?
                .authorizer()?;

            info!("Local key validates our token.");

            info!(
                "Token contents: =====\n{}\n=====================",
                authorizer.dump_code().trim()
            );

            let uid = get_biscuit_user_id(&mut authorizer)?;
            info!("Logged in as {uid}");

            match nodeinfo(&args.directory_url) {
                Ok(directory_info) => {
                    info!("Directory online. (v{})", directory_info.version);

                    if directory_info.node_type != NodeType::Directory {
                        error!("Directory URL is not a directory node");
                    }

                    if directory_info.pubkey.to_bytes() != pubkey.to_bytes() {
                        error!("Directory public key does not match local key.")
                    }
                }
                Err(e) => {
                    error!("Directory offline. ({e})");
                }
            };

            match nodeinfo(&args.store_url) {
                Ok(store_info) => {
                    info!("Storage server online. (v{})", store_info.version);

                    if store_info.pubkey.to_bytes() != pubkey.to_bytes() {
                        error!("Storage node public key does not match local key.")
                    }

                    if store_info.node_type != NodeType::Store {
                        error!("Storage URL is not a storage node");
                    }
                }
                Err(e) => {
                    error!("Storage node offline. ({e})");
                }
            }
        }

        List => {
            let ids: Vec<ReportID> = ureq::get(args.store_url.clone() + "/report")
                .add_auth_token_by_path(&args.token)?
                .call()?
                .into_body()
                .read_json()?;

            for id in &ids {
                println!("{id}");
            }
            eprintln!("{} reports.", ids.len())
        }

        Send { patient, keywords } => {
            let biscuit = load_biscuit(&args.token)?;
            let directory_pubkey = load_public(&args.public_key)?;

            let mut auth = biscuit.clone().verify(directory_pubkey)?.authorizer()?;

            let author = get_biscuit_user_id(&mut auth)?;
            let patient = get_user_id(&args.directory_url, &patient)?;
            let keywords = keywords.into_iter().map(Keyword::from).collect();

            let meta = ReportMeta {
                date: Utc::now(),
                author,
                patient,
                keywords,
            };

            let contents = read_from_stdin()?;

            let data = PostReport { meta, contents };

            let id: ReportID = ureq::post(args.store_url + "/report")
                .add_auth_token(&biscuit)?
                .send_json(data)?
                .into_body()
                .read_json()?;

            info!("Report {id} created.");
        }

        Read { id } => {
            let rep: Report = ureq::get(format!("{}/report/{}", args.store_url, id))
                .add_auth_token_by_path(&args.token)?
                .call()?
                .into_body()
                .read_json()?;

            println!("{rep:?}");
        }

        Lock { check } => {
            let biscuit = load_biscuit(&args.token)?;
            let directory_pubkey = load_public(&args.public_key)?;

            let biscuit = biscuit.verify(directory_pubkey)?;

            let mut block = biscuit::builder::BlockBuilder::new();

            block.add_code(&check)?;

            let biscuit = biscuit.append(block)?;

            std::fs::write(&args.token, biscuit.to_base64()?)?;
        }
    }

    Ok(ExitCode::SUCCESS)
}

trait AuthWithToken: Sized {
    fn add_auth_token(self, path: &UnverifiedBiscuit) -> Result<Self>;

    fn add_auth_token_by_path(self, path: &str) -> Result<Self> {
        let biscuit = load_biscuit(path)?;
        self.add_auth_token(&biscuit)
    }
}

impl<T> AuthWithToken for ureq::RequestBuilder<T> {
    fn add_auth_token(self, biscuit: &UnverifiedBiscuit) -> Result<Self> {
        let token = biscuit.to_base64()?;
        let token = token.trim();
        Ok(self.header("Authorization", format!("Bearer {token}")))
    }
}
