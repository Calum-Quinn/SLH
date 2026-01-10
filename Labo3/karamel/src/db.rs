use serde::{de::DeserializeOwned, Serialize};
use serde_json;
use std::path::PathBuf;
use tracing::info;

use tokio::fs::{File, OpenOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, RwLockReadGuard},
};

/// An in-memory data structure backed by a file on disk.
///
/// This is adequate to persist serializable objects of reasonable size,
/// where a full key-value store or SQL database would be overkill.
///
/// # Usage
///
/// ```rust
/// tokio_test::block_on(async {
/// use karamel::db::JsonFile;
///
/// let stored_blobs: JsonFile<Vec<String>> = JsonFile::open_or_create("/tmp/test.json").await.unwrap();
///
///     stored_blobs.transact(|blobs| {
///         blobs.push("Hello,".to_string());
///         blobs.push("World!".to_string());
///     }).await;
///
///     let blobs = stored_blobs.read().await;
///     assert_eq!(blobs.len(), 2);
/// });
/// ```
pub struct JsonFile<D> {
    path: PathBuf,
    inner: RwLock<D>,
}

impl<D: DeserializeOwned + Serialize + Default> JsonFile<D> {
    /// Initializes the store with the data read on disk. If the file does not exist,
    /// it is created with the value provided by [`Default`].
    pub async fn open_or_create<P: Into<PathBuf>>(path: P) -> Result<Self, std::io::Error> {
        Self::open_or_create_path(path.into()).await
    }

    async fn open_or_create_path(path: PathBuf) -> Result<Self, std::io::Error> {
        let inner = D::default();
        let buf = serde_json::to_vec(&inner)?;

        if let Ok(mut fresh) = File::create_new(&path).await {
            info!("Creating new database {path:?}");
            fresh.write_all(&buf).await?
        }

        Self::open(path).await
    }
}

impl<D: DeserializeOwned> JsonFile<D> {
    /// Opens a file on disk and reads the contents, or fails if
    /// the contents is not available.
    pub async fn open(path: PathBuf) -> Result<Self, std::io::Error> {
        let mut file = OpenOptions::new().read(true).open(&path).await?;
        let mut buf = vec![];
        file.read_to_end(&mut buf).await?;

        let inner = RwLock::new(serde_json::from_reader(&buf[..])?);

        Ok(Self { path, inner })
    }
}

impl<D> JsonFile<D> {
    /// Acquires a read lock on the structure
    pub async fn read(&self) -> RwLockReadGuard<'_, D> {
        self.inner.read().await
    }
}

impl<D: Serialize> JsonFile<D> {
    /// Executes a transaction with a write lock on the database.
    /// After the transaction is complete, the database is entirely
    /// written to the file.
    pub async fn transact<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut D) -> R,
    {
        let mut lock = self.inner.write().await;
        let mut file = File::options().write(true).open(&self.path).await.unwrap();

        let result = f(&mut *lock);
        let buf = serde_json::to_vec_pretty(&*lock).unwrap();

        file.write_all(&buf[..])
            .await
            .expect("Could not save database");

        drop(lock);
        info!("Database saved.");

        result
    }
}
