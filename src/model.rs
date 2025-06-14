use crate::dir::{CrateVersionDirIndex, CrateWorkspaceFileSystemManager, CrateWorkspaceIndex};
use crate::utils;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Krate {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) dependents: Vec<Krate>,
    /// the working directory of the crate. when analyzing a crate,
    /// a copy of the crate will be created in the working directory
    pub(crate) ws_idx: CrateWorkspaceIndex,
    pub(crate) dir_idx: CrateVersionDirIndex,
    pub(crate) working_dir: PathBuf,
}

impl Krate {
    /// This function is used to create a krate
    /// 1. create a krate workspace and version directory
    /// 2. download and unzip the crate
    /// 3. copy it to the working directory
    /// 4. return the krate object
    pub async fn create(
        name: &str,
        version: &str,
        parent_version_dir_index: CrateVersionDirIndex,
        fs_manager: Arc<Mutex<CrateWorkspaceFileSystemManager>>,
    ) -> Result<Self> {
        let (ws_idx, dir_idx) = fs_manager
            .lock()
            .await
            .create_krate_working_dir(parent_version_dir_index, name, version)
            .await?;

        let krate = Self {
            name: name.to_owned(),
            version: version.to_owned(),
            dependents: Vec::new(),
            ws_idx,
            dir_idx,
            working_dir: fs_manager
                .lock()
                .await
                .get_krate_working_dir(dir_idx)
                .await,
        };

        // download into download directory and unzip into extract directory
        krate.fetch_and_unzip_crate().await?;
        // copy the crate to the working directory
        // now, we have a copy of the crate in the
        // working directory, which can be modified anyway
        krate
            .cp_crate_to_working_dir(fs_manager)
            .await
            .expect("Failed to copy crate to working directory");
        Ok(krate)
    }

    /// obtain the download directory
    /// $DOWNLOAD_DIR/crate_name/ ,such as /home/rust/xinshi/download/crossbeam-channel/
    async fn get_download_crate_dir_path(&self) -> PathBuf {
        let base_dir = std::env::var("DOWNLOAD_DIR").unwrap_or_else(|_| "./downloads".to_string());
        Path::new(&base_dir).join(&self.name)
    }

    /// obtain the crate file path
    /// $DOWNLOAD_DIR/crate_name/crate_name-crate_version.crate
    async fn get_download_crate_file_path(&self) -> PathBuf {
        let crate_file = format!("{}-{}.crate", self.name, self.version);
        self.get_download_crate_dir_path().await.join(crate_file)
    }

    /// obtain the extract directory path
    /// $DOWNLOAD_DIR/crate_name/crate_name-crate_version/
    async fn get_extract_crate_dir_path(&self) -> PathBuf {
        let extract_dir = format!("{}-{}", self.name, self.version);
        self.get_download_crate_dir_path().await.join(extract_dir)
    }

    pub(crate) async fn get_working_dir(
        &self,
    ) -> PathBuf {
        self.working_dir.clone()
    }

    pub(crate) async fn get_cargo_toml_path(
        &self,
    ) -> PathBuf {
        self.working_dir.join("Cargo.toml")
    }

    pub(crate) async fn get_target_dir(&self) -> PathBuf {
        self.working_dir.join("target")
    }

    pub(crate) async fn get_src_dir(&self) -> PathBuf {
        self.working_dir.join("src")
    }

    pub async fn has_cargo_toml(&self) -> bool {
        self.get_cargo_toml_path().await.exists()
    }

    /// download the crate file
    async fn download(&self, force: bool) -> Result<()> {
        tracing::debug!("Download crate: {} {}", self.name, self.version);

        let download_dir = self.get_download_crate_dir_path().await;
        let crate_file_path = self.get_download_crate_file_path().await;
        let extract_dir_path = self.get_extract_crate_dir_path().await;

        // check if the crate-version.crate file already exists
        // we don't need to download the crate file again
        if crate_file_path.exists() && !force {
            tracing::debug!("{} exists, skip the download", extract_dir_path.display());
            return Ok(());
        }

        tokio_fs::create_dir_all(&download_dir)
            .await
            .context(format!(
                "Failed to create the download directory: {}",
                download_dir.display()
            ))?;

        // download the crate file
        tracing::debug!("Downloading the crate file: {}", crate_file_path.display());
        let download_url = format!(
            "https://crates.io/api/v1/crates/{}/{}/download",
            self.name, self.version
        );

        let download_result = Command::new("curl")
            .args(&[
                "-L",
                &download_url,
                "-o",
                &crate_file_path.to_string_lossy(),
            ])
            .output()
            .await;

        if let Err(e) = download_result {
            return Err(anyhow::anyhow!("Failed to download the crate: {}", e));
        }

        // check the file size
        let metadata = tokio_fs::metadata(&crate_file_path).await.context(format!(
            "Failed to get the file metadata: {}",
            crate_file_path.display()
        ))?;

        if metadata.len() == 0 {
            return Err(anyhow::anyhow!(
                "Failed to download: the size of {} is 0",
                crate_file_path.display()
            ));
        }

        Ok(())
    }

    /// unzip the crate file
    async fn unzip(&self, force: bool) -> Result<()> {
        let crate_file_path = self.get_download_crate_file_path().await;
        let extract_dir_path = self.get_extract_crate_dir_path().await;
        let download_dir = self.get_download_crate_dir_path().await;

        // if the target directory already exists, return directly
        if extract_dir_path.exists() {
            if !force {
                tracing::debug!(
                    "directory {} already exists, no need to extract",
                    extract_dir_path.display()
                );
                return Ok(());
            } else {
                tracing::debug!(
                    "directory {} already exists, but force is true, so delete it",
                    extract_dir_path.display()
                );
                tokio_fs::remove_dir_all(&extract_dir_path).await?;
            }
        }

        // ensure the crate file exists
        if !crate_file_path.exists() {
            return Err(anyhow::anyhow!(
                "Cannot extract, crate file does not exist: {}",
                crate_file_path.display()
            ));
        }

        // extract the crate
        info!(
            "extracting crate: {} to {}",
            crate_file_path.display(),
            download_dir.display()
        );

        let unzip_result = Command::new("tar")
            .args(&["-xf", &crate_file_path.to_string_lossy()])
            .current_dir(&download_dir)
            .output()
            .await
            .context("Failed to execute tar command")?;

        if !unzip_result.status.success() {
            let stderr = String::from_utf8_lossy(&unzip_result.stderr);
            return Err(anyhow::anyhow!(
                "Extract {} failed: {}",
                crate_file_path.display(),
                stderr
            ));
        }

        // check if the directory exists
        if !extract_dir_path.exists() {
            // try to list the current directory contents
            let entries = tokio_fs::read_dir(&download_dir)
                .await
                .context("Failed to read directory")?;

            let mut files = String::new();
            let mut entry_count = 0;

            tokio::pin!(entries);
            while let Some(entry) = entries
                .next_entry()
                .await
                .context("Failed to read directory entry")?
            {
                files.push_str(&format!("\n  - {}", entry.path().display()));
                entry_count += 1;

                if entry_count > 10 {
                    files.push_str("\n  ... (more files)");
                    break;
                }
            }

            return Err(anyhow::anyhow!(
                "Extracted directory does not exist: {}. Directory contents: {}",
                extract_dir_path.display(),
                files
            ));
        }

        info!(
            "Successfully extracted crate to: {}",
            extract_dir_path.display()
        );
        Ok(())
    }

    /// download and unzip the crate, return the path to the extracted directory
    pub async fn fetch_and_unzip_crate(&self) -> Result<PathBuf> {
        let extract_dir_path = self.get_extract_crate_dir_path().await;
        let mut last_err = None;
        for attempt in 0..3 {
            // if the extract directory does not exist, download and unzip the crate
            let result = async {
                tracing::debug!("get_crate_dir_path: extract directory does not exist, prepare to download and unzip");
                // if the attempt is greater than 0, we need to force the download and unzip
                let force = attempt > 0;
                if let Err(e) = self.download(force).await {
                    tracing::error!("Failed to download the crate: {}", e);
                    return Err(anyhow::anyhow!("download() failed: {}", e));
                }

                if let Err(e) = self.unzip(force).await {
                    tracing::error!(
                        "Failed to unzip the crate {}: {e}",
                        extract_dir_path.display()
                    );
                    return Err(anyhow::anyhow!("unzip() failed: {}", e));
                }

                // 检查是否有 Cargo.toml
                if !self.has_cargo_toml().await {
                    return Err(anyhow::anyhow!("No Cargo.toml found in {}, will retry if attempts remain", extract_dir_path.display()));
                }else{
                    tracing::info!("Successfully extracted crate to: {}", extract_dir_path.display());
                }

                tracing::debug!("get_crate_dir_path: return the unzip directory: {}", extract_dir_path.display());
                Ok(extract_dir_path.clone())
            }.await;

            match result {
                Ok(path) => return Ok(path),
                Err(e) => {
                    last_err = Some(e);
                    tracing::warn!(
                        "No Cargo.toml found in {} (attempt {}/3), will retry if attempts remain",
                        extract_dir_path.display(),
                        attempt + 1
                    );
                    // 删除解压目录，准备重试
                    let _ = tokio_fs::remove_dir_all(&extract_dir_path).await;
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| anyhow::anyhow!("fetch_and_unzip_crate failed for unknown reason")))
    }

    async fn cp_crate_to_working_dir(
        &self,
        fs_manager: Arc<Mutex<CrateWorkspaceFileSystemManager>>,
    ) -> Result<()> {
        let extract_dir = self.get_extract_crate_dir_path().await;
        let working_dir = fs_manager
            .lock()
            .await
            .get_krate_working_dir(self.dir_idx)
            .await;

        tracing::debug!(
            "Copy the crate to the working directory: {} -> {}",
            extract_dir.display(),
            working_dir.display()
        );
        utils::copy_dir(&extract_dir, &working_dir, false).await?;
        Ok(())
    }

    /// execute cargo clean in the crate extract directory, release the target space
    pub async fn cargo_clean(
        &self,
        fs_manager: Arc<Mutex<CrateWorkspaceFileSystemManager>>,
    ) -> Result<()> {
        let extract_dir = self.get_working_dir(fs_manager).await;
        let manifest_path = extract_dir.join("Cargo.toml");
        if !manifest_path.exists() {
            tracing::warn!("cargo_clean: {} 不存在，跳过", manifest_path.display());
            return Ok(());
        }
        tracing::info!("cargo_clean: {}", manifest_path.display());
        let output = Command::new("cargo")
            .args(&["clean", "--manifest-path", &manifest_path.to_string_lossy()])
            .current_dir(&extract_dir)
            .output()
            .await
            .context(format!(
                "执行 cargo clean 失败: {}",
                manifest_path.display()
            ))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("cargo clean 执行失败: {}", stderr);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReverseDependency {
    // the crate name of the reverse dependency
    pub name: String,
    // the version of the reverse dependency
    pub version: String,
    // the version requirement of the dependency
    // i.e. `[dependencies]  "dep_name" = "1.0.0"` in `Cargo.toml`
    pub req: String,
}

impl ReverseDependency {
    pub fn new(name: String, version: String, req: String) -> Self {
        Self { name, version, req }
    }
}
