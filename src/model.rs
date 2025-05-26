use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::info;

const MAX_DOWNLOAD_CONCURRENT: usize = 4; // 与 DependencyAnalyzer 保持一致
                                          // static CARGO_UPDATE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// 下载/解压限流
static DOWNLOAD_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(MAX_DOWNLOAD_CONCURRENT)));

#[derive(Debug, Clone)]
pub struct Krate {
    name: String,
    version: String,
    dependents: Vec<Krate>,
}

impl Krate {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            dependents: Vec::new(),
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn version(&self) -> String {
        self.version.clone()
    }

    #[allow(dead_code)]
    pub fn dependents(&self) -> &Vec<Krate> {
        &self.dependents
    }

    #[allow(dead_code)]
    pub fn dependents_mut(&mut self) -> &mut Vec<Krate> {
        &mut self.dependents
    }

    /// obtain the download directory
    /// $DOWNLOAD_DIR/crate_name/ ,such as /home/rust/xinshi/download/crossbeam-channel/
    fn get_download_dir(&self) -> PathBuf {
        let base_dir = std::env::var("DOWNLOAD_DIR").unwrap_or_else(|_| "./downloads".to_string());
        Path::new(&base_dir).join(&self.name)
    }

    /// obtain the crate file path
    /// $DOWNLOAD_DIR/crate_name/crate_name-crate_version.crate
    fn get_crate_file_path(&self) -> PathBuf {
        let crate_file = format!("{}-{}.crate", self.name, self.version);
        self.get_download_dir().join(crate_file)
    }

    /// obtain the extract directory path
    /// $DOWNLOAD_DIR/crate_name/crate_name-crate_version/
    fn get_extract_dir_path(&self) -> PathBuf {
        let extract_dir = format!("{}-{}", self.name, self.version);
        self.get_download_dir().join(extract_dir)
    }

    /// download the crate file
    async fn download(&self) -> Result<()> {
        info!("download crate: {} {}", self.name, self.version);

        let download_dir = self.get_download_dir();
        let crate_file_path = self.get_crate_file_path();
        let extract_dir_path = self.get_extract_dir_path();

        tracing::info!("crate_file_path: {}", crate_file_path.display());
        tracing::info!("extract_dir_path: {}", extract_dir_path.display());
        tracing::info!("download_dir: {}", download_dir.display());

        // check if the crate-version.crate file already exists
        // we don't need to download the crate file again
        if crate_file_path.exists() {
            info!(
                "directory {} already exists, skip the download",
                extract_dir_path.display()
            );
            return Ok(());
        }

        tokio_fs::create_dir_all(&download_dir)
            .await
            .context(format!(
                "Failed to create the download directory: {}",
                download_dir.display()
            ))?;

        // download the crate file
        info!("downloading the crate file: {}", crate_file_path.display());
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

        let size = metadata.len();
        info!("the size of the downloaded file is {} bytes", size);

        if size == 0 {
            return Err(anyhow::anyhow!(
                "the size of the downloaded file is 0, maybe the download failed"
            ));
        }

        Ok(())
    }

    /// unzip the crate file
    async fn unzip(&self) -> Result<PathBuf> {
        let crate_file_path = self.get_crate_file_path();
        let extract_dir_path = self.get_extract_dir_path();
        let download_dir = self.get_download_dir();

        tracing::info!("crate_file_path: {}", crate_file_path.display());
        tracing::info!("extract_dir_path: {}", extract_dir_path.display());
        tracing::info!("download_dir: {}", download_dir.display());

        // if the target directory already exists, return directly
        if extract_dir_path.exists() {
            info!(
                "directory {} already exists, no need to extract",
                extract_dir_path.display()
            );
            return Ok(extract_dir_path);
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
            return Err(anyhow::anyhow!("Extract command failed: {}", stderr));
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
        Ok(extract_dir_path)
    }

    /// download and unzip the crate, return the path to the extracted directory
    pub async fn get_crate_dir_path(&self) -> Result<PathBuf> {
        let _download_permit = DOWNLOAD_SEMAPHORE.acquire().await.unwrap();

        let extract_dir_path = self.get_extract_dir_path();
        let _key = format!("{}-{}", self.name, self.version);

        tracing::info!(
            "get_crate_dir_path: extract_dir_path={}",
            extract_dir_path.display()
        );

        // 优先判断解压目录是否已存在
        if extract_dir_path.exists() && extract_dir_path.is_dir() {
            tracing::info!(
                "get_crate_dir_path: 解压目录已存在: {}",
                extract_dir_path.display()
            );
            return Ok(extract_dir_path);
        }

        // 下面的代码只有第一个任务能执行
        let result = async {
            tracing::info!("get_crate_dir_path: 解压目录不存在，准备下载和解压");

            if let Err(e) = self.download().await {
                tracing::warn!(
                    "get_crate_dir_path: download()失败: {}，crate_file_path={}",
                    e,
                    self.get_crate_file_path().display()
                );
                return Err(anyhow::anyhow!("download()失败: {}", e));
            } else {
                tracing::info!("get_crate_dir_path: download()成功");
            }

            let unzip_path = match self.unzip().await {
                Ok(path) => {
                    tracing::info!("get_crate_dir_path: unzip() 成功，解压到: {}", path.display());
                    path
                }
                Err(e) => {
                    tracing::warn!(
                        "get_crate_dir_path: unzip() 失败: {}，crate_file_path={}, extract_dir_path={}",
                        e,
                        self.get_crate_file_path().display(),
                        extract_dir_path.display()
                    );
                    return Err(anyhow::anyhow!("unzip() 失败: {}", e));
                }
            };

            // 检查解压目录
            if !unzip_path.is_dir() || unzip_path.read_dir().is_err() {
                tracing::warn!(
                    "get_crate_dir_path: 解压目录不是有效目录: {}",
                    unzip_path.display()
                );
                return Err(anyhow::anyhow!(
                    "the unzip path is not a directory: {}",
                    unzip_path.display()
                ));
            }

            tracing::info!("get_crate_dir_path: 返回解压目录: {}", unzip_path.display());
            Ok(unzip_path)
        }.await;

        result
    }

    /// cleanup the downloaded crate file, keep the extracted directory
    pub async fn cleanup_crate_file(&self) -> Result<()> {
        let crate_file_path = self.get_crate_file_path();

        if crate_file_path.exists() {
            tokio_fs::remove_file(&crate_file_path)
                .await
                .context(format!(
                    "Failed to delete file: {}",
                    crate_file_path.display()
                ))?;
            info!("Deleted crate file: {}", crate_file_path.display());
        }

        Ok(())
    }

    /// 修改目标 crate 的 Cargo.toml，将父节点依赖锁定为指定版本
    pub async fn patch_cargo_toml_with_parent(
        crate_dir: &Path,
        parent_name: &str,
        parent_version: &str,
    ) -> Result<Option<String>> {
        let cargo_toml_path = crate_dir.join("Cargo.toml");
        let original_content = tokio_fs::read_to_string(&cargo_toml_path).await.ok();

        let mut command_str = String::new();
        write!(
            &mut command_str,
            "cargo update --precise {} --package {} --manifest-path {}",
            parent_version,
            parent_name,
            cargo_toml_path.to_string_lossy()
        )
        .expect("构建命令字符串失败");

        // 记录执行的命令
        tracing::info!("执行命令: {}", command_str);

        // let _update_guard = CARGO_UPDATE_MUTEX.lock().await;
        // 使用cargo update --precise
        let status = Command::new("cargo")
            .args(&[
                "update",
                "--precise",
                parent_version,
                "--package",
                parent_name,
                "--manifest-path",
                &cargo_toml_path.to_string_lossy(),
            ])
            .current_dir(crate_dir)
            .output()
            .await
            .context("执行 cargo update --precise 失败")?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            tracing::warn!(
                "cargo update --precise 执行失败: {}, 命令: {}",
                stderr,
                command_str
            );
            return Err(anyhow::anyhow!(
                "cargo update --precise 执行失败: {}, 命令: {}",
                stderr,
                command_str
            ));
        } else {
            tracing::info!("cargo update --precise 执行成功");
        }
        Ok(original_content)
    }

    /// 在 crate 解压目录下执行 cargo clean，释放 target 空间
    pub async fn cargo_clean(&self) -> Result<()> {
        let extract_dir = self.get_extract_dir_path();
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

#[derive(Debug, Clone)]
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
