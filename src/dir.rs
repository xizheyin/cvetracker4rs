use std::path::PathBuf;

use tokio::fs;

pub(crate) type CrateWorkspaceIndex = usize;
pub(crate) type CrateVersionDirIndex = usize;

/// crate worspace directory
/// e.g. tokio-workspace
#[derive(Debug, Clone)]
pub(crate) struct CrateWorkspace {
    cve_id: String,
    path: PathBuf,
}

impl CrateWorkspace {
    /// create a child crate workspace from a parent version directory
    /// $WORKING_DIR/X-workspace/X-1.0.0/Y-workspace
    pub async fn create_from_parent(parent: &CrateVersionDir, name: String) -> Self {
        let path = parent.path.join(format!("{}-workspace", name));
        fs::create_dir_all(&path).await.unwrap();
        Self {
            cve_id: parent.cve_id.clone(),
            path,
        }
    }
}

/// crate version directory, which is in the crate workspace directory
/// e.g. tokio-workspace/tokio-1.0.0
#[derive(Debug, Clone)]
pub(crate) struct CrateVersionDir {
    cve_id: String,
    path: PathBuf,
    // name: String,
    // version: String,
}

impl CrateVersionDir {
    pub async fn root(cve_id: &str) -> Self {
        let path = PathBuf::from(
            &std::env::var("WORKING_DIR").unwrap_or_else(|_| "./downloads/working".to_string()),
        )
        .join(cve_id);
        fs::create_dir_all(&path).await.unwrap();
        Self {
            cve_id: cve_id.to_owned(),
            path,
        }
    }

    pub async fn create(me: &CrateWorkspace, name: String, version: String) -> Self {
        let path = me.path.join(format!("{}-{}", name, version));
        fs::create_dir_all(&path).await.unwrap();
        Self {
            cve_id: me.cve_id.clone(),
            path,
        }
    }

    pub async fn get_working_dir(&self) -> PathBuf {
        self.path.clone()
    }
}

/// controller
#[derive(Debug, Clone)]
pub(crate) struct CrateWorkspaceFileSystemManager {
    workspaces: Vec<CrateWorkspace>,
    version_dirs: Vec<CrateVersionDir>,
}

impl CrateWorkspaceFileSystemManager {
    /// create a new crate workspace file system manager
    pub async fn new(cve_id: &str) -> anyhow::Result<Self> {
        let workspaces = Vec::new();
        let mut version_dirs = Vec::new();

        let pseudo_root_version_dir = CrateVersionDir::root(cve_id).await;
        version_dirs.push(pseudo_root_version_dir);

        assert_eq!(version_dirs.len(), 1);

        Ok(Self {
            workspaces,
            version_dirs,
        })
    }

    /// parent is the index of the parent workspace, i.e. dependency of the crate
    /// crate_name is the name of the crate
    /// crate_version is the version of the crate
    /// return the index of the workspace and the version directory
    pub async fn create_krate_working_dir(
        &mut self,
        parent: CrateVersionDirIndex,
        crate_name: &str,
        crate_version: &str,
    ) -> anyhow::Result<(CrateWorkspaceIndex, CrateVersionDirIndex)> {
        let parent_version_dir = self
            .version_dirs
            .get(parent)
            .ok_or(anyhow::anyhow!("parent workspace not found"))?;

        let crate_workspace =
            CrateWorkspace::create_from_parent(parent_version_dir, crate_name.to_string()).await;
        self.workspaces.push(crate_workspace.clone());

        let version_dir = CrateVersionDir::create(
            &crate_workspace,
            crate_name.to_string(),
            crate_version.to_string(),
        )
        .await;
        self.version_dirs.push(version_dir.clone());
        Ok((self.workspaces.len() - 1, self.version_dirs.len() - 1))
    }

    pub async fn get_krate_working_dir(&self, version_dir_index: CrateVersionDirIndex) -> PathBuf {
        let version_dir = self
            .version_dirs
            .get(version_dir_index)
            .expect("version directory not found");
        version_dir.get_working_dir().await
    }
}
