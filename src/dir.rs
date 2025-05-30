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
    name: String,
    index: usize,
}

impl CrateWorkspace {
    /// create a root crate workspace
    /// $WORKING_DIR/cve_id/tokio-workspace
    /// tokio is the crate where the cve is found
    async fn create_root(cve_id: String, name: String) -> Self {
        let path = PathBuf::from(
            &std::env::var("WORKING_DIR").unwrap_or_else(|_| "./downloads/working".to_string()),
        )
        .join(&cve_id)
        .join(format!("{}-workspace", name));
        fs::create_dir_all(&path).await.unwrap();
        Self {
            cve_id,
            path,
            name,
            index: 0,
        }
    }

    /// create a child crate workspace
    /// $WORKING_DIR/tokio-workspace/tokio-1.0.0-workspace
    pub async fn create_child(parent: &CrateWorkspace, name: String, index: usize) -> Self {
        let path = parent.path.join(format!("{}-workspace", name));
        fs::create_dir_all(&path).await.unwrap();
        Self {
            cve_id: parent.cve_id.clone(),
            path,
            name,
            index,
        }
    }
}

/// crate version directory, which is in the crate workspace directory
/// e.g. tokio-workspace/tokio-1.0.0
#[derive(Debug, Clone)]
pub(crate) struct CrateVersionDir {
    path: PathBuf,
    name: String,
    version: String,
}

impl CrateVersionDir {
    pub async fn create(parent: &CrateWorkspace, name: String, version: String) -> Self {
        let path = parent.path.join(format!("{}-{}", name, version));
        fs::create_dir_all(&path).await.unwrap();
        Self {
            path,
            name,
            version,
        }
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
    pub fn new() -> Self {
        Self {
            workspaces: Vec::new(),
            version_dirs: Vec::new(),
        }
    }

    pub async fn create_root(
        &mut self,
        cve_id: &str,
        crate_name: &str,
    ) -> anyhow::Result<CrateWorkspaceIndex> {
        let crate_workspace =
            CrateWorkspace::create_root(cve_id.to_owned(), crate_name.to_owned()).await;
        self.workspaces.push(crate_workspace.clone());
        assert_eq!(self.workspaces.len(), 1);
        Ok(0)
    }

    /// parent is the index of the parent workspace, i.e. dependency of the crate
    /// crate_name is the name of the crate
    /// crate_version is the version of the crate
    /// return the index of the workspace and the version directory
    pub async fn create_krate_working_dir(
        &mut self,
        parent: CrateWorkspaceIndex,
        crate_name: &str,
        crate_version: &str,
    ) -> anyhow::Result<(CrateWorkspaceIndex, CrateVersionDirIndex)> {
        let parent_workspace = self
            .workspaces
            .get(parent)
            .ok_or(anyhow::anyhow!("parent workspace not found"))?;
        let crate_workspace = CrateWorkspace::create_child(
            parent_workspace,
            crate_name.to_string(),
            self.workspaces.len(),
        )
        .await;
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

    pub fn get_krate_working_dir(
        &self,
        version_dir_index: CrateVersionDirIndex,
    ) -> anyhow::Result<PathBuf> {
        let version_dir = self
            .version_dirs
            .get(version_dir_index)
            .ok_or(anyhow::anyhow!("version directory not found"))?;
        Ok(version_dir.path.clone())
    }
}
