use std::path::PathBuf;

/// controller
#[derive(Debug, Clone)]
pub(crate) struct CrateWorkspaceManager {
    root_crate_workspaces: Vec<CrateWorkspace>,
}

/// crate worspace directory
/// e.g. tokio-workspace
#[derive(Debug, Clone)]
pub(crate) struct CrateWorkspace {
    path: PathBuf,
    name: String,
    version_dirs: Vec<CrateVersionDir>,
    reverse_dependency_workspaces: Vec<CrateWorkspace>,
}

/// crate version directory, which is in the crate workspace directory
/// e.g. tokio-1.0.0
#[derive(Debug, Clone)]
pub(crate) struct CrateVersionDir {
    path: PathBuf,
    name: String,
    version: String,
    is_downloaded: bool,
    is_extracted: bool,
}

impl CrateWorkspaceManager {
    /// create a new crate workspace manager
    pub fn new() -> Self {
        Self {
            root_crate_workspaces: Vec::new(),
        }
    }
}
