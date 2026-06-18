use crate::model::Architecture;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormId {
    architecture: Architecture,
    local_name: &'static str,
}

impl FormId {
    pub const fn new(architecture: Architecture, local_name: &'static str) -> Self {
        Self {
            architecture,
            local_name,
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn local_name(&self) -> &'static str {
        self.local_name
    }

    pub fn name(&self) -> String {
        let arch = match self.architecture {
            Architecture::Aarch64 => "aarch64",
            Architecture::X86_64 => "x86_64",
        };
        format!("{arch}.{}", self.local_name)
    }
}
