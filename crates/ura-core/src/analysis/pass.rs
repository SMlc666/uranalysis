use crate::model::PassId;

#[derive(Debug, Clone)]
pub struct PassSpec {
    pub id: PassId,
    pub deps: &'static [PassId],
}

pub const PASS_SPECS: &[PassSpec] = &[
    PassSpec {
        id: PassId::Decode,
        deps: &[],
    },
    PassSpec {
        id: PassId::Strings,
        deps: &[],
    },
    PassSpec {
        id: PassId::Cfg,
        deps: &[PassId::Decode],
    },
    PassSpec {
        id: PassId::Functions,
        deps: &[PassId::Decode, PassId::Cfg],
    },
    PassSpec {
        id: PassId::Xrefs,
        deps: &[PassId::Decode, PassId::Strings, PassId::Cfg],
    },
    PassSpec {
        id: PassId::Diagnostics,
        deps: &[PassId::Decode, PassId::Cfg, PassId::Functions],
    },
];
