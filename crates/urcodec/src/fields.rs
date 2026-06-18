use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    U64(u64),
    I64(i64),
    Register(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FieldBindings {
    values: BTreeMap<&'static str, FieldValue>,
}

impl FieldBindings {
    pub fn insert(&mut self, name: &'static str, value: FieldValue) {
        self.values.insert(name, value);
    }

    pub fn get(&self, name: &'static str) -> Option<&FieldValue> {
        self.values.get(name)
    }
}
