//! Auxiliary capture records cannot write the sole authoritative desired document.
use super::{invalid, Store};
use std::io;
use voboost_contract::desired::{Config, Field};
use voboost_contract::runtime_owner::{CapturedIntent, IntentAdmission};

impl Store {
    pub(super) fn prepare_intent(
        &mut self,
        _source: &str,
        _key: &str,
        _record: CapturedIntent,
    ) -> io::Result<IntentAdmission> {
        Err(invalid(
            "captured inputs must use the semantic SaveDesired lane",
        ))
    }

    pub(super) fn finish_intent(
        &mut self,
        _source: &str,
        _key: &str,
        _record: CapturedIntent,
    ) -> io::Result<()> {
        Err(invalid(
            "captured inputs must use the semantic SaveDesired lane",
        ))
    }

    pub(super) fn recover_intent(&mut self, source: &str, key: &str) -> io::Result<bool> {
        if !super::super::native::CODECS
            .iter()
            .any(|codec| codec.id == source && codec.pending_journals.contains(&key))
        {
            return Err(invalid("captured intent source is not declared"));
        }
        if let Some(current) = self.config()? {
            let current = Config::decode(&current)?;
            let field = Field::Option {
                agent: source.into(),
                key: key.into(),
            };
            if current.field_revisions.contains_key(&field.path()) {
                return Ok(false);
            }
        }
        let Some(bytes) = self.journal(source, key)? else {
            return Ok(false);
        };
        let record = CapturedIntent::decode(&bytes).map_err(invalid)?;
        if !record.pending {
            return Ok(false);
        }
        self.revoke_source(source);
        Err(invalid(
            "pending auxiliary capture has no saved user authority",
        ))
    }
}

#[cfg(test)]
#[path = "intent.test.rs"]
mod tests;
