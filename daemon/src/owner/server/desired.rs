//! Persistence and revocation for the sole authoritative desired document.
use super::{invalid, Directory, Outcome, Store};
use serde_json::Value;
use std::io;
pub(super) use voboost_contract::desired::Config;
use voboost_contract::desired::{Disposition, Field, Input};

impl Store {
    pub(super) fn save_startup_recovery(&mut self, input: &Input) -> io::Result<Outcome> {
        // This is the narrow hidden-mode gesture, not an ordinary next-boot radio.
        if !matches!(
            self.running_startup.as_deref(),
            Some("hidden" | "interface")
        ) {
            return Err(invalid("startup recovery is not available in this session"));
        }
        let reply =
            self.save_desired(&Field::Startup, &Value::String("interface".into()), input)?;
        if let Outcome::DesiredSaved { disposition, .. } = &reply {
            if *disposition != Disposition::Superseded {
                let session = serde_json::json!({"schemaVersion":1,"bootId":input.boot_id,"startup":"interface"});
                let apply = (|| -> io::Result<()> {
                    let run = Directory::open(&self.root)?
                        .open_or_create_child_with_mode("run", 0o755)?;
                    run.write_atomic(
                        "startup-session.json",
                        &serde_json::to_vec(&session).map_err(io::Error::other)?,
                        0o600,
                    )
                })();
                if apply.is_ok() {
                    self.running_startup = Some("interface".into());
                    let _ = self.refresh_native();
                } else {
                    // Saved is durable desired state; a failed application is not a failed save.
                    eprintln!("startup recovery projection failed after desired was saved");
                }
            }
        }
        Ok(reply)
    }
    pub(super) fn save_launcher_desired(
        &mut self,
        changes: Vec<(Field, Value)>,
        input: &Input,
    ) -> io::Result<Outcome> {
        let boot = self
            .native_boot
            .clone()
            .ok_or_else(|| invalid("desired boot unavailable"))?;
        let current = self
            .config()?
            .ok_or_else(|| invalid("desired configuration unavailable"))?;
        let mut config = Config::decode(&current)?;
        let disposition = config.save_launcher(&boot, changes, input)?;
        let bytes = serde_json::to_vec(&config).map_err(io::Error::other)?;
        Directory::open(&self.root)?.write_atomic("agents.json", &bytes, 0o600)?;
        if disposition == Disposition::Saved {
            let _ = self.refresh_native();
        }
        Ok(Outcome::DesiredSaved {
            revision: config.user_revision,
            config: String::from_utf8(bytes).map_err(io::Error::other)?,
            disposition,
        })
    }
    pub(super) fn read_desired(&self, field: &Field) -> io::Result<Outcome> {
        if !field.valid() {
            return Err(invalid("invalid desired field"));
        }
        let directory = Directory::open(&self.root)?;
        let (bytes, file) = directory.read_trusted_retained(
            "agents.json",
            voboost_contract::runtime_owner::MAX_CONFIG_BYTES,
            0o600,
        )?;
        let config = Config::decode(&bytes)?;
        if config.value_at(&field.path()).is_none() {
            return Err(invalid("desired field unavailable"));
        }
        // A read receipt after a lost/uncertain write establishes durability,
        // rather than claiming that readable renamed bytes were already durable.
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Outcome::DesiredSaved {
            revision: config.user_revision,
            config: String::from_utf8(bytes).map_err(io::Error::other)?,
            disposition: Disposition::Replayed,
        })
    }
    pub(super) fn reconcile_desired(&mut self, defaults: &[u8]) -> io::Result<Outcome> {
        self.reconcile_desired_with(defaults, |_| Ok(()))
    }

    fn reconcile_desired_with<F>(
        &mut self,
        defaults: &[u8],
        before_commit: F,
    ) -> io::Result<Outcome>
    where
        F: FnOnce(&mut Self) -> io::Result<()>,
    {
        let observed = self.config()?;
        let previous = observed.as_deref().map(Config::decode).transpose()?;
        let bytes = match &previous {
            Some(current) => current.reconcile(defaults)?,
            None => Config::initial(defaults)?,
        };
        let next = Config::decode(&bytes)?;
        next.verify_defaults(defaults)?;
        if previous
            .as_ref()
            .is_some_and(|previous| !next.preserves_user_authority(previous))
        {
            return Err(invalid("product reconciliation changed user authority"));
        }
        before_commit(self)?;
        // The owner serializes trusted writers. Retain the snapshot CAS at
        // the storage boundary as well, so an unexpected write cannot be lost.
        if self.config()? != observed {
            return Ok(Outcome::Conflict {});
        }
        Directory::open(&self.root)?.write_atomic("agents.json", &bytes, 0o600)?;
        let _ = self.refresh_native();
        Ok(Outcome::DesiredReconciled {
            revision: next.user_revision,
            config: String::from_utf8(bytes).map_err(io::Error::other)?,
        })
    }
    pub(super) fn save_desired(
        &mut self,
        field: &Field,
        value: &Value,
        input: &Input,
    ) -> io::Result<Outcome> {
        self.save_desired_with(field, value, input, |directory, bytes| {
            directory.write_atomic("agents.json", bytes, 0o600)
        })
    }

    pub(super) fn save_desired_with<F>(
        &mut self,
        field: &Field,
        value: &Value,
        input: &Input,
        persist: F,
    ) -> io::Result<Outcome>
    where
        F: FnOnce(&Directory, &[u8]) -> io::Result<()>,
    {
        let boot = self
            .native_boot
            .clone()
            .ok_or_else(|| invalid("desired boot unavailable"))?;
        if !input.bound() || input.boot_id != boot || !field.accepts(value) {
            return Err(invalid("invalid desired input authority"));
        }
        let is_off = matches!(field, Field::Enabled { .. }) && value == false
            || matches!(field, Field::Option { key, .. } if key == "intent") && value == "off";
        let current = self.config().and_then(|bytes| {
            Config::decode(&bytes.ok_or_else(|| invalid("desired configuration unavailable"))?)
        });
        let mut config = match current {
            Ok(config) => config,
            Err(error) => {
                if is_off {
                    self.fence_desired_off(field);
                }
                return Err(error);
            }
        };
        let initial = config.classify(field, value, input)?;
        if initial != Disposition::Saved {
            // Readable renamed bytes can follow a failed directory fsync for
            // either ON or OFF. Every saved/replayed response needs a barrier.
            let directory = Directory::open(&self.root)?;
            persist(
                &directory,
                &serde_json::to_vec(&config).map_err(io::Error::other)?,
            )?;
            if initial == Disposition::Replayed && is_off {
                self.desired_off_fences.remove(&field.path());
            }
            return Ok(Outcome::DesiredSaved {
                revision: config.user_revision,
                config: String::from_utf8(serde_json::to_vec(&config).map_err(io::Error::other)?)
                    .map_err(io::Error::other)?,
                disposition: initial,
            });
        }
        // Fresh, authenticated OFF is a denial even when bounded storage,
        // serialization, revision allocation or fsync subsequently fails.
        if is_off {
            self.fence_desired_off(field);
        }
        let (dependencies, catalog_unavailable) = match field {
            Field::Enabled { agent } if value == true => match self.desired_dependencies(agent) {
                Ok(dependencies) => (dependencies, false),
                Err(_) => (Vec::new(), true),
            },
            _ => (Vec::new(), false),
        };
        let disposition = config.save(&boot, field, value, input, &dependencies)?;
        let bytes = serde_json::to_vec(&config).map_err(io::Error::other)?;
        if disposition == Disposition::Saved {
            for source in &dependencies {
                self.fence_desired_off(&Field::Enabled {
                    agent: source.clone(),
                });
            }
            let directory = Directory::open(&self.root)?;
            persist(&directory, &bytes)?;
            if let Field::Enabled { agent } = field {
                if catalog_unavailable {
                    self.desired_catalog_fences.insert(agent.clone());
                    self.revoke_source(agent);
                } else {
                    self.desired_catalog_fences.remove(agent);
                }
                // UI teardown is acknowledged separately. Saved OFF already
                // revoked automation and cancelled commands before this refresh.
                if value == true {
                    self.withdrawing.remove(agent);
                } else {
                    self.begin_withdrawal(agent);
                }
            }
            for source in &dependencies {
                self.begin_withdrawal(source);
            }
            // Only a newly committed action can replace a volatile failure fence.
            // A replay of an older ON cannot grant authority after a failed OFF.
            self.desired_off_fences.remove(&field.path());
            for source in &dependencies {
                self.desired_off_fences.remove(
                    &Field::Enabled {
                        agent: source.clone(),
                    }
                    .path(),
                );
            }
            // Saved means fsync completed; effective application has its own result.
            let _ = self.refresh_native();
        }
        Ok(Outcome::DesiredSaved {
            revision: config.user_revision,
            config: String::from_utf8(bytes).map_err(io::Error::other)?,
            disposition,
        })
    }

    fn fence_desired_off(&mut self, field: &Field) {
        if let Field::Enabled { agent } | Field::Option { agent, .. } = field {
            self.desired_off_fences.insert(field.path());
            self.revoke_source(agent);
            self.cancel_source_commands(agent);
        }
    }

    pub(super) fn apply_desired_off_fences(&mut self) {
        for source in &self.desired_catalog_fences {
            self.native_enabled.remove(source);
        }
        for path in &self.desired_off_fences {
            if let Some(source) = path
                .strip_prefix("agents/")
                .and_then(|path| path.split('/').next())
            {
                self.native_enabled.remove(source);
            }
        }
    }
}

#[cfg(test)]
#[path = "desired.test.rs"]
mod tests;
