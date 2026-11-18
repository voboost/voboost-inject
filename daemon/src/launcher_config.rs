//! Launcher-only inventory observation and typed canonical visibility options.
//! Inventory is volatile, endpoint-scoped observation, never a second intent store.

use crate::agent_log::EndpointContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const PROCESS: &str = "com.qinggan.app.launcher";
const MAX_ITEMS: usize = 256;
const MAX_PAGES: usize = 32;
const MAX_PAGE_BYTES: usize = 4096;
const MAX_TOTAL_BYTES: usize = 65536;
const FRESHNESS: Duration = Duration::from_secs(30);

fn valid_density(value: &Value, inherit: bool) -> bool {
    value
        .as_u64()
        .is_some_and(|dpi| matches!(dpi, 160 | 210 | 240 | 300) || (inherit && dpi == 0))
}

pub fn valid_options(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.keys().all(|key| {
        matches!(
            key.as_str(),
            "itemVisibility" | "densityDpi" | "appPreferences"
        )
    }) && object
        .get("itemVisibility")
        .and_then(Value::as_object)
        .is_some_and(|items| {
            items.len() <= MAX_ITEMS
                && items
                    .iter()
                    .all(|(id, value)| valid_identity(id) && value.is_boolean())
        })
        && object
            .get("densityDpi")
            .is_none_or(|value| valid_density(value, false))
        && object.get("appPreferences").is_none_or(|value| {
            value.as_object().is_some_and(|items| {
                items.len() <= MAX_ITEMS
                    && items.iter().all(|(id, value)| {
                        valid_identity(id)
                            && value.as_object().is_some_and(|preference| {
                                preference.len() == 2
                                    && preference
                                        .get("densityDpi")
                                        .is_some_and(|value| valid_density(value, true))
                                    && preference
                                        .get("displayMode")
                                        .and_then(Value::as_str)
                                        .is_some_and(|mode| {
                                            matches!(mode, "fit" | "left-inset" | "fullscreen")
                                        })
                            })
                    })
            })
        })
}

pub fn default_options() -> Value {
    json!({"itemVisibility": {}, "densityDpi":160, "appPreferences":{}})
}

pub fn derived(options: &Value, enabled: bool) -> Value {
    json!({"schemaVersion": 2, "enabled": enabled,
        "itemVisibility": options.get("itemVisibility").cloned().unwrap_or_else(|| json!({})),
        "densityDpi": options.get("densityDpi").cloned().unwrap_or_else(|| json!(160)),
        "appPreferences": options.get("appPreferences").cloned().unwrap_or_else(|| json!({}))})
}

fn valid_original_binding(item: &Item) -> bool {
    match (&item.package_name, item.user_id) {
        (None, None) => true,
        (Some(package), Some(user)) => {
            item.kind == "original"
                && item.identity.starts_with("o.")
                && user <= 21474
                && valid_package(package)
        }
        _ => false,
    }
}

fn valid_package(package: &str) -> bool {
    package.len() <= 255
        && package.contains('.')
        && package.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Only observed original rows from this running generation may bind opaque identities.
pub fn derived_with_original_bindings(
    options: &Value,
    enabled: bool,
    generation: &str,
    catalog: &str,
) -> Value {
    let mut result = derived(options, enabled);
    let bindings = inventory()
        .lock()
        .ok()
        .map(|store| original_bindings(&store, options, generation, catalog))
        .unwrap_or_default();
    result
        .as_object_mut()
        .unwrap()
        .insert("originalBindings".into(), Value::Object(bindings));
    result
}

fn original_bindings(
    store: &Inventory,
    options: &Value,
    generation: &str,
    catalog: &str,
) -> serde_json::Map<String, Value> {
    let mut result = serde_json::Map::new();
    let Some(batch) = store.complete.as_ref().filter(|batch| {
        batch.binding.generation == generation
            && batch.binding.catalog == catalog
            && batch.updated.elapsed() < FRESHNESS
    }) else {
        return result;
    };
    let mut ambiguous = HashSet::new();
    let mut observed = BTreeMap::new();
    for item in batch.data.values().flat_map(|page| &page.items) {
        if !valid_original_binding(item) || item.kind != "original" {
            continue;
        }
        let (Some(package), Some(user)) = (&item.package_name, item.user_id) else {
            continue;
        };
        let key = format!("{user}:{package}");
        if observed
            .insert(key.clone(), item.identity.clone())
            .is_some()
        {
            ambiguous.insert(key);
        }
    }
    for (key, identity) in observed {
        if !ambiguous.contains(&key)
            && options
                .get("appPreferences")
                .and_then(|prefs| prefs.get(&identity))
                .is_some()
        {
            result.insert(key, identity.into());
        }
    }
    result
}

fn valid_identity(id: &str) -> bool {
    (3..=192).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Item {
    identity: String,
    label: String,
    kind: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "packageName"
    )]
    package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userId")]
    user_id: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    schema_version: u32,
    snapshot: String,
    page: usize,
    pages: usize,
    items: Vec<Item>,
}

#[derive(Clone, PartialEq, Eq)]
struct Binding {
    epoch: u64,
    generation: String,
    catalog: String,
    revision: i64,
}
impl Binding {
    fn from_context(ctx: &EndpointContext) -> Option<Self> {
        if !ctx.settings_generation_is_active() || !ctx.owns_agent("launcher") {
            return None;
        }
        Some(Self {
            epoch: ctx.endpoint_epoch,
            generation: ctx.active_generation_id.clone(),
            catalog: ctx.active_catalog_sha256.clone(),
            revision: ctx.document_generation?,
        })
    }
    fn active_for(&self, ctx: &EndpointContext) -> bool {
        ctx.settings_generation_is_active()
            && ctx.owns_agent("launcher")
            && self.generation == ctx.active_generation_id
            && self.catalog == ctx.active_catalog_sha256
    }
}

struct Batch {
    binding: Binding,
    snapshot: String,
    pages: usize,
    data: BTreeMap<usize, Page>,
    updated: Instant,
}
#[derive(Default)]
struct Inventory {
    pending: Option<Batch>,
    complete: Option<Batch>,
}
fn inventory() -> &'static Mutex<Inventory> {
    static STORE: OnceLock<Mutex<Inventory>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Inventory::default()))
}

pub fn reserved(key: &str) -> bool {
    key.starts_with("inventory-")
}

/// Only the actual selected launcher process can publish these reserved keys.
pub fn publish(key: &str, raw: &str, ctx: &EndpointContext) -> bool {
    let Some(binding) = Binding::from_context(ctx) else {
        return false;
    };
    if ctx.process != PROCESS || raw.len() > MAX_PAGE_BYTES {
        return false;
    }
    let Ok(strict) = serde_json::from_str::<crate::strict_json::StrictValue>(raw) else {
        return false;
    };
    let Ok(page) = serde_json::from_value::<Page>(strict.0) else {
        return false;
    };
    if page.schema_version != 1
        || page.pages == 0
        || page.pages > MAX_PAGES
        || page.page >= page.pages
        || key != format!("inventory-{}", page.page)
        || page.snapshot.len() != 64
        || !page
            .snapshot
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || page.items.len() > MAX_ITEMS
        || page.items.iter().any(|item| {
            !valid_identity(&item.identity)
                || item.label.is_empty()
                || item.label.len() > 256
                || item.label.chars().any(char::is_control)
                || !matches!(item.kind.as_str(), "installed" | "original" | "folder")
                || !valid_original_binding(item)
        })
    {
        return false;
    }
    let Ok(mut store) = inventory().lock() else {
        return false;
    };
    accept_page(&mut store, page, binding, Instant::now())
}

fn accept_page(store: &mut Inventory, page: Page, binding: Binding, now: Instant) -> bool {
    let same = |batch: &Batch| {
        batch.binding == binding && batch.snapshot == page.snapshot && batch.pages == page.pages
    };
    // A snapshot is immutable. Repeated pages refresh only an identical complete batch.
    if let Some(batch) = store.complete.as_mut().filter(|batch| same(batch)) {
        if batch.data.get(&page.page) != Some(&page) {
            return false;
        }
        // Require a full refresh batch instead of refreshing all rows by replaying one page.
    }
    if !store
        .pending
        .as_ref()
        .is_some_and(|batch| same(batch) && now.duration_since(batch.updated) < FRESHNESS)
    {
        store.pending = Some(Batch {
            binding,
            snapshot: page.snapshot.clone(),
            pages: page.pages,
            data: BTreeMap::new(),
            updated: now,
        });
    }
    let batch = store.pending.as_mut().unwrap();
    if batch.data.get(&page.page).is_some_and(|old| old != &page) {
        return false;
    }
    batch.data.insert(page.page, page);
    let mut identities = HashSet::new();
    let mut bytes = 0;
    for value in batch.data.values() {
        bytes += serde_json::to_vec(value).map_or(MAX_TOTAL_BYTES + 1, |v| v.len());
        for item in &value.items {
            if !identities.insert(item.identity.as_str()) {
                store.pending = None;
                return false;
            }
        }
    }
    if identities.len() > MAX_ITEMS || bytes > MAX_TOTAL_BYTES {
        store.pending = None;
        return false;
    }
    if batch.data.len() == batch.pages {
        batch.updated = now;
        store.complete = store.pending.take();
    }
    true
}

pub fn read(key: &str, ctx: &EndpointContext) -> Option<Value> {
    let store = inventory().lock().ok()?;
    let batch = store.complete.as_ref()?;
    if !batch.binding.active_for(ctx) || batch.updated.elapsed() >= FRESHNESS {
        return None;
    }
    if key == "inventory-index" {
        return Some(
            json!({"schemaVersion":1,"snapshot":batch.snapshot,"revision":batch.binding.revision,"pages":batch.pages}),
        );
    }
    let page: usize = key.strip_prefix("inventory-")?.parse().ok()?;
    let mut value = serde_json::to_value(batch.data.get(&page)?).ok()?;
    value
        .as_object_mut()?
        .insert("revision".into(), batch.binding.revision.into());
    Some(value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    snapshot: String,
    revision: i64,
    identity: String,
    visible: bool,
}

/// Check the exact complete observed item before modifying the canonical options.
pub fn mutate(options: &mut Value, raw: &str, ctx: &EndpointContext) -> Option<()> {
    if !valid_options(options) || raw.len() > 1024 || ctx.process != "com.qinggan.app.setting" {
        return None;
    }
    let strict: crate::strict_json::StrictValue = serde_json::from_str(raw).ok()?;
    let mutation: Mutation = serde_json::from_value(strict.0).ok()?;
    let store = inventory().lock().ok()?;
    let batch = store.complete.as_ref()?;
    if !batch.binding.active_for(ctx)
        || batch.updated.elapsed() >= FRESHNESS
        || batch.snapshot != mutation.snapshot
        || batch.binding.revision != mutation.revision
        || !batch
            .data
            .values()
            .flat_map(|page| &page.items)
            .any(|item| item.identity == mutation.identity)
    {
        return None;
    }
    let items = options.get_mut("itemVisibility")?.as_object_mut()?;
    if !items.contains_key(&mutation.identity) && items.len() >= MAX_ITEMS {
        return None;
    }
    items.insert(mutation.identity, Value::Bool(mutation.visible));
    Some(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SectionMutation {
    snapshot: String,
    revision: i64,
    kind: String,
    visible: bool,
}

/// One canonical transaction changes every observed item in the selected section.
pub fn mutate_section(options: &mut Value, raw: &str, ctx: &EndpointContext) -> Option<()> {
    if !valid_options(options) || raw.len() > 1024 || ctx.process != "com.qinggan.app.setting" {
        return None;
    }
    let strict: crate::strict_json::StrictValue = serde_json::from_str(raw).ok()?;
    let mutation: SectionMutation = serde_json::from_value(strict.0).ok()?;
    if !matches!(mutation.kind.as_str(), "installed" | "original") {
        return None;
    }
    let store = inventory().lock().ok()?;
    let batch = store.complete.as_ref()?;
    if !batch.binding.active_for(ctx)
        || batch.updated.elapsed() >= FRESHNESS
        || batch.snapshot != mutation.snapshot
        || batch.binding.revision != mutation.revision
    {
        return None;
    }
    let mut items = options.get("itemVisibility")?.as_object()?.clone();
    for item in batch.data.values().flat_map(|page| &page.items) {
        if (item.kind == "installed") == (mutation.kind == "installed") {
            items.insert(item.identity.clone(), Value::Bool(mutation.visible));
        }
    }
    if items.len() > MAX_ITEMS {
        return None;
    }
    *options.get_mut("itemVisibility")? = Value::Object(items);
    Some(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreferenceMutation {
    snapshot: String,
    revision: i64,
    identity: String,
    density_dpi: u32,
    display_mode: String,
}

pub fn mutate_preference(options: &mut Value, raw: &str, ctx: &EndpointContext) -> Option<()> {
    if !valid_options(options) || raw.len() > 1024 || ctx.process != "com.qinggan.app.setting" {
        return None;
    }
    let strict: crate::strict_json::StrictValue = serde_json::from_str(raw).ok()?;
    let mutation: PreferenceMutation = serde_json::from_value(strict.0).ok()?;
    if !valid_density(&json!(mutation.density_dpi), true)
        || !matches!(
            mutation.display_mode.as_str(),
            "fit" | "left-inset" | "fullscreen"
        )
    {
        return None;
    }
    let store = inventory().lock().ok()?;
    let batch = store.complete.as_ref()?;
    if !batch.binding.active_for(ctx)
        || batch.updated.elapsed() >= FRESHNESS
        || batch.snapshot != mutation.snapshot
        || batch.binding.revision != mutation.revision
        || !batch
            .data
            .values()
            .flat_map(|page| &page.items)
            .any(|item| item.identity == mutation.identity && item.kind != "folder")
    {
        return None;
    }
    let mut preferences = options
        .get("appPreferences")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if !preferences.contains_key(&mutation.identity) && preferences.len() >= MAX_ITEMS {
        return None;
    }
    preferences.insert(
        mutation.identity,
        json!({"densityDpi":mutation.density_dpi,"displayMode":mutation.display_mode}),
    );
    options
        .as_object_mut()?
        .insert("appPreferences".into(), Value::Object(preferences));
    Some(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSection {
    snapshot: String,
    revision: i64,
    kind: String,
    visible: bool,
    identities: Vec<String>,
}

/// User intent is durable independently of volatile inventory and apply readiness.
/// Section membership is the exact bounded list rendered for this user action.
pub fn desired_changes(
    kind: &str,
    key: &str,
    raw: &str,
    ctx: &EndpointContext,
) -> Option<Vec<(voboost_contract::desired::Field, Value)>> {
    use voboost_contract::desired::Field;
    if ctx.process != "com.qinggan.app.setting" || raw.len() > 57344 {
        return None;
    }
    if (kind, key) == ("launcher-density", "density") {
        return matches!(raw, "160" | "210" | "240" | "300").then(|| {
            vec![(
                Field::Option {
                    agent: "launcher".into(),
                    key: "densityDpi".into(),
                },
                raw.parse::<u32>().unwrap().into(),
            )]
        });
    }
    let strict: crate::strict_json::StrictValue = serde_json::from_str(raw).ok()?;
    match (kind, key) {
        ("launcher-item-visibility", "item") => {
            let mutation: Mutation = serde_json::from_value(strict.0).ok()?;
            valid_identity(&mutation.identity).then(|| {
                vec![(
                    Field::LauncherItemVisibility {
                        identity: mutation.identity,
                    },
                    mutation.visible.into(),
                )]
            })
        }
        ("launcher-section-visibility", "section") => {
            let mutation: DesiredSection = serde_json::from_value(strict.0).ok()?;
            if mutation.snapshot.len() > 192
                || mutation.revision < 0
                || !matches!(mutation.kind.as_str(), "installed" | "original")
                || mutation.identities.is_empty()
                || mutation.identities.len() > MAX_ITEMS
            {
                return None;
            }
            let mut unique = HashSet::new();
            let mut changes = Vec::new();
            for identity in mutation.identities {
                if !valid_identity(&identity) || !unique.insert(identity.clone()) {
                    return None;
                }
                changes.push((
                    Field::LauncherItemVisibility { identity },
                    mutation.visible.into(),
                ));
            }
            Some(changes)
        }
        ("launcher-app-preference", "preference") => {
            let mut value = strict.0;
            let key = value.as_object_mut()?.remove("key")?.as_str()?.to_string();
            let mutation: PreferenceMutation = serde_json::from_value(value).ok()?;
            if !valid_identity(&mutation.identity)
                || !valid_density(&json!(mutation.density_dpi), true)
                || !matches!(
                    mutation.display_mode.as_str(),
                    "fit" | "left-inset" | "fullscreen"
                )
            {
                return None;
            }
            let value = match key.as_str() {
                "densityDpi" => mutation.density_dpi.into(),
                "displayMode" => mutation.display_mode.into(),
                _ => return None,
            };
            Some(vec![(
                Field::LauncherAppPreference {
                    identity: mutation.identity,
                    key,
                },
                value,
            )])
        }
        _ => None,
    }
}

pub fn forget_endpoint(epoch: u64) {
    if let Ok(mut store) = inventory().lock() {
        if store
            .pending
            .as_ref()
            .is_some_and(|batch| batch.binding.epoch == epoch)
        {
            store.pending = None;
        }
        if store
            .complete
            .as_ref()
            .is_some_and(|batch| batch.binding.epoch == epoch)
        {
            store.complete = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            epoch: 1,
            generation: "g".into(),
            catalog: "c".into(),
            revision: 4,
        }
    }
    fn page(index: usize, id: &str) -> Page {
        Page {
            schema_version: 1,
            snapshot: "a".repeat(64),
            page: index,
            pages: 2,
            items: vec![Item {
                identity: id.into(),
                label: "App".into(),
                kind: "installed".into(),
                package_name: None,
                user_id: None,
            }],
        }
    }
    #[test]
    fn original_projection_requires_fresh_generation_explicit_preference_and_unique_package() {
        let id = format!("o.{}", "a".repeat(64));
        let mut row = page(0, &id);
        row.pages = 1;
        row.items[0].kind = "original".into();
        row.items[0].package_name = Some("com.example.original".into());
        row.items[0].user_id = Some(0);
        let options =
            json!({"appPreferences":{id.clone():{"densityDpi":210,"displayMode":"fullscreen"}}});
        let mut store = Inventory::default();
        assert!(accept_page(
            &mut store,
            row.clone(),
            binding(),
            Instant::now()
        ));
        assert_eq!(
            original_bindings(&store, &options, "g", "c")["0:com.example.original"],
            id
        );
        assert!(original_bindings(&store, &options, "other", "c").is_empty());
        assert!(original_bindings(&store, &options, "g", "other").is_empty());
        assert!(original_bindings(&store, &json!({}), "g", "c").is_empty());
        store.complete.as_mut().unwrap().updated = Instant::now() - FRESHNESS;
        assert!(original_bindings(&store, &options, "g", "c").is_empty());
        let mut second = row.items[0].clone();
        second.identity = format!("o.{}", "b".repeat(64));
        row.items.push(second);
        store = Inventory::default();
        assert!(accept_page(&mut store, row, binding(), Instant::now()));
        assert!(original_bindings(&store, &options, "g", "c").is_empty());
    }

    #[test]
    fn original_binding_rejects_folder_partial_and_invalid_package() {
        let mut row = page(0, "o.a").items.remove(0);
        row.kind = "folder".into();
        row.package_name = Some("com.example.app".into());
        row.user_id = Some(0);
        assert!(!valid_original_binding(&row));
        row.kind = "original".into();
        assert!(valid_original_binding(&row));
        row.user_id = None;
        assert!(!valid_original_binding(&row));
        row.user_id = Some(0);
        row.package_name = Some("../bad".into());
        assert!(!valid_original_binding(&row));
    }

    #[test]
    fn incomplete_inventory_retains_previous_complete_and_rejects_duplicates() {
        let mut store = Inventory::default();
        let now = Instant::now();
        assert!(accept_page(&mut store, page(0, "i.a"), binding(), now));
        assert!(store.complete.is_none());
        assert!(!accept_page(&mut store, page(1, "i.a"), binding(), now));
        assert!(store.pending.is_none());
        assert!(accept_page(&mut store, page(0, "i.a"), binding(), now));
        assert!(accept_page(&mut store, page(1, "i.b"), binding(), now));
        assert!(store.complete.is_some());
        let mut changed = page(0, "i.c");
        changed.snapshot = "b".repeat(64);
        assert!(accept_page(&mut store, changed, binding(), now));
        assert_eq!(store.complete.unwrap().snapshot, "a".repeat(64));
    }
    #[test]
    fn snapshot_immutable_and_endpoint_revision_isolated() {
        let mut store = Inventory::default();
        let now = Instant::now();
        assert!(accept_page(&mut store, page(0, "i.a"), binding(), now));
        assert!(accept_page(&mut store, page(1, "i.b"), binding(), now));
        assert!(!accept_page(&mut store, page(0, "i.c"), binding(), now));
        let mut next = binding();
        next.revision = 5;
        assert!(accept_page(&mut store, page(0, "i.c"), next, now));
        assert_eq!(store.complete.unwrap().binding.revision, 4);
    }
    #[test]
    fn published_inventory_fences_visibility_and_dead_endpoint() {
        let mut ctx = EndpointContext {
            process: PROCESS.into(),
            endpoint_epoch: 909,
            document_generation: Some(7),
            resident_generation_id: "generation".into(),
            active_generation_id: "generation".into(),
            resident_catalog_sha256: "catalog".into(),
            active_catalog_sha256: "catalog".into(),
            resident_agents: ["launcher".into()].into_iter().collect(),
            ..EndpointContext::default()
        };
        let mut value = page(0, "i.test");
        value.items.push(Item {
            identity: "o.stock".into(),
            label: "Stock".into(),
            kind: "original".into(),
            package_name: None,
            user_id: None,
        });
        value.items.push(Item {
            identity: "o.folder".into(),
            label: "Folder".into(),
            kind: "folder".into(),
            package_name: None,
            user_id: None,
        });
        value.pages = 1;
        let raw = serde_json::to_string(&value).unwrap();
        let mut spoof = ctx.clone();
        spoof.process = "com.qinggan.app.setting".into();
        assert!(!publish("inventory-0", &raw, &spoof));
        assert!(publish("inventory-0", &raw, &ctx));
        ctx.process = "com.qinggan.app.setting".into();
        ctx.document_generation = Some(999);
        assert_eq!(read("inventory-index", &ctx).unwrap()["revision"], 7);
        let mutation =
            json!({"snapshot":"a".repeat(64),"revision":7,"identity":"i.test","visible":false});
        let mut options = default_options();
        assert_eq!(mutate(&mut options, &mutation.to_string(), &ctx), Some(()));
        assert_eq!(options["itemVisibility"]["i.test"], false);
        let changes = desired_changes(
            "launcher-item-visibility",
            "item",
            &mutation.to_string(),
            &ctx,
        )
        .unwrap();
        assert_eq!(
            changes,
            vec![(
                voboost_contract::desired::Field::LauncherItemVisibility {
                    identity: "i.test".into()
                },
                false.into()
            )]
        );
        let section_patch = json!({"snapshot":"a".repeat(64),"revision":7,"kind":"original","visible":false,"identities":["o.stock","o.folder"]});
        let changes = desired_changes(
            "launcher-section-visibility",
            "section",
            &section_patch.to_string(),
            &ctx,
        )
        .unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|(field, value)| matches!(field,
            voboost_contract::desired::Field::LauncherItemVisibility { identity } if identity.starts_with("o.")) && value == false));
        let preference_patch = json!({"snapshot":"a".repeat(64),"revision":7,"identity":"i.test","densityDpi":240,"displayMode":"fullscreen","key":"densityDpi"});
        let changes = desired_changes(
            "launcher-app-preference",
            "preference",
            &preference_patch.to_string(),
            &ctx,
        )
        .unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes.iter().all(|(field, _)| matches!(field,
            voboost_contract::desired::Field::LauncherAppPreference { identity, .. } if identity == "i.test")));

        let mut stale = mutation.clone();
        stale["revision"] = 8.into();
        assert!(mutate(&mut options, &stale.to_string(), &ctx).is_none());
        stale = mutation.clone();
        stale["identity"] = "i.unknown".into();
        assert!(mutate(&mut options, &stale.to_string(), &ctx).is_none());
        let mut stale_ctx = ctx.clone();
        stale_ctx.active_catalog_sha256 = "new".into();
        assert!(read("inventory-index", &stale_ctx).is_none());
        // Apply-side inventory validation remains separate from desired owner admission.
        let mut section =
            json!({"snapshot":"a".repeat(64),"revision":7,"kind":"original","visible":false});
        assert_eq!(
            mutate_section(&mut options, &section.to_string(), &ctx),
            Some(())
        );
        for id in ["i.test", "o.stock", "o.folder"] {
            assert_eq!(options["itemVisibility"][id], false);
        }
        section["visible"] = true.into();
        assert_eq!(
            mutate_section(&mut options, &section.to_string(), &ctx),
            Some(())
        );
        assert_eq!(options["itemVisibility"]["i.test"], false);
        assert_eq!(options["itemVisibility"]["o.stock"], true);
        assert_eq!(options["itemVisibility"]["o.folder"], true);
        let before = options.clone();
        section["kind"] = "foreign".into();
        assert!(mutate_section(&mut options, &section.to_string(), &ctx).is_none());
        assert_eq!(options, before);
        assert_eq!(
            desired_changes("launcher-density", "density", "210", &ctx),
            Some(vec![(
                voboost_contract::desired::Field::Option {
                    agent: "launcher".into(),
                    key: "densityDpi".into()
                },
                210.into()
            )])
        );
        assert!(desired_changes("launcher-density", "density", "211", &ctx).is_none());
        let mut preference = json!({"snapshot":"a".repeat(64),"revision":7,"identity":"i.test","densityDpi":300,"displayMode":"fullscreen"});
        assert_eq!(
            mutate_preference(&mut options, &preference.to_string(), &ctx),
            Some(())
        );
        assert_eq!(options["appPreferences"]["i.test"]["densityDpi"], 300);
        assert_eq!(
            options["appPreferences"]["i.test"]["displayMode"],
            "fullscreen"
        );
        let before = options.clone();
        preference["identity"] = "i.unknown".into();
        assert!(mutate_preference(&mut options, &preference.to_string(), &ctx).is_none());
        assert_eq!(options, before);
        crate::agent_events::forget_endpoint(909);
        assert!(read("inventory-index", &ctx).is_none());
        assert!(mutate(&mut options, &mutation.to_string(), &ctx).is_none());
    }

    #[test]
    fn application_scale_options_are_bounded_and_inherit_global_density() {
        assert!(valid_options(
            &json!({"itemVisibility":{},"densityDpi":210,"appPreferences":{"i.app":{"densityDpi":0,"displayMode":"fit"}}})
        ));
        assert!(!valid_options(
            &json!({"itemVisibility":{},"densityDpi":211})
        ));
        assert!(!valid_options(
            &json!({"itemVisibility":{},"appPreferences":{"../app":{"densityDpi":160,"displayMode":"fit"}}})
        ));
        assert!(!valid_options(
            &json!({"itemVisibility":{},"appPreferences":{"i.app":{"densityDpi":240,"displayMode":"arbitrary"}}})
        ));
        assert_eq!(
            derived(&json!({"itemVisibility":{}}), true)["densityDpi"],
            160
        );
    }

    #[test]
    fn typed_options_reject_fake_enum_and_path_identity() {
        assert!(valid_options(&default_options()));
        assert!(valid_options(&json!({"itemVisibility":{"i.abc":false}})));
        assert!(!valid_options(&json!({"itemVisibility":{"../app":false}})));
        assert!(!valid_options(&json!({"itemVisibility":{"i.abc":"false"}})));
        assert!(!valid_options(&json!({"itemVisibility":{},"extra":true})));
    }
}
