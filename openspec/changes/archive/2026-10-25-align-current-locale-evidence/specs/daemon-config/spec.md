## REMOVED Requirements

### Requirement: UI language includes canonical simplified Chinese

**Reason**: Current follow-system design has no independent Settings language override; accepting a language mutation contradicts the closed canonical document.
**Migration**: Existing language-bearing canonical documents are rejected; the runtime's system locale owns UI language.

## MODIFIED Requirements

### Requirement: Canonical intent has no separate interface language

The canonical root document SHALL contain only schemaVersion, startup and agents. It SHALL reject language and other unknown root fields. Settings projections SHALL omit language, and the daemon SHALL reject voboost-language radio mutations.

#### Scenario: A canonical document retains a former language override

- **WHEN** an otherwise valid document contains language
- **THEN** validation rejects it without interpreting a language preference

#### Scenario: A Settings endpoint requests a former language mutation

- **WHEN** owned or foreign Settings events request a former language radio value
- **THEN** the daemon rejects the mutation and retains the canonical document unchanged

# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::canonical_intent_follows_system_language_without_an_override -- --exact

Gate contract: Closed canonical intent shape.
Maps: Requirement `Canonical intent has no separate interface language`; Scenario `A canonical document retains a former language override`.
Preconditions: Production canonical parser receives the new shape and a former language field.
Observable result: The new document is valid and both language and unknown fields fail closed.
Evidence boundary: Host canonical parsing; actual Android locale is not observed by the daemon.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::language_mutations_are_rejected_without_changing_canonical_intent -- --exact

Gate contract: Former Settings language mutations are rejected.
Maps: Requirement `Canonical intent has no separate interface language`; Scenario `A Settings endpoint requests a former language mutation`.
Preconditions: An owned Settings context, canonical plan and attempted canonical, alias and foreign language radio events.
Observable result: Every attempted language mutation returns no action and preserves the exact plan bytes.
Evidence boundary: Host event parser and plan write boundary; actual Android follow-system UI and reboot behavior require runtime evidence.

# Unverified: Follow-system Settings projection



