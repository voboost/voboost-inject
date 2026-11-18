//! Table tests for the schema-1 native cleanup parser (extracted; targets
//! "Unsuitable in all cases must fail, suitable cases expected" correction).
use super::*;

/// Body of a confirmed result with optional overrides, serialized JSON.
fn confirmed_json(tags: &str, user: &str, updated: bool, status: &str, schema: u32) -> String {
    let tags16: Vec<&str> = vec![tags; 16];
    let _ = tags16; // keep helper minimal; tags itself is already validated form
    let escaped = tags.replace('\\', "\\\\").replace('"', "\\\"");
    let persisted = escaped.clone();
    format!(
        concat!(
            "{{\"schema\":{},\"status\":\"{}\",",
            "\"updateRequested\":{},\"userId\":{},",
            "\"actualLocales\":\"{}\",\"persistedLocales\":\"{}\"}}"
        ),
        schema, status, updated, user, escaped, persisted
    )
}

fn ok(payload: String) -> NoneCleanupObservation {
    parse(payload.as_bytes()).unwrap_or_else(|e| panic!("expected pass: {e}"))
}

fn confirmed(tags: &str, user: &str, updated: bool) -> String {
    confirmed_json(tags, user, updated, "confirmed", 1)
}

fn reject(name: &str, payload: String) {
    assert!(parse(payload.as_bytes()).is_err(), "case {name} must fail");
}

#[test]
fn table_accept() {
    let (o, tags) = (ok(confirmed("en-US", "0", false)), "en-US");
    assert_eq!(o.primary_language(), PrimaryLanguage::English);
    assert_eq!(o.full_tags(), tags);
    assert_eq!(o.user_id(), 0);
    assert!(!o.update_requested());

    let o = ok(confirmed("zh-CN", "42", false));
    assert_eq!(o.primary_language(), PrimaryLanguage::Chinese);
    assert_eq!(o.user_id(), 42);

    // Secondary ru / de after an en or zh first locale are PRESERVED VERBATIM.
    for (lang, tags, updated) in [
        (PrimaryLanguage::English, "en-US,ru-RU", false),
        (PrimaryLanguage::Chinese, "zh-CN,ru-RU", false),
        (PrimaryLanguage::English, "en-US,de-DE", true),
        (PrimaryLanguage::Chinese, "zh", false),
    ] {
        let o = ok(confirmed(tags, "5", updated));
        assert_eq!(o.primary_language(), lang, "{tags}");
        assert_eq!(o.full_tags(), tags);
        assert_eq!(o.update_requested(), updated);
    }

    // 16 locales at the bound: exactly 16 en entries (15 commas, 32 chars).
    let bound = "en,en,en,en,en,en,en,en,en,en,en,en,en,en,en,en";
    assert_eq!(bound.len(), 47); // well under 512; 16 entries
    let o = ok(confirmed(bound, "1", false));
    assert_eq!(o.primary_language(), PrimaryLanguage::English);
    assert_eq!(o.full_tags().matches(',').count(), 15);

    // updateRequested true passthrough.
    let o = ok(confirmed("en", "9", true));
    assert_eq!(o.user_id(), 9);
    assert!(o.update_requested());

    // Trailing newline is the only tolerated whitespace.
    let payload = confirmed("en-US,ru-RU", "0", false);
    assert!(parse(format!("{}\n", payload).as_bytes()).is_ok());
}

#[test]
fn table_reject() {
    for (name, payload) in [
        (
            "trailing log text",
            format!("{}log: done", confirmed("en", "1", false)),
        ),
        (
            "two objects",
            format!(
                "{}{}",
                confirmed("en", "1", false),
                confirmed("zh", "1", false)
            ),
        ),
        (
            "leading log prefix",
            format!("W/log: {}", confirmed("en", "1", false)),
        ),
    ] {
        reject(name, payload);
    }
    for (name, payload) in [
        (
            "schema not 1",
            confirmed_json("en", "1", false, "confirmed", 2),
        ),
        (
            "schema missing",
            String::from(
                "{\"status\":\"confirmed\",\"updateRequested\":false,\"userId\":1,\
                       \"actualLocales\":\"en\",\"persistedLocales\":\"en\"}",
            ),
        ),
        (
            "status observation-timeout",
            confirmed_json("en", "-1", false, "observation-timeout", 1),
        ),
        (
            "status invalid-arguments",
            confirmed_json("en", "-1", false, "invalid-arguments", 1),
        ),
        (
            "status process-timeout",
            confirmed_json("en", "-1", false, "process-timeout", 1),
        ),
        (
            "status capability-or-execution-failed",
            confirmed_json("en", "-1", false, "capability-or-execution-failed", 1),
        ),
        (
            "status unsupported-language",
            confirmed_json("ru", "1", false, "unsupported-language", 1),
        ),
        ("negative userId", confirmed("en", "-1", false)),
        (
            "float userId",
            String::from(
                "{\"schema\":1,\"status\":\"confirmed\",\"updateRequested\":false,\
                       \"userId\":1.5,\"actualLocales\":\"en\",\"persistedLocales\":\"en\"}",
            ),
        ),
        (
            "oversize userId",
            String::from(
                "{\"schema\":1,\"status\":\"confirmed\",\"updateRequested\":false,\
                       \"userId\":4294967296,\"actualLocales\":\"en\",\"persistedLocales\":\"en\"}",
            ),
        ),
        (
            "null locales",
            String::from(
                "{\"schema\":1,\"status\":\"confirmed\",\"updateRequested\":false,\
                       \"userId\":1,\"actualLocales\":null,\"persistedLocales\":null}",
            ),
        ),
        (
            "actual and persisted differ",
            String::from(
                "{\"schema\":1,\"status\":\"confirmed\",\"updateRequested\":false,\
                       \"userId\":1,\"actualLocales\":\"en-US\",\"persistedLocales\":\"en-GB\"}",
            ),
        ),
        ("first locale ru", confirmed("ru-RU,ru-RU", "1", false)),
        (
            "first locale de, secondary en",
            confirmed("de-DE,en-US", "1", false),
        ),
        ("only ru secondary", confirmed("ru,ru", "1", false)),
        (
            "17 locales",
            confirmed(
                "en,en,en,en,en,en,en,en,en,en,en,en,en,en,en,en,en",
                "1",
                false,
            ),
        ),
        ("empty tag list", confirmed("", "1", false)),
        ("underscore", confirmed("en_US", "1", false)),
        ("empty subtag", confirmed("en-", "1", false)),
        ("empty entry", confirmed("en,,ru", "1", false)),
        ("digit primary", confirmed("e1", "1", false)),
        (
            "oversize list",
            confirmed(&"en-xxxxxxxx".repeat(52), "1", false),
        ),
        (
            "unterminated string",
            String::from("{\"schema\":1,\"status\":\"confirmed"),
        ),
        ("trailing comma", String::from("{\"schema\":1,}")),
        ("empty object", String::from("{}")),
    ] {
        reject(name, payload);
    }

    // Duplicate keys fail closed, matching the handwritten vendored parser's
    // reject_duplicate, but natively via serde_json's map visitor.
    reject(
        "duplicate schema",
        String::from(
            "{\"schema\":1,\"schema\":1,\"status\":\"confirmed\",\
                         \"updateRequested\":false,\"userId\":1,\
                         \"actualLocales\":\"en\",\"persistedLocales\":\"en\"}",
        ),
    );

    // Unknown fields fail closed via deny_unknown_fields.
    for extra in ["\"extra\":\"x\"", "\"extra\":null"] {
        reject(
            "unknown field",
            String::from(
                "{\"schema\":1,\"status\":\"confirmed\",\"updateRequested\":false,\
                             \"userId\":1,\"actualLocales\":\"en\",\"persistedLocales\":\"en\",",
            ) + extra
                + "}",
        );
    }

    // Field order is irrelevant: nothing assumed about key order.
    let reordered = String::from(concat!(
        "{\"persistedLocales\":\"en-US,ru-RU\",\"userId\":6,",
        "\"actualLocales\":\"en-US,ru-RU\",\"schema\":1,",
        "\"status\":\"confirmed\",\"updateRequested\":false}"
    ));
    let o = ok(reordered);
    assert_eq!(o.primary_language(), PrimaryLanguage::English);

    // Non-UTF-8 and oversize bytes fail closed.
    assert!(parse(&[0x22u8, 0xff, 0x5b, 0x5d, 0x22]).is_err());
    assert!(parse(&[b'x'; MAXIMUM + 1]).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn parse_process_exit_status_controls() {
    let line = confirmed("en", "1", false);
    assert!(parse_process(true, line.as_bytes()).is_ok());
    assert!(parse_process(false, line.as_bytes()).is_err()); // forced exit-code
    assert!(parse_process(true, b"{}").is_err());
}

#[test]
fn impossible_android_observations_reject() {
    assert!(parse(confirmed("en", "2147483648", false).as_bytes()).is_err());
    assert!(parse(confirmed("zh", "0", true).as_bytes()).is_err());
}

fn failure_line(status: &str) -> String {
    format!(
        r#"{{"schema":1,"status":"{status}","updateRequested":false,"userId":-1,"actualLocales":null,"persistedLocales":null}}"#
    )
}

#[test]
fn failed_process_preserves_only_known_schema_one_failure_status() {
    for status in [
        "invalid-arguments",
        "process-timeout",
        "capability-or-execution-failed",
        "observation-timeout",
        "unsupported-language",
    ] {
        let line = failure_line(status);
        assert_eq!(
            parse_process(false, line.as_bytes()).unwrap_err(),
            format!("none cleanup command failed: {status}")
        );
        assert!(parse_process(true, line.as_bytes()).is_err());
    }
}

#[test]
fn failed_process_never_publishes_untrusted_output_or_confirms() {
    let line = failure_line("observation-timeout");
    for bytes in [
        failure_line("message with private data").into_bytes(),
        failure_line("confirmed").into_bytes(),
        line.replace(r#""schema":1"#, r#""schema":2"#).into_bytes(),
        line.replace(r#""schema":1"#, r#""schema":1,"schema":1"#)
            .into_bytes(),
        line.replace(
            r#""status":"observation-timeout""#,
            r#""status":"observation-timeout","status":"observation-timeout""#,
        )
        .into_bytes(),
        line.replace(
            r#""actualLocales":null"#,
            r#""actualLocales":null,"secret":"private""#,
        )
        .into_bytes(),
        line.replace(r#""actualLocales":null,"#, "").into_bytes(),
        line.replace(r#""persistedLocales":null"#, r#""persistedLocales":12"#)
            .into_bytes(),
        line.replace(r#""userId":-1"#, r#""userId":-2"#)
            .into_bytes(),
        line.replace(r#""userId":-1"#, r#""userId":2147483648"#)
            .into_bytes(),
        line.replace(r#""updateRequested":false"#, r#""updateRequested":"false""#)
            .into_bytes(),
        line.replace(
            r#""actualLocales":null"#,
            r#""actualLocales":"en-US private""#,
        )
        .into_bytes(),
        format!("{line}\nprivate log text").into_bytes(),
        format!("{line}{line}").into_bytes(),
        confirmed("en", "0", false).into_bytes(),
        vec![b' '; MAXIMUM + 1],
        vec![0xff],
        Vec::new(),
    ] {
        assert_eq!(
            parse_process(false, &bytes).unwrap_err(),
            "none cleanup command failed"
        );
    }
}

#[test]
fn english_cleanup_preserves_russian_and_rejects_any_locale_update() {
    for (tags, primary) in [
        ("ru-RU,en-US", PrimaryLanguage::Russian),
        ("en-US", PrimaryLanguage::English),
        ("zh-CN", PrimaryLanguage::Chinese),
    ] {
        let observed = parse_english_process(true, confirmed(tags, "0", false).as_bytes()).unwrap();
        assert_eq!(observed.primary_language(), primary);
        assert_eq!(observed.full_tags(), tags);
        assert!(!observed.update_requested());
        assert!(parse_english_process(true, confirmed(tags, "0", true).as_bytes()).is_err());
    }
    assert!(parse(confirmed("ru-RU", "0", false).as_bytes()).is_err());
    assert!(parse_english_process(false, confirmed("en", "0", false).as_bytes()).is_err());
}
