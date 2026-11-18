//! Duplicate-aware bounded JSON value used for app-owned opaque config.

use std::collections::HashSet;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};

#[derive(Debug, Clone)]
pub struct StrictValue(pub Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("duplicate-free JSON")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(value.to_string())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    let value = map.next_value::<StrictValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ValueLimits {
    pub max_depth: usize,
    pub max_total_nodes: usize,
    pub max_object_properties: usize,
    pub max_array_items: usize,
    pub max_string_bytes: usize,
}

impl StrictValue {
    pub fn validate(&self, limits: ValueLimits) -> Result<(), &'static str> {
        let mut nodes = 0usize;
        validate_value(&self.0, 0, &mut nodes, limits)
    }
}

fn validate_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    limits: ValueLimits,
) -> Result<(), &'static str> {
    if depth > limits.max_depth {
        return Err("JSON nesting exceeds bound");
    }
    *nodes = nodes.checked_add(1).ok_or("JSON node count overflow")?;
    if *nodes > limits.max_total_nodes {
        return Err("JSON node count exceeds bound");
    }
    match value {
        Value::String(value) if value.len() > limits.max_string_bytes => {
            Err("JSON string exceeds bound")
        }
        Value::Array(values) => {
            if values.len() > limits.max_array_items {
                return Err("JSON array exceeds item bound");
            }
            for value in values {
                validate_value(value, depth + 1, nodes, limits)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > limits.max_object_properties {
                return Err("JSON object exceeds property bound");
            }
            for (key, value) in values {
                if key.len() > limits.max_string_bytes {
                    return Err("JSON key exceeds bound");
                }
                validate_value(value, depth + 1, nodes, limits)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_at_any_depth_are_rejected() {
        assert!(serde_json::from_str::<StrictValue>(r#"{"a":{"b":1,"b":2}}"#).is_err());
    }

    #[test]
    fn depth_nodes_items_and_strings_are_bounded() {
        let value: StrictValue = serde_json::from_str(r#"{"a":["long"]}"#).unwrap();
        assert!(value
            .validate(ValueLimits {
                max_depth: 1,
                max_total_nodes: 10,
                max_object_properties: 2,
                max_array_items: 2,
                max_string_bytes: 8,
            })
            .is_err());
        assert!(value
            .validate(ValueLimits {
                max_depth: 3,
                max_total_nodes: 10,
                max_object_properties: 2,
                max_array_items: 2,
                max_string_bytes: 8,
            })
            .is_ok());
    }
}
