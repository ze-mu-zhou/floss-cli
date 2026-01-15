//! FLOSS `-j/--json` 输出的强类型结构体。
//!
//! 结构与字段命名对齐 `flare-floss` 的 `floss/results.py` 与 `floss/render/json.py`：
//! - JSON 由 Python dataclass `asdict()` 生成；
//! - `datetime` 会被编码为 `ISO8601 + "Z"` 字符串；
//! - `decoding_function_scores` 的 key 在 JSON 中是字符串（因为 JSON object key 只能是字符串），这里支持十进制与 `0x` 十六进制地址。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 地址类字段（函数地址、程序计数器、解码例程地址等）。
pub type Address = u64;

/// FLOSS JSON 顶层结构。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultDocument {
    pub analysis: Analysis,
    pub metadata: Metadata,
    pub strings: Strings,
}

/// 字符串编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StringEncoding {
    #[serde(rename = "ASCII")]
    Ascii,
    #[serde(rename = "UTF-16LE")]
    Utf16Le,
    #[serde(rename = "UTF-8")]
    Utf8,
}

/// 内存地址类型（栈/全局/堆）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AddressType {
    Stack,
    Global,
    Heap,
}

/// 栈字符串（stack strings / tight strings）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Eq)]
pub struct StackString {
    pub encoding: StringEncoding,
    pub frame_offset: i64,
    pub function: Address,
    pub offset: i64,
    pub original_stack_pointer: Address,
    pub program_counter: Address,
    pub stack_pointer: Address,
    pub string: String,
}

/// 解码字符串（decoded strings）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Eq)]
pub struct DecodedString {
    pub address: Address,
    pub address_type: AddressType,
    pub decoded_at: Address,
    pub decoding_routine: Address,
    pub encoding: StringEncoding,
    pub string: String,
}

/// 静态字符串（static strings / language strings）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Eq)]
pub struct StaticString {
    pub encoding: StringEncoding,
    pub offset: Address,
    pub string: String,
}

/// 运行时统计（耗时，单位秒）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Runtime {
    #[serde(default)]
    pub decoded_strings: f64,
    #[serde(default)]
    pub find_features: f64,
    #[serde(default)]
    pub language_strings: f64,
    #[serde(default)]
    pub stack_strings: f64,
    #[serde(default)]
    pub start_date: String,
    #[serde(default)]
    pub static_strings: f64,
    #[serde(default)]
    pub tight_strings: f64,
    #[serde(default)]
    pub total: f64,
    #[serde(default)]
    pub vivisect: f64,
}

/// 被识别为“字符串解码函数”的评分信息。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodingFunctionScore {
    pub score: f64,
    #[serde(deserialize_with = "deserialize_u64_from_number")]
    pub xrefs_to: u64,
}

/// 函数相关统计信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Functions {
    #[serde(default)]
    pub analyzed_decoded_strings: u64,
    #[serde(default)]
    pub analyzed_stack_strings: u64,
    #[serde(default)]
    pub analyzed_tight_strings: u64,
    #[serde(default, deserialize_with = "deserialize_address_key_map")]
    pub decoding_function_scores: BTreeMap<Address, DecodingFunctionScore>,
    #[serde(default)]
    pub discovered: u64,
    #[serde(default)]
    pub library: u64,
}

/// FLOSS 里的“是否启用某类字符串”的开关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Enabled(pub bool);

impl Enabled {
    #[must_use]
    pub const fn get(self) -> bool {
        self.0
    }
}

impl From<Enabled> for bool {
    fn from(value: Enabled) -> Self {
        value.0
    }
}

/// FLOSS 分析配置与统计。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Analysis {
    #[serde(default = "default_enabled")]
    pub enable_decoded_strings: Enabled,
    #[serde(default = "default_enabled")]
    pub enable_stack_strings: Enabled,
    #[serde(default = "default_enabled")]
    pub enable_static_strings: Enabled,
    #[serde(default = "default_enabled")]
    pub enable_tight_strings: Enabled,
    #[serde(default)]
    pub functions: Functions,
}

/// FLOSS 输出元数据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub file_path: String,
    #[serde(default)]
    pub imagebase: Address,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub language_selected: String,
    #[serde(default)]
    pub language_version: String,
    #[serde(default)]
    pub min_length: u64,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub version: String,
}

/// 字符串列表集合。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Eq)]
pub struct Strings {
    #[serde(default)]
    pub decoded_strings: Vec<DecodedString>,
    #[serde(default)]
    pub language_strings: Vec<StaticString>,
    #[serde(default)]
    pub language_strings_missed: Vec<StaticString>,
    #[serde(default)]
    pub stack_strings: Vec<StackString>,
    #[serde(default)]
    pub static_strings: Vec<StaticString>,
    #[serde(default)]
    pub tight_strings: Vec<StackString>,
}

const fn default_enabled() -> Enabled {
    Enabled(true)
}

fn deserialize_address_key_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<Address, DecodingFunctionScore>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct MapVisitor;

    impl<'de> serde::de::Visitor<'de> for MapVisitor {
        type Value = BTreeMap<Address, DecodingFunctionScore>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("包含十进制或 0x 十六进制地址 key 的 map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, value)) =
                access.next_entry::<AddressKey, DecodingFunctionScore>()?
            {
                map.insert(key.0, value);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(MapVisitor)
}

struct AddressKey(Address);

impl<'de> Deserialize<'de> for AddressKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyVisitor;

        impl serde::de::Visitor<'_> for KeyVisitor {
            type Value = AddressKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("十进制或 0x 十六进制地址")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(AddressKey(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u64::try_from(value)
                    .map(AddressKey)
                    .map_err(|_error| E::custom("期望非负整数地址"))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.is_finite() && value.fract() == 0.0 && value >= 0.0 {
                    value
                        .to_string()
                        .parse::<u64>()
                        .map(AddressKey)
                        .map_err(|_error| E::custom("期望非负整数地址"))
                } else {
                    Err(E::custom("期望非负整数地址"))
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_address_key(value)
                    .map(AddressKey)
                    .map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(KeyVisitor)
    }
}

fn parse_address_key(value: &str) -> Result<Address, &'static str> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        if hex.is_empty() {
            return Err("十六进制地址不能为空");
        }
        u64::from_str_radix(hex, 16).map_err(|_error| "无效的十六进制地址")
    } else if value.is_empty() {
        Err("地址不能为空")
    } else {
        value.parse::<u64>().map_err(|_error| "无效的十进制地址")
    }
}

fn deserialize_u64_from_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NumberVisitor;

    impl serde::de::Visitor<'_> for NumberVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a non-negative integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            u64::try_from(value).map_err(|_error| E::custom("expected a non-negative integer"))
        }

        fn visit_f64<E>(self, value: f64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            if value.is_finite() && value.fract() == 0.0 && value >= 0.0 {
                value
                    .to_string()
                    .parse::<u64>()
                    .map_err(|_error| E::custom("expected a non-negative integer"))
            } else {
                Err(E::custom("expected a non-negative integer"))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            value
                .parse::<u64>()
                .map_err(|_error| E::custom("expected a non-negative integer"))
        }
    }

    deserializer.deserialize_any(NumberVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_function_scores_accepts_hex_keys() {
        let json = r#"{"analysis":{"functions":{"decoding_function_scores":{"0x1000":{"score":1.5,"xrefs_to":2}}}},"metadata":{"file_path":"sample.bin"},"strings":{}}"#;
        let doc: ResultDocument = serde_json::from_str(json).expect("解析 JSON 失败");
        let mut expected = BTreeMap::new();
        expected.insert(
            0x1000,
            DecodingFunctionScore {
                score: 1.5,
                xrefs_to: 2,
            },
        );
        assert_eq!(doc.analysis.functions.decoding_function_scores, expected);
    }

    #[test]
    fn decoding_function_scores_accepts_decimal_keys() {
        let json = r#"{"analysis":{"functions":{"decoding_function_scores":{"4096":{"score":1.5,"xrefs_to":2}}}},"metadata":{"file_path":"sample.bin"},"strings":{}}"#;
        let doc: ResultDocument = serde_json::from_str(json).expect("解析 JSON 失败");
        assert!(doc
            .analysis
            .functions
            .decoding_function_scores
            .contains_key(&4096));
    }
}
