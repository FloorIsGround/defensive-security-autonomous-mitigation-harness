//! Closed, typed rules for expected changes in collector sets.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::watch::CollectorType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectationRuleSpec {
    pub scope: RuleScope,
    pub matches: Vec<MatchClause>,
    pub effect: RuleEffect,
    pub rationale: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleScope {
    pub host_id: String,
    pub collector: CollectorType,
    #[serde(default)]
    pub watch_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchClause {
    Eq {
        field: String,
        value: RuleValue,
    },
    In {
        field: String,
        values: Vec<RuleValue>,
    },
    Range {
        field: String,
        min: i64,
        max: i64,
    },
    Prefix {
        field: String,
        value: String,
    },
}

impl MatchClause {
    pub fn field(&self) -> &str {
        match self {
            Self::Eq { field, .. }
            | Self::In { field, .. }
            | Self::Range { field, .. }
            | Self::Prefix { field, .. } => field,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleValue {
    Int(i64),
    Bool(bool),
    Text(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    AllowOptional,
    RequirePresent,
    IgnoreModified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOrigin {
    Operator,
    Investigator,
}

/// A rule selected for evaluation by the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRule {
    pub rule_id: String,
    pub spec: ExpectationRuleSpec,
}
