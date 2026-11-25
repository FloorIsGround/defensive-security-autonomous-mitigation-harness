use serde_json::{Value, json};

use crate::Mode;

pub(crate) struct Tool {
    pub name: &'static str,
    description: &'static str,
    schema: fn() -> Value,
}

impl Tool {
    pub fn descriptor(&self) -> Value {
        json!({"name": self.name, "description": self.description, "inputSchema": (self.schema)()})
    }
}

pub(crate) fn available_tools(mode: Mode) -> impl Iterator<Item = &'static Tool> {
    let investigator = (mode == Mode::Investigator).then_some(INVESTIGATOR_TOOLS);
    READ_TOOLS.iter().chain(investigator.into_iter().flatten())
}

const READ_TOOLS: &[Tool] = &[
    Tool {
        name: "list_hosts",
        description: "List enrolled hosts in the capability scope.",
        schema: || object([], [("limit", nullable(unsigned(u32::MAX.into())))]),
    },
    Tool {
        name: "list_active_incidents",
        description: "List active incidents within scope, optionally filtered by host.",
        schema: || {
            object(
                [],
                [
                    ("host_id", nullable(string())),
                    ("limit", nullable(unsigned(u32::MAX.into()))),
                ],
            )
        },
    },
    Tool {
        name: "list_active_watches",
        description: "List effective watches for a host.",
        schema: host_schema,
    },
    Tool {
        name: "list_collector_capabilities",
        description: "List typed collectors available for a host within scope.",
        schema: host_schema,
    },
    Tool {
        name: "get_incident_context",
        description: "Get an incident and its active watches, recent observations, and findings.",
        schema: || object([("incident_id", string())], []),
    },
    Tool {
        name: "query_observations",
        description: "Query bounded observations with stable evidence IDs.",
        schema: || {
            object(
                [("host_id", string())],
                [
                    ("watch_id", nullable(string())),
                    ("since", nullable(timestamp())),
                    ("limit", nullable(unsigned(u32::MAX.into()))),
                ],
            )
        },
    },
    Tool {
        name: "get_host_baseline_summary",
        description: "Get accepted baseline revisions for a host.",
        schema: host_schema,
    },
    Tool {
        name: "list_investigation_runs",
        description: "List recent investigation runs and their progress within scope.",
        schema: || object([], run_filters()),
    },
    Tool {
        name: "get_run_events",
        description: "Read an investigation run's events in sequence order.",
        schema: || {
            object(
                [("run_id", string())],
                [
                    ("after_seq", nullable(signed())),
                    ("limit", nullable(unsigned(u32::MAX.into()))),
                ],
            )
        },
    },
    Tool {
        name: "list_trigger_queue",
        description: "List recent trigger queue entries without lease credentials.",
        schema: || {
            object(
                [],
                run_filters().into_iter().chain([(
                    "statuses",
                    nullable(array(choices(&[
                        "pending",
                        "leased",
                        "done",
                        "dead_letter",
                    ]))),
                )]),
            )
        },
    },
    Tool {
        name: "list_expectation_rules",
        description: "List expectation rules within scope, optionally filtered by host and status.",
        schema: || {
            object(
                [],
                [
                    ("host_id", nullable(string())),
                    (
                        "statuses",
                        nullable(array(choices(&[
                            "active",
                            "proposed",
                            "rejected",
                            "revoked",
                            "expired",
                        ]))),
                    ),
                    ("limit", nullable(unsigned(u32::MAX.into()))),
                ],
            )
        },
    },
];

const INVESTIGATOR_TOOLS: &[Tool] = &[
    Tool {
        name: "start_investigation_run",
        description: "Start a scoped investigation run for an incident.",
        schema: || {
            object(
                [
                    ("incident_id", string()),
                    ("backend_id", string()),
                    ("model_id", string()),
                    ("prompt_schema_version", string()),
                ],
                [],
            )
        },
    },
    Tool {
        name: "propose_ephemeral_watch",
        description: "Submit a typed temporary watch for a controller policy decision.",
        schema: || {
            object(
                [
                    ("run_id", string()),
                    ("idempotency_key", string()),
                    ("spec", watch_schema()),
                    ("rationale", string()),
                ],
                [],
            )
        },
    },
    Tool {
        name: "record_hypothesis_or_finding",
        description: "Record a scoped hypothesis or finding with observation IDs.",
        schema: || {
            object(
                [
                    ("run_id", string()),
                    ("incident_id", string()),
                    ("kind", choices(&["hypothesis", "verified_finding"])),
                    (
                        "severity",
                        choices(&["info", "low", "medium", "high", "critical"]),
                    ),
                    ("summary", string()),
                    ("uncertainty", string()),
                    ("evidence_observation_ids", array(signed())),
                    ("escalation_requested", boolean()),
                ],
                [],
            )
        },
    },
    Tool {
        name: "propose_expectation_rule",
        description: (
            "Submit a closed-schema expectation rule for the adapter's current \
             investigation run. A deterministic gate decides; accepted rules are \
             stored as proposed with a backtest and stay inert until an operator \
             approves them. The run binding comes from the adapter, not the caller."
        ),
        schema: || {
            object(
                [("idempotency_key", string()), ("rule", rule_schema())],
                [],
            )
        },
    },
];

fn run_filters() -> [(&'static str, Value); 3] {
    [
        ("incident_id", nullable(string())),
        ("host_id", nullable(string())),
        ("limit", nullable(unsigned(u32::MAX.into()))),
    ]
}

fn host_schema() -> Value {
    object([("host_id", string())], [])
}

fn watch_schema() -> Value {
    object(
        [
            ("id", string()),
            ("version", unsigned(u32::MAX.into())),
            ("host_id", string()),
            ("class", choices(&["baseline", "ephemeral"])),
            ("collector", collector_schema()),
            (
                "schedule",
                object(
                    [
                        ("interval_seconds", unsigned(u64::MAX)),
                        ("timeout_seconds", unsigned(u64::MAX)),
                    ],
                    [],
                ),
            ),
            ("trigger", trigger_schema()),
            (
                "wake_policy",
                object(
                    [
                        ("cooldown_seconds", unsigned(u64::MAX)),
                        ("max_wakeups_per_hour", unsigned(u32::MAX.into())),
                    ],
                    [],
                ),
            ),
            (
                "lifecycle",
                object(
                    [("enabled", boolean())],
                    [
                        ("expires_at", nullable(timestamp())),
                        ("max_runs", nullable(unsigned(u64::MAX))),
                    ],
                ),
            ),
        ],
        [("incident_id", nullable(string()))],
    )
}

fn collector_schema() -> Value {
    let collector = |tag, parameters| tagged(tag, [("parameters", parameters)]);
    json!({"oneOf": [
        collector("sockets.listening", object([], [
            ("include_tcp", boolean()), ("include_udp", boolean()),
            ("include_ipv6", boolean()), ("resolve_process", boolean()),
        ])),
        collector("systemd.unit_state", object([("unit", string())], [
            ("hash_unit_files", boolean()),
        ])),
        collector("files.metadata", object([("paths", array(string()))], [
            ("compute_hash", boolean()), ("max_file_bytes", nullable(unsigned(u64::MAX))),
        ])),
        collector("journal.unit_events", object([("unit", string())], [
            ("min_priority", nullable(unsigned(u8::MAX.into()))),
            ("max_events_per_batch", nullable(unsigned(u32::MAX.into()))),
            ("max_message_bytes", nullable(unsigned(usize::MAX as u64))),
        ])),
    ]})
}

fn trigger_schema() -> Value {
    let compare = || choices(&["last_observed", "accepted_baseline"]);
    json!({"oneOf": [
        tagged("field_changed", [
            ("compare_against", compare()), ("fields", array(string())),
        ]),
        tagged("set_diff", [
            ("compare_against", compare()), ("set_field", string()), ("identity_key", string()),
        ]),
        tagged("threshold_sustained", [
            ("field", string()), ("operator", choices(&["gt", "gte", "lt", "lte", "eq", "neq"])),
            ("threshold", signed()), ("consecutive_samples", unsigned(u32::MAX.into())),
        ]),
        tagged("collector_stale_or_error", [
            ("max_stale_seconds", unsigned(u64::MAX)),
            ("consecutive_errors", unsigned(u32::MAX.into())),
        ]),
    ]})
}

fn tagged(tag: &str, required: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    object(
        [("type", json!({"const": tag}))]
            .into_iter()
            .chain(required),
        [],
    )
}

// `MatchClause` is internally tagged on "op" rather than "type".
fn op_tagged(tag: &str, required: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    object(
        [("op", json!({"const": tag}))]
            .into_iter()
            .chain(required),
        [],
    )
}

/// Strict mirror of `ExpectationRuleSpec` (`crates/protocol/src/rules.rs`).
fn rule_schema() -> Value {
    object(
        [
            (
                "scope",
                object(
                    [
                        ("host_id", string()),
                        (
                            "collector",
                            choices(&[
                                "sockets.listening",
                                "systemd.unit_state",
                                "files.metadata",
                                "journal.unit_events",
                            ]),
                        ),
                    ],
                    [("watch_id", nullable(string()))],
                ),
            ),
            (
                "matches",
                json!({"type": "array", "minItems": 1, "maxItems": 8, "items": clause_schema()}),
            ),
            (
                "effect",
                choices(&["allow_optional", "require_present", "ignore_modified"]),
            ),
            ("rationale", string()),
        ],
        [("expires_at", nullable(timestamp()))],
    )
}

fn clause_schema() -> Value {
    json!({"oneOf": [
        op_tagged("eq", [("field", string()), ("value", rule_value())]),
        op_tagged("in", [
            ("field", string()),
            (
                "values",
                json!({"type": "array", "minItems": 1, "maxItems": 32, "items": rule_value()}),
            ),
        ]),
        op_tagged("range", [("field", string()), ("min", signed()), ("max", signed())]),
        op_tagged("prefix", [("field", string()), ("value", string())]),
    ]})
}

// `RuleValue` is untagged: Int(i64) | Bool(bool) | Text(String).
fn rule_value() -> Value {
    json!({"anyOf": [signed(), boolean(), string()]})
}

fn object(
    required: impl IntoIterator<Item = (&'static str, Value)>,
    optional: impl IntoIterator<Item = (&'static str, Value)>,
) -> Value {
    let mut required_names = Vec::new();
    let mut properties = serde_json::Map::new();
    for (name, schema) in required {
        required_names.push(name);
        properties.insert(name.into(), schema);
    }
    properties.extend(
        optional
            .into_iter()
            .map(|(name, schema)| (name.into(), schema)),
    );
    json!({
        "type": "object",
        "properties": properties,
        "required": required_names,
        "additionalProperties": false,
    })
}

fn string() -> Value {
    json!({"type": "string"})
}

fn timestamp() -> Value {
    json!({"type": "string", "format": "date-time"})
}

fn boolean() -> Value {
    json!({"type": "boolean"})
}

fn unsigned(maximum: u64) -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": maximum})
}

fn signed() -> Value {
    json!({"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX})
}

fn choices(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

fn nullable(schema: Value) -> Value {
    json!({"anyOf": [schema, {"type": "null"}]})
}

fn array(items: Value) -> Value {
    json!({"type": "array", "items": items})
}
