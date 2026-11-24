//! Shared Restricted Investigation RPC and Administrative API contracts.
//!
//! Both automated workers (`reasoner-d`) and interactive frontends (`mcp-adapter`)
//! invoke the exact same server-side Investigation RPC and policy gate.
//! Administrative mutations live on a strictly separate Admin interface/role.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::{
    ActionAuthMode, ActionIntentPayload, ActionIntentStatus, ActionReceipt, ActionSummary,
    ActionVerb, AuthorizedActionIntent,
};
use crate::audit::AuditEntry;
use crate::observation::ObservationStatus;
use crate::signing::SignedEnvelope;
use crate::watch::{CollectorCapability, CollectorType, WatchSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    /// Read-only scoped discovery and evidence queries.
    Observer,
    /// Read + scoped ephemeral watch proposals and hypothesis/finding recording.
    Investigator,
    /// Separate administrative interface only: host enrollment, baseline CRUD/promotion, policy.
    Admin,
}

/// Server-validated scoped capability bound to a principal/session/run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedCapability {
    pub principal_id: String,
    pub role: PrincipalRole,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub incident_id: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_collectors: Vec<CollectorType>,
    pub expires_at: DateTime<Utc>,
}

/// Durable policy decision recorded for every proposal or gated mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub rule_id: String,
    pub reason: String,
    pub policy_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Hypothesis,
    VerifiedFinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Authenticated envelope for every Investigation RPC call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationCall {
    pub request_id: String,
    pub capability_token: String,
    pub request: InvestigationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvestigationRequest {
    ListHosts {
        #[serde(default)]
        limit: Option<u32>,
    },
    ListActiveIncidents {
        #[serde(default)]
        host_id: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    ListActiveWatches {
        host_id: String,
    },
    ListCollectorCapabilities {
        host_id: String,
    },
    GetIncidentContext {
        incident_id: String,
    },
    QueryObservations {
        host_id: String,
        #[serde(default)]
        watch_id: Option<String>,
        #[serde(default)]
        since: Option<DateTime<Utc>>,
        #[serde(default)]
        limit: Option<u32>,
    },
    GetHostBaselineSummary {
        host_id: String,
    },
    StartInvestigationRun {
        incident_id: String,
        backend_id: String,
        model_id: String,
        prompt_schema_version: String,
    },
    ProposeEphemeralWatch {
        run_id: String,
        idempotency_key: String,
        spec: WatchSpec,
        rationale: String,
    },
    RecordHypothesisOrFinding {
        run_id: String,
        incident_id: String,
        kind: FindingKind,
        severity: Severity,
        summary: String,
        uncertainty: String,
        evidence_observation_ids: Vec<i64>,
        escalation_requested: bool,
    },
    LeaseNextTrigger {
        lease_owner: String,
        lease_seconds: u64,
    },
    CompleteTriggerLease {
        event_id: i64,
        lease_token: String,
        #[serde(default)]
        run_id: Option<String>,
        #[serde(default)]
        summary: Option<String>,
    },
    FailTriggerLease {
        event_id: i64,
        lease_token: String,
        error: String,
        retryable: bool,
    },
    ProposeAction {
        run_id: String,
        incident_id: String,
        idempotency_key: String,
        verb: ActionVerb,
        evidence_observation_ids: Vec<i64>,
        expected_effect: String,
        blast_radius: String,
        rollback_plan: String,
    },
    ListActions {
        #[serde(default)]
        host_id: Option<String>,
        #[serde(default)]
        incident_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedTrigger {
    pub event_id: i64,
    pub incident_id: String,
    pub host_id: String,
    pub watch_id: String,
    pub spec_version: u32,
    pub lease_token: String,
    pub lease_expires_at: DateTime<Utc>,
    pub retry_count: u32,
    pub outcome: serde_json::Value,
    pub evidence_observation_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionRecord {
    pub decision_id: i64,
    #[serde(default)]
    pub proposal_id: Option<i64>,
    pub actor: String,
    pub request_id: String,
    pub decision: PolicyDecision,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSummary {
    pub host_id: String,
    pub agent_version: String,
    pub liveness_status: String,
    pub active_bundle_version: u64,
    #[serde(default)]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentSummary {
    pub incident_id: String,
    pub host_id: String,
    pub status: String,
    pub priority: Severity,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSlice {
    pub observation_id: i64,
    pub host_id: String,
    pub watch_id: String,
    pub spec_version: u32,
    pub observed_at: DateTime<Utc>,
    pub status: ObservationStatus,
    pub state_hash: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineSummaryEntry {
    pub watch_id: String,
    pub revision_id: i64,
    pub state_hash: String,
    pub approver: String,
    pub approved_at: DateTime<Utc>,
    #[serde(default)]
    pub ticket_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvestigationResponse {
    Hosts {
        hosts: Vec<HostSummary>,
    },
    Incidents {
        incidents: Vec<IncidentSummary>,
    },
    Watches {
        watches: Vec<WatchSpec>,
    },
    Capabilities {
        capabilities: Vec<CollectorCapability>,
    },
    IncidentContext {
        incident: IncidentSummary,
        active_watches: Vec<WatchSpec>,
        recent_observations: Vec<ObservationSlice>,
        findings: Vec<serde_json::Value>,
    },
    Observations {
        observations: Vec<ObservationSlice>,
    },
    BaselineSummary {
        host_id: String,
        baselines: Vec<BaselineSummaryEntry>,
    },
    RunStarted {
        run_id: String,
        incident_id: String,
        expires_at: DateTime<Utc>,
    },
    ProposalEvaluated {
        decision: PolicyDecision,
        #[serde(default)]
        watch_id: Option<String>,
        #[serde(default)]
        bundle_version: Option<u64>,
    },
    FindingRecorded {
        finding_id: i64,
        verified_evidence_count: usize,
    },
    TriggerLeased {
        #[serde(default)]
        lease: Option<LeasedTrigger>,
    },
    LeaseUpdated {
        event_id: i64,
        status: String,
    },
    ActionProposalEvaluated {
        decision: PolicyDecision,
        #[serde(default)]
        proposal_id: Option<i64>,
        #[serde(default)]
        intent_id: Option<String>,
        #[serde(default)]
        auth_mode: Option<ActionAuthMode>,
        #[serde(default)]
        status: Option<ActionIntentStatus>,
        #[serde(default)]
        authorized_intent: Option<AuthorizedActionIntent>,
    },
    Actions {
        actions: Vec<ActionSummary>,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Separate operator administrative RPC (never exposed to MCP/reasoner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admin_op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    EnrollHost {
        host_id: String,
        agent_public_key_hex: Option<String>,
    },
    ApplyBaselineWatch {
        spec: WatchSpec,
        actor: String,
        rationale: String,
    },
    PromoteBaseline {
        host_id: String,
        watch_id: String,
        observation_id: i64,
        approver: String,
        rationale: String,
        #[serde(default)]
        ticket_ref: Option<String>,
    },
    MintCapabilityToken {
        principal_id: String,
        role: PrincipalRole,
        allowed_hosts: Vec<String>,
        allowed_collectors: Vec<CollectorType>,
        #[serde(default)]
        incident_id: Option<String>,
        ttl_seconds: u64,
    },
    CloseIncident {
        incident_id: String,
        actor: String,
        resolution: String,
    },
    ListHosts,
    ListIncidents,
    VerifyAuditChain,
    ListAuditEntries {
        #[serde(default)]
        limit: Option<u32>,
    },
    ListPolicyDecisions {
        #[serde(default)]
        limit: Option<u32>,
    },
    ListActions {
        #[serde(default)]
        host_id: Option<String>,
        #[serde(default)]
        incident_id: Option<String>,
    },
    GetActionIntent {
        intent_id: String,
    },
    ApproveAction {
        intent_id: String,
        approver: String,
        operator_approval: SignedEnvelope,
    },
    RecordActionReceipt {
        receipt: ActionReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admin_result", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminResponse {
    HostEnrolled {
        host_id: String,
        control_signing_key_id: String,
        control_public_key_hex: String,
    },
    WatchApplied {
        watch_id: String,
        bundle_version: u64,
    },
    BaselinePromoted {
        revision_id: i64,
        host_id: String,
        watch_id: String,
        state_hash: String,
    },
    TokenMinted {
        token: String,
        expires_at: DateTime<Utc>,
    },
    IncidentClosed {
        incident_id: String,
        retired_ephemeral_watches: usize,
    },
    Hosts {
        hosts: Vec<HostSummary>,
    },
    Incidents {
        incidents: Vec<IncidentSummary>,
    },
    AuditChainStatus {
        valid: bool,
        entries_checked: u64,
        #[serde(default)]
        latest_hash: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    AuditEntries {
        entries: Vec<AuditEntry>,
    },
    PolicyDecisions {
        decisions: Vec<PolicyDecisionRecord>,
    },
    Actions {
        actions: Vec<ActionSummary>,
    },
    ActionIntentDetail {
        payload: ActionIntentPayload,
        #[serde(default)]
        authorized_intent: Option<AuthorizedActionIntent>,
        status: ActionIntentStatus,
    },
    ActionApproved {
        intent_id: String,
        authorized_intent: AuthorizedActionIntent,
    },
    ActionReceiptAck {
        intent_id: String,
        status: ActionIntentStatus,
    },
    Error {
        code: String,
        message: String,
    },
}
