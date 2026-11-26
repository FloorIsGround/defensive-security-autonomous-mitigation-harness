use chrono::{DateTime, Duration, Utc};
use defsec_policy::edge_floor::validate_watch_spec;
use defsec_protocol::{
    observation::{ObservationStatus, PackagesInventorySnapshot, SocketsListeningSnapshot},
    profile::HostProfileSummary,
    rpc::*,
    watch::*,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

use crate::{
    ledger::{json_column, optional_json},
    service::{
        ControlError, ControlService, Result, active_watches, insert_watch, parse_stamp, stamp,
        uuid,
    },
};

pub(crate) const COLLECTORS: [CollectorType; 2] = [
    CollectorType::SocketsListening,
    CollectorType::PackagesInventory,
];

pub(crate) fn enqueue(db: &Connection, host: &str, now: DateTime<Utc>) -> Result<()> {
    let deadline = now + Duration::hours(24);
    let inserted = db.execute(
        "INSERT INTO host_discovery (host_id,deadline) VALUES (?1,?2) ON CONFLICT DO NOTHING",
        params![host, stamp(deadline)],
    )?;
    if inserted == 1 {
        save(
            db,
            &HostAssessment {
                host_id: host.into(),
                version: 1,
                interpretations: vec![],
                deadline,
                collectors: COLLECTORS
                    .into_iter()
                    .map(|collector| HostDiscoveryCoverage {
                        collector,
                        evidence: None,
                        gap: Some(HostDiscoveryGap::AwaitingAgent),
                    })
                    .collect(),
            },
            false,
        )?;
    }
    Ok(())
}

pub(crate) fn refresh(
    db: &Connection, host: &str, collectors: &[CollectorType], deadline: DateTime<Utc>,
) -> Result<()> {
    let mut assessment = load(db, host, None)?
        .ok_or_else(|| ControlError::missing("discovery assessment is missing"))?;
    for entry in &mut assessment.collectors {
        if collectors.contains(&entry.collector) {
            db.execute(
                "UPDATE watch_state SET retired=1 WHERE host_id=?1 AND (watch_id,spec_version) IN (
                     SELECT watch_id,spec_version FROM host_discovery_watches WHERE host_id=?1 AND collector=?2
                 )",
                params![host, entry.collector.as_str()],
            )?;
            db.execute(
                "DELETE FROM host_discovery_watches WHERE host_id=?1 AND collector=?2",
                params![host, entry.collector.as_str()],
            )?;
            entry.evidence = None;
            entry.gap = Some(HostDiscoveryGap::AwaitingAgent);
        }
    }
    assessment.interpretations.clear();
    assessment.version += 1;
    assessment.deadline = deadline;
    db.execute("UPDATE host_discovery SET deadline=?2 WHERE host_id=?1", params![host, stamp(deadline)])?;
    save(db, &assessment, false)
}

fn save(db: &Connection, assessment: &HostAssessment, finished: bool) -> Result<()> {
    db.execute(
        "INSERT INTO host_discovery_assessments (host_id,version,assessment_json) VALUES (?1,?2,?3)",
        params![assessment.host_id, assessment.version, serde_json::to_string(assessment)?],
    )?;
    db.execute(
        "UPDATE host_discovery SET latest_version=?2,finished=?3 WHERE host_id=?1",
        params![assessment.host_id, assessment.version, finished],
    )?;
    Ok(())
}

pub(crate) fn load(
    db: &Connection,
    host: &str,
    version: Option<u32>,
) -> Result<Option<HostAssessment>> {
    Ok(db.query_row(
        "SELECT a.assessment_json FROM host_discovery d JOIN host_discovery_assessments a USING (host_id)
         WHERE d.host_id=?1 AND a.version=COALESCE(?2,d.latest_version)",
        params![host, version], |r| json_column(r, 0),
    ).optional()?)
}

pub(crate) fn get(
    db: &Connection,
    cap: &ScopedCapability,
    host: &str,
    version: Option<u32>,
) -> Result<InvestigationResponse> {
    let assessment = load(db, host, version)?.map(|mut assessment| {
        scope_assessment(&mut assessment, &cap.allowed_collectors);
        if cap.incident_id.is_some() || cap.run_id.is_some() {
            assessment.interpretations.clear();
        }
        assessment
    });
    Ok(InvestigationResponse::HostAssessment { assessment })
}

/// Derived text is visible only when every source used to write it is visible.
pub(crate) fn scope_assessment(assessment: &mut HostAssessment, collectors: &[CollectorType]) {
    assessment.collectors.retain(|entry| collectors.contains(&entry.collector));
    assessment.interpretations.retain(|interpretation| {
        interpretation.source_ids.iter().all(|id| {
            assessment.collectors.iter().any(|entry| entry.evidence.as_ref().is_some_and(|e| e.observation_id == *id))
        })
    });
}

fn authorize_scope(cap: &ScopedCapability) -> Result<()> {
    if cap.run_id.is_some() || cap.incident_id.is_some() {
        return Err(ControlError::denied(
            "discovery requires a host-scoped grant",
        ));
    }
    Ok(())
}

pub(crate) fn correlate_packages(
    db: &Connection,
    cap: &ScopedCapability,
    [first, second]: [String; 2],
    package_name: String,
    max_age_seconds: u32,
    now: DateTime<Utc>,
) -> Result<InvestigationResponse> {
    authorize_scope(cap)?;
    if !cap
        .allowed_collectors
        .contains(&CollectorType::PackagesInventory)
    {
        return Err(ControlError::denied(
            "package inventory is outside capability scope",
        ));
    }
    if first == second || max_age_seconds == 0 {
        return Err(ControlError::invalid(
            "comparison requires two distinct hosts and a positive maximum age",
        ));
    }
    crate::investigation::require_text(&package_name, "package_name", 256)?;
    crate::service::require_host(db, &first)?;
    crate::service::require_host(db, &second)?;
    let cutoff = now - Duration::seconds(i64::from(max_age_seconds));
    let hosts = [
        compare_package(db, first, &package_name, cutoff, now)?,
        compare_package(db, second, &package_name, cutoff, now)?,
    ];
    let both_present = hosts[0].present.zip(hosts[1].present).map(|(a, b)| a && b);
    Ok(InvestigationResponse::PackageSnapshotsCorrelated {
        package_name,
        compared_at: now,
        max_age_seconds,
        hosts,
        both_present,
        interpretation: "Package presence describes the recorded snapshots. Shared presence provides no evidence of connectivity or causation.".into(),
    })
}

fn compare_package(
    db: &Connection,
    host_id: String,
    package_name: &str,
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<PackageSnapshotComparison> {
    let mut comparison = PackageSnapshotComparison {
        host_id,
        citation: None,
        observed_at: None,
        received_at: None,
        present: None,
        gap: Some(PackageSnapshotGap::MissingObservation),
    };
    let observation = db
        .query_row(
            "SELECT o.watch_id,o.spec_version,o.observation_id,o.state_hash,o.status_json,
                o.observed_at,o.received_at,o.sample_json
         FROM host_discovery_watches w JOIN observations o
           ON o.host_id=w.host_id AND o.watch_id=w.watch_id AND o.spec_version=w.spec_version
          AND o.collector_type=w.collector
         WHERE w.host_id=?1 AND w.collector=?2 AND w.review_only=0
         ORDER BY o.observation_id DESC LIMIT 1",
            params![
                comparison.host_id,
                CollectorType::PackagesInventory.as_str()
            ],
            |row| {
                Ok((
                    HostDiscoveryEvidence {
                        watch_id: row.get(0)?,
                        spec_version: row.get(1)?,
                        observation_id: row.get(2)?,
                        state_hash: row.get(3)?,
                        status: json_column(row, 4)?,
                    },
                    parse_stamp(&row.get::<_, String>(5)?, 5)?,
                    parse_stamp(&row.get::<_, String>(6)?, 6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((citation, observed_at, received_at, sample)) = observation else {
        return Ok(comparison);
    };
    comparison.gap = if observed_at > now || received_at > now {
        Some(PackageSnapshotGap::FutureObservation)
    } else if observed_at < cutoff {
        Some(PackageSnapshotGap::StaleObservation)
    } else if citation.status != ObservationStatus::Ok {
        Some(PackageSnapshotGap::IncompleteObservation)
    } else if let Some(snapshot) = sample
        .as_deref()
        .and_then(|sample| serde_json::from_str::<PackagesInventorySnapshot>(sample).ok())
    {
        if snapshot.truncated == Some(true)
            || snapshot.omitted_packages.unwrap_or(0) > 0
            || snapshot.malformed_stanzas > 0
            || snapshot.duplicate_stanzas > 0
            || snapshot.total_packages as usize != snapshot.packages.len()
        {
            Some(PackageSnapshotGap::IncompleteObservation)
        } else {
            comparison.present = Some(
                snapshot
                    .packages
                    .iter()
                    .any(|entry| entry.name == package_name),
            );
            None
        }
    } else {
        Some(PackageSnapshotGap::UnusableSnapshot)
    };
    comparison.citation = Some(citation);
    comparison.observed_at = Some(observed_at);
    comparison.received_at = Some(received_at);
    Ok(comparison)
}

pub(crate) fn samples(
    db: &Connection,
    cap: &ScopedCapability,
    host: &str,
    version: Option<u32>,
) -> Result<Vec<HostDiscoverySample>> {
    authorize_scope(cap)?;
    let Some(assessment) = load(db, host, version)? else {
        return Ok(vec![]);
    };
    let mut samples = vec![];
    for entry in assessment.collectors {
        if !cap.allowed_collectors.contains(&entry.collector) {
            continue;
        }
        let Some(evidence) = entry.evidence else {
            continue;
        };
        let sample: Option<serde_json::Value> = db
            .query_row(
                "SELECT sample_json FROM observations
             WHERE observation_id=?1 AND host_id=?2 AND collector_type=?3
               AND watch_id=?4 AND spec_version=?5 AND state_hash=?6
               AND sample_json IS NOT NULL
               AND (?7 OR NOT EXISTS (
                   SELECT 1 FROM discovery_watch_origins w WHERE w.host_id=?2 AND w.watch_id=?4
                       AND w.spec_version=?5 AND w.review_only=1
               ))",
                params![
                    evidence.observation_id,
                    host,
                    entry.collector.as_str(),
                    evidence.watch_id,
                    evidence.spec_version,
                    evidence.state_hash,
                    version.is_some()
                ],
                |row| json_column(row, 0),
            )
            .optional()?;
        if let Some(mut sample) = sample {
            let key = match entry.collector {
                CollectorType::SocketsListening
                    if SocketsListeningSnapshot::deserialize(&sample).is_ok() =>
                {
                    "sockets"
                }
                CollectorType::PackagesInventory
                    if PackagesInventorySnapshot::deserialize(&sample).is_ok() =>
                {
                    "packages"
                }
                _ => continue,
            };
            let Some(entries) = sample[key].as_array_mut() else {
                continue;
            };
            let mut remaining_bytes = 15 * 1024;
            let original_count = entries.len();
            entries.retain(|entry| {
                let size = entry.to_string().len() + 1;
                if size > remaining_bytes {
                    return false;
                }
                remaining_bytes -= size;
                true
            });
            let omitted_entries = original_count - entries.len();
            if sample.to_string().len() > 16 * 1024 {
                continue;
            }
            samples.push(HostDiscoverySample {
                collector: entry.collector,
                evidence,
                sample,
                omitted_entries,
            });
        }
    }
    Ok(samples)
}

pub(crate) fn submit(
    db: &Connection,
    cap: &ScopedCapability,
    host: &str,
    source_ids: Vec<i64>,
    proposal: ProposedHostInterpretation,
) -> Result<InvestigationResponse> {
    let samples = samples(db, cap, host, None)?;
    let expected: Vec<_> = samples
        .iter()
        .map(|sample| sample.evidence.observation_id)
        .collect();
    if expected.is_empty()
        || source_ids != expected
        || proposal.citations.is_empty()
        || proposal.citations.len() > expected.len()
        || proposal
            .citations
            .iter()
            .enumerate()
            .any(|(i, id)| proposal.citations[..i].contains(id))
        || proposal.citations.iter().any(|id| !expected.contains(id))
        || !samples.iter().any(|sample| {
            sample.collector == proposal.proposed_watch.collector
                && proposal.citations.contains(&sample.evidence.observation_id)
        })
    {
        return Err(ControlError::invalid(
            "proposal must cite current scoped discovery samples",
        ));
    }
    if proposal
        .proposed_watch
        .service_unit
        .as_ref()
        .is_some_and(|unit| {
            !unit.ends_with(".service")
                || defsec_policy::edge_floor::validate_systemd_unit_name(unit).is_err()
        })
    {
        return Err(ControlError::invalid("invalid proposed service unit"));
    }
    let valid_text = |text: &str| !text.trim().is_empty() && text.len() <= 512;
    if [
        &proposal.purpose,
        &proposal.uncertainty,
        &proposal.proposed_watch.rationale,
    ]
    .into_iter()
    .chain(&proposal.dependencies)
    .chain(&proposal.visibility_gaps)
    .any(|text| !valid_text(text))
        || proposal.dependencies.len() > 8
        || proposal.visibility_gaps.len() > 8
    {
        return Err(ControlError::invalid(
            "discovery proposal exceeds text bounds",
        ));
    }
    let mut assessment = load(db, host, None)?
        .ok_or_else(|| ControlError::missing("discovery assessment is missing"))?;
    if !assessment
        .interpretations
        .iter()
        .any(|value| value.source_ids == source_ids)
    {
        let finished = db.query_row(
            "SELECT finished FROM host_discovery WHERE host_id=?1",
            [host],
            |row| row.get(0),
        )?;
        assessment.version += 1;
        assessment.interpretations.push(HostInterpretation {
            source_ids,
            proposal,
        });
        save(db, &assessment, finished)?;
    }
    Ok(InvestigationResponse::HostInterpretationSaved {
        version: assessment.version,
    })
}

const MAX_INTERPRETATION_ATTEMPTS: u32 = 3;

fn interpretation_backoff(attempt: u32) -> Duration {
    Duration::seconds(30 * 2_i64.pow(attempt.saturating_sub(1).min(2)))
}

pub(crate) struct AttemptScope<'a> {
    pub db: &'a Connection,
    pub cap: &'a ScopedCapability,
    pub host: &'a str,
    pub now: DateTime<Utc>,
}

impl AttemptScope<'_> {
    pub fn claim(
        &self,
        hash: &str,
        request: &str,
        source_ids: Vec<i64>,
        export_collectors: &[CollectorType],
        lease_seconds: u32,
    ) -> Result<InvestigationResponse> {
        let unavailable = InvestigationResponse::HostInterpretationClaimed { lease_id: None };
        let current = samples(self.db, self.cap, self.host, None)?;
        let expected: Vec<_> = current.iter().map(|s| s.evidence.observation_id).collect();
        if expected.is_empty()
            || expected != source_ids
            || current
                .iter()
                .any(|s| !export_collectors.contains(&s.collector))
        {
            return Ok(unavailable);
        }
        let lease_until = self.now + Duration::seconds(i64::from(lease_seconds));
        if !(1..=900).contains(&lease_seconds) || lease_until >= self.cap.expires_at {
            return Ok(unavailable);
        }
        if load(self.db, self.host, None)?
            .is_some_and(|a| a.interpretations.iter().any(|i| i.source_ids == source_ids))
        {
            return Ok(unavailable);
        }
        let key = serde_json::to_string(&source_ids)?;
        // Investigation RPCs hold an immediate transaction across this check and insertion.
        let (count, blocked): (u32, bool) = self.db.query_row(
            "SELECT count(*), COALESCE(max(status='saved' OR retry_at>?3),0)
             FROM host_discovery_interpretation_attempts
             WHERE host_id=?1 AND source_ids=?2 AND status!='cancelled'",
            params![self.host, key, stamp(self.now)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count >= MAX_INTERPRETATION_ATTEMPTS || blocked {
            return Ok(unavailable);
        }
        let lease_id = uuid();
        let collectors: Vec<_> = current.iter().map(|s| s.collector).collect();
        let inserted = self.db.execute(
            "INSERT INTO host_discovery_interpretation_attempts
             (lease_id,host_id,source_ids,collectors,token_hash,request_id,lease_until,retry_at,status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'leased')
             ON CONFLICT(token_hash,request_id) DO NOTHING",
            params![lease_id, self.host, key, serde_json::to_string(&collectors)?, hash, request,
                stamp(lease_until), stamp(lease_until + interpretation_backoff(count + 1))],
        )?;
        Ok(InvestigationResponse::HostInterpretationClaimed {
            lease_id: (inserted == 1).then_some(lease_id),
        })
    }

    pub fn finish(
        &self,
        hash: &str,
        lease_id: &str,
        proposal: Option<serde_json::Value>,
        usage: Option<HostInterpretationUsage>,
        mut error: Option<HostInterpretationError>,
    ) -> Result<InvestigationResponse> {
        use HostInterpretationError::*;
        authorize_scope(self.cap)?;
        let (source_ids, _, until, retry_at, status, version): (
            Vec<i64>,
            Vec<CollectorType>,
            String,
            String,
            String,
            Option<u32>,
        ) = self
            .db
            .query_row(
                "SELECT source_ids,collectors,lease_until,retry_at,status,assessment_version
             FROM host_discovery_interpretation_attempts
             WHERE host_id=?1 AND lease_id=?2 AND token_hash=?3",
                params![self.host, lease_id, hash],
                |r| {
                    Ok((
                        json_column(r, 0)?,
                        json_column(r, 1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?
            .filter(|(_, collectors, _, _, _, _): &(_, Vec<_>, _, _, _, _)| {
                collectors
                    .iter()
                    .all(|c| self.cap.allowed_collectors.contains(c))
            })
            .ok_or_else(|| ControlError::missing("interpretation lease unavailable"))?;
        if status != "leased" {
            return Ok(InvestigationResponse::HostInterpretationFinished { version });
        }
        let until = parse_stamp(&until, 2)?;
        let mut version = None;
        if error == Some(ExportRevoked) {
            if proposal.is_some() || usage.is_some() {
                return Err(ControlError::invalid("invalid export cancellation"));
            }
            // Keep the request tombstone to prevent replay. No provider call was made.
            self.db.execute(
                "UPDATE host_discovery_interpretation_attempts SET status='cancelled' WHERE lease_id=?1",
                [lease_id],
            )?;
            return Ok(InvestigationResponse::HostInterpretationFinished { version });
        }
        if self.now >= until {
            error = Some(LeaseExpired);
        } else if error.is_none() {
            let current = samples(self.db, self.cap, self.host, None)?;
            if !current
                .iter()
                .map(|s| s.evidence.observation_id)
                .eq(source_ids.iter().copied())
            {
                error = Some(EvidenceChanged);
            } else if let Some(proposal) = proposal.and_then(|p| serde_json::from_value(p).ok()) {
                match submit(self.db, self.cap, self.host, source_ids, proposal) {
                    Ok(InvestigationResponse::HostInterpretationSaved { version: saved }) => {
                        version = Some(saved)
                    }
                    Err(ControlError::Request {
                        code: "invalid_request",
                        ..
                    }) => error = Some(MalformedResponse),
                    Err(err) => return Err(err),
                    Ok(_) => unreachable!(),
                }
            } else {
                error = Some(MalformedResponse);
            }
        }
        let retry = if self.now >= until {
            retry_at
        } else {
            stamp(self.now + (parse_stamp(&retry_at, 3)? - until))
        };
        let status = if version.is_some() { "saved" } else { "failed" };
        self.db.execute(
            "UPDATE host_discovery_interpretation_attempts
             SET status=?2, usage_json=?3, error_class=?4, assessment_version=?5, retry_at=?6
             WHERE lease_id=?1",
            params![
                lease_id,
                status,
                usage.map(|u| serde_json::to_string(&u)).transpose()?,
                error.map(|e| serde_json::to_string(&e)).transpose()?,
                version,
                retry
            ],
        )?;
        Ok(InvestigationResponse::HostInterpretationFinished { version })
    }

    pub fn list(&self, source_ids: Vec<i64>) -> Result<InvestigationResponse> {
        authorize_scope(self.cap)?;
        let mut statement = self.db.prepare(
            "SELECT status,lease_until,retry_at,usage_json,error_class,assessment_version
             FROM host_discovery_interpretation_attempts a
             WHERE host_id=?1 AND source_ids=?2 AND status!='cancelled' AND NOT EXISTS (
                 SELECT 1 FROM json_each(a.collectors)
                 WHERE value NOT IN (SELECT value FROM json_each(?3))
             )
             ORDER BY rowid",
        )?;
        let attempts = statement
            .query_map(
                params![
                    self.host,
                    serde_json::to_string(&source_ids)?,
                    serde_json::to_string(&self.cap.allowed_collectors)?
                ],
                |r| {
                    let lease_until = parse_stamp(&r.get::<_, String>(1)?, 1)?;
                    let mut status: String = r.get(0)?;
                    let mut error = optional_json(r, 4)?;
                    if status == "leased" && lease_until <= self.now {
                        status = "failed".into();
                        error = Some(HostInterpretationError::LeaseExpired);
                    }
                    Ok(HostInterpretationAttempt {
                        status,
                        lease_until,
                        retry_at: parse_stamp(&r.get::<_, String>(2)?, 2)?,
                        usage: optional_json(r, 3)?,
                        error,
                        assessment_version: r.get(5)?,
                    })
                },
            )?
            .collect::<std::result::Result<_, _>>()?;
        Ok(InvestigationResponse::HostInterpretationAttempts { attempts })
    }
}

impl ControlService {
    pub(crate) fn advance_discovery(
        &self,
        db: &Connection,
        cap: &ScopedCapability,
        host: Option<&str>,
        request: &str,
        now: DateTime<Utc>,
    ) -> Result<InvestigationResponse> {
        let selected: Option<(String, String, bool, String, String, Option<HostProfileSummary>)> =
            db.query_row(
            "SELECT d.host_id,d.deadline,d.finished,h.liveness_status,h.agent_version,h.profile_json
             FROM host_discovery d JOIN hosts h USING (host_id)
             WHERE d.host_id IN (SELECT value FROM json_each(?1))
               AND ((?2 IS NOT NULL AND d.host_id=?2)
                 OR (?2 IS NULL AND d.last_polled_at<?3 AND (d.finished=0 OR EXISTS (
                     SELECT 1 FROM host_discovery_watches w JOIN observations o
                     USING (host_id,watch_id,spec_version)
                     WHERE w.host_id=d.host_id AND w.collector IN (SELECT value FROM json_each(?4))
                       AND o.received_at<=d.deadline AND o.sample_json IS NOT NULL
                 ))))
             ORDER BY d.last_polled_at,d.host_id LIMIT 1",
            params![serde_json::to_string(&cap.allowed_hosts)?, host, stamp(now - Duration::seconds(5)), serde_json::to_string(&cap.allowed_collectors)?],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,optional_json(r,5)?)),
        ).optional()?;
        let Some((host, deadline, finished, liveness, agent_version, profile)) = selected else {
            return Ok(InvestigationResponse::HostDiscoveryAdvanced {
                host_id: None,
                bundle_version: None,
            });
        };
        if finished {
            db.execute(
                "UPDATE host_discovery SET last_polled_at=?2 WHERE host_id=?1",
                params![host, stamp(now)],
            )?;
            return Ok(InvestigationResponse::HostDiscoveryAdvanced {
                host_id: Some(host),
                bundle_version: None,
            });
        }

        let deadline = parse_stamp(&deadline, 1)?;
        let (policy, floor) = (self.policy(), &self.policy().edge_floor);
        let mut watches = active_watches(db, &host, now)?;
        let mut assessment = load(db, &host, None)?.ok_or_else(|| {
            crate::service::ControlError::missing("discovery assessment is missing")
        })?;
        let previous = assessment.collectors.clone();
        let mut issued = false;
        for entry in &mut assessment.collectors {
            // Refresh and schedule only collectors authorized by the caller.
            if !cap.allowed_collectors.contains(&entry.collector) || entry.evidence.is_some() {
                continue;
            }
            let collector = entry.collector.as_str();
            let watch: Option<(String, u32, String)> = db.query_row(
                "SELECT watch_id,spec_version,expires_at FROM host_discovery_watches WHERE host_id=?1 AND collector=?2",
                params![host, collector], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).optional()?;
            if let Some((id, version, _)) = &watch {
                entry.evidence = db
                    .query_row(
                        "SELECT observation_id,state_hash,status_json FROM observations
                     WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3 AND received_at<=?4
                     ORDER BY observation_id LIMIT 1",
                        params![host, id, version, stamp(deadline)],
                        |r| {
                            Ok(HostDiscoveryEvidence {
                                watch_id: id.clone(),
                                spec_version: *version,
                                observation_id: r.get(0)?,
                                state_hash: r.get(1)?,
                                status: json_column(r, 2)?,
                            })
                        },
                    )
                    .optional()?;
            }
            entry.gap = if let Some(evidence) = &entry.evidence {
                (evidence.status != ObservationStatus::Ok)
                    .then_some(HostDiscoveryGap::IncompleteSample)
            } else if now >= deadline {
                Some(HostDiscoveryGap::DeadlineElapsed)
            } else if liveness != "online" {
                Some(HostDiscoveryGap::AwaitingAgent)
            } else if !agent_version.ends_with(HOST_DISCOVERY_AGENT_SUFFIX) {
                Some(HostDiscoveryGap::AgentUnsupported)
            } else if !floor.allowed_collectors.contains(&entry.collector)
                || profile
                    .as_ref()
                    .is_some_and(|p| !p.enabled_collectors.contains(&entry.collector))
            {
                Some(HostDiscoveryGap::CollectorDisabled)
            } else if let Some((_, _, expiry)) = &watch {
                Some(if parse_stamp(expiry, 2)? <= now {
                    HostDiscoveryGap::SampleWindowElapsed
                } else {
                    HostDiscoveryGap::AwaitingSample
                })
            } else if watches.len() >= floor.max_watches_total
                || watches
                    .iter()
                    .filter(|w| w.class == WatchClass::Ephemeral)
                    .count()
                    >= floor
                        .max_ephemeral_watches
                        .min(policy.max_ephemeral_per_host)
            {
                Some(HostDiscoveryGap::AwaitingCapacity)
            } else {
                let expiry = deadline
                    .min(cap.expires_at)
                    .min(now + Duration::seconds(floor.max_ephemeral_ttl_seconds.min(120) as i64));
                let spec = spec(&host, entry.collector, floor, expiry);
                let bundle_denial = crate::service::bundle_collector_denial(
                    db,
                    &host,
                    watches
                        .iter()
                        .map(|w| w.collector.collector_type())
                        .chain([spec.collector.collector_type()]),
                )?;
                if bundle_denial.is_some() {
                    Some(HostDiscoveryGap::CollectorDisabled)
                } else if validate_watch_spec(&spec, floor, now).is_err()
                    || (expiry - now).num_seconds()
                        <= (spec.schedule.interval_seconds + spec.schedule.timeout_seconds) as i64
                {
                    Some(HostDiscoveryGap::AwaitingCapacity)
                } else {
                    insert_watch(db, &spec, &cap.principal_id, now)?;
                    db.execute(
                        "INSERT INTO host_discovery_watches (host_id,collector,watch_id,spec_version,expires_at,review_only)
                         VALUES (?1,?2,?3,?4,?5,EXISTS (
                             SELECT 1 FROM host_reviews r, json_each(r.config_json,'$.collectors') c
                             WHERE r.host_id=?1 AND r.status='pending' AND r.refresh_until>?6 AND c.value=?2
                         ))",
                        params![host, collector, spec.id, spec.version, stamp(expiry), stamp(now)],
                    )?;
                    watches.push(spec);
                    issued = true;
                    Some(HostDiscoveryGap::AwaitingSample)
                }
            };
        }
        let bundle_version = if issued {
            Some(self.issue_bundle(db, &host, &cap.principal_id, request, now)?)
        } else {
            None
        };
        if previous != assessment.collectors {
            assessment.version += 1;
            let finished = assessment.collectors.iter().all(|entry| {
                entry.evidence.is_some() || entry.gap == Some(HostDiscoveryGap::DeadlineElapsed)
            });
            save(db, &assessment, finished)?;
        }
        db.execute(
            "UPDATE host_discovery SET last_polled_at=?2 WHERE host_id=?1",
            params![host, stamp(now)],
        )?;
        Ok(InvestigationResponse::HostDiscoveryAdvanced {
            host_id: Some(host),
            bundle_version,
        })
    }
}

fn spec(
    host: &str,
    collector: CollectorType,
    floor: &defsec_policy::edge_floor::EdgeSafetyConfig,
    expires_at: DateTime<Utc>,
) -> WatchSpec {
    let collector = match collector {
        CollectorType::SocketsListening => {
            CollectorSpec::SocketsListening(SocketsListeningParams {
                include_tcp: true,
                include_udp: true,
                include_ipv6: true,
                resolve_process: false,
            })
        }
        CollectorType::PackagesInventory => {
            CollectorSpec::PackagesInventory(PackagesInventoryParams { max_packages: None })
        }
        _ => unreachable!("closed discovery collector catalog"),
    };
    WatchSpec {
        id: format!("discovery-{}", uuid()),
        version: 1,
        host_id: host.into(),
        class: WatchClass::Ephemeral,
        incident_id: None,
        collector,
        schedule: WatchSchedule {
            interval_seconds: floor.min_interval_seconds.max(2),
            timeout_seconds: floor.max_timeout_seconds.min(1),
        },
        trigger: TriggerPredicate::FieldChanged {
            compare_against: CompareTarget::LastObserved,
            fields: vec!["count".into()],
        },
        wake_policy: WakePolicy {
            cooldown_seconds: 60,
            max_wakeups_per_hour: 0,
        },
        lifecycle: WatchLifecycle {
            enabled: true,
            expires_at: Some(expires_at),
            max_runs: Some(1),
        },
    }
}

pub(crate) fn is_discovery_watch(db: &Connection, spec: &WatchSpec) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM discovery_watch_origins
         WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3)",
        params![spec.host_id, spec.id, spec.version],
        |r| r.get(0),
    )?)
}

pub(crate) fn retire_unsupported(db: &Connection, host: &str, now: DateTime<Utc>) -> Result<bool> {
    // An older agent can reconnect after an upgrade. Renew the signed bundle
    // without discovery watches before sending it to that agent.
    let mut retired = false;
    for spec in active_watches(db, host, now)? {
        if is_discovery_watch(db, &spec)? {
            db.execute(
                "UPDATE watch_state SET retired=1 WHERE host_id=?1 AND watch_id=?2 AND spec_version=?3",
                params![host, spec.id, spec.version],
            )?;
            retired = true;
        }
    }
    Ok(retired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_objective_is_saved_and_leaves_the_queue() {
        let dir = std::env::temp_dir().join(uuid());
        std::fs::create_dir(&dir).unwrap();
        let service = ControlService::open(&dir, "test", 1).unwrap();
        assert!(matches!(
            service.handle_admin_request(AdminRequest::EnrollHost {
                host_id: "edge".into(),
                agent_public_key_hex: None,
            }),
            AdminResponse::HostEnrolled { .. }
        ));
        let now = Utc::now() + Duration::days(2);
        let grant = ScopedCapability {
            principal_id: "worker".into(),
            role: PrincipalRole::Investigator,
            run_id: None,
            incident_id: None,
            may_spawn_runs: false,
            allowed_hosts: vec!["edge".into()],
            allowed_purposes: None,
            allowed_collectors: COLLECTORS.into(),
            expires_at: now + Duration::minutes(5),
        };
        service
            .transaction(|db| {
                assert_eq!(
                    service.advance_discovery(db, &grant, None, "test", now)?,
                    InvestigationResponse::HostDiscoveryAdvanced {
                        host_id: Some("edge".into()),
                        bundle_version: None,
                    }
                );
                let assessment = load(db, "edge", None)?.unwrap();
                assert_eq!(assessment.version, 2);
                assert!(assessment.collectors.iter().all(|entry| {
                    entry.evidence.is_none() && entry.gap == Some(HostDiscoveryGap::DeadlineElapsed)
                }));
                assert_eq!(
                    service.advance_discovery(
                        db,
                        &grant,
                        None,
                        "retry",
                        now + Duration::seconds(6)
                    )?,
                    InvestigationResponse::HostDiscoveryAdvanced {
                        host_id: None,
                        bundle_version: None,
                    }
                );
                Ok(())
            })
            .unwrap();
        drop(service);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
