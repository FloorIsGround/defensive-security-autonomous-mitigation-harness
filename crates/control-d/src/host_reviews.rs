use chrono::{DateTime, Duration, Utc};
use defsec_protocol::{canonical::sha256_hex, rpc::*};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use crate::{
    discovery,
    investigation::require_text,
    ledger::json_column,
    service::{ControlError, Result, parse_stamp, stamp, uuid},
};

pub(crate) fn configure(
    db: &Connection,
    mut schedule: HostReviewSchedule,
    now: DateTime<Utc>,
) -> Result<AdminResponse> {
    require_text(&schedule.question, "question", 2048)?;
    require_text(&schedule.route, "route", 128)?;
    crate::service::require_host(db, &schedule.host_id)?;
    schedule.collectors.sort_unstable();
    schedule.collectors.dedup();
    if !schedule
        .collectors
        .iter()
        .all(|collector| discovery::COLLECTORS.contains(collector))
    {
        return Err(ControlError::invalid(
            "host review collectors must come from host discovery",
        ));
    }
    if !(60..=2_592_000).contains(&schedule.interval_seconds) || schedule.collectors.is_empty() {
        return Err(ControlError::invalid(
            "invalid host review interval or collectors",
        ));
    }
    let previous: Option<HostReviewSchedule> = db
        .query_row(
            "SELECT config_json FROM host_review_schedules WHERE host_id=?1",
            [&schedule.host_id],
            |row| json_column(row, 0),
        )
        .optional()?;
    if previous.as_ref() != Some(&schedule) {
        discovery::enqueue(db, &schedule.host_id, now)?;
        cancel(db, &schedule.host_id)?;
        db.execute(
            "INSERT INTO host_review_schedules(host_id, config_json, route, next_due_at)
             VALUES (?1,?2,?3,?4)",
            params![
                schedule.host_id,
                serde_json::to_string(&schedule)?,
                schedule.route,
                stamp(now)
            ],
        )?;
    }
    Ok(AdminResponse::HostReviewScheduleUpdated {})
}

pub(crate) fn cancel(db: &Connection, host: &str) -> Result<AdminResponse> {
    db.execute(
        "UPDATE host_reviews SET status='cancelled', lease_hash=NULL, grant_hash=NULL, lease_until=NULL
         WHERE host_id=?1 AND status='pending'",
        [host],
    )?;
    db.execute("DELETE FROM host_review_schedules WHERE host_id=?1", [host])?;
    Ok(AdminResponse::HostReviewScheduleUpdated {})
}

pub(crate) fn latest(db: &Connection, host: &str) -> Result<AdminResponse> {
    crate::service::require_host(db, host)?;
    let review = db.query_row(
        "SELECT review_id, json_extract(config_json,'$.question'), assessment_version, completed_at,
                json_quote(json_extract(result_json,'$.interpretation')), json_extract(result_json,'$.summary'),COALESCE(json_extract(result_json,'$.citations'),'[]')
         FROM host_reviews WHERE host_id=?1 AND status='completed'
         ORDER BY completed_at DESC, review_id DESC LIMIT 1",
        [host],
        |row| Ok(HostReviewResult {
            review_id: row.get(0)?,
            question: row.get(1)?,
            assessment_version: row.get(2)?,
            completed_at: parse_stamp(&row.get::<_, String>(3)?, 3)?,
            interpretation: json_column(row, 4)?,
            summary: row.get(5)?,
            citations: json_column(row, 6)?,
        }),
    ).optional()?;
    Ok(AdminResponse::LatestHostReview { review })
}

pub(crate) struct Worker<'a> {
    pub db: &'a Connection,
    pub grant: &'a ScopedCapability,
    pub grant_hash: &'a str,
    pub now: DateTime<Utc>,
}

impl Worker<'_> {
    fn authorize(&self) -> Result<()> {
        if self.grant.role != PrincipalRole::Investigator
            || self.grant.run_id.is_some()
            || self.grant.incident_id.is_some()
            || !self.grant.may_spawn_runs
            || self.grant.expires_at <= self.now
        {
            return Err(ControlError::denied(
                "host reviews require a current unbound investigator grant with run-spawn permission",
            ));
        }
        Ok(())
    }

    pub(crate) fn claim(
        &self,
        service: &crate::ControlService,
        route: &str,
        lease_seconds: u32,
        request: &str,
        sources: Option<&[HostEvidenceScope]>,
    ) -> Result<InvestigationResponse> {
        self.authorize()?;
        require_text(route, "route", 128)?;
        if !(1..=900).contains(&lease_seconds) {
            return Err(ControlError::invalid(
                "lease_seconds must be within 1..=900",
            ));
        }
        let db = self.db;
        let now = stamp(self.now);
        db.execute(
            "UPDATE host_reviews SET status='expired', lease_hash=NULL, grant_hash=NULL, lease_until=NULL
             WHERE status='pending' AND expires_at<=?1",
            [&now],
        )?;
        let candidate = db
            .query_row(
                "SELECT s.config_json, COALESCE(r.due_at,s.next_due_at),
                    COALESCE(r.assessment_version,d.latest_version), r.review_id, r.expires_at, r.refresh_until, COALESCE(r.refresh_finalized,0)
             FROM host_review_schedules s
             JOIN host_discovery d USING(host_id)
             LEFT JOIN host_reviews r ON r.host_id=s.host_id AND r.status='pending'
             WHERE s.route=?1 AND s.host_id IN (SELECT value FROM json_each(?2))
               AND NOT EXISTS (
                   SELECT value FROM json_each(s.config_json,'$.collectors')
                   EXCEPT SELECT value FROM json_each(?3)
               )
               AND (?5 IS NULL OR EXISTS (SELECT 1 FROM json_each(?5) dest
                   WHERE json_extract(dest.value,'$.host_id')=s.host_id AND NOT EXISTS (
                       SELECT value FROM json_each(s.config_json,'$.collectors')
                       EXCEPT SELECT value FROM json_each(dest.value,'$.collectors'))))
               AND ((r.review_id IS NULL AND s.next_due_at<=?4)
                    OR (r.review_id IS NOT NULL AND
                        (r.lease_until<=?4 OR (r.lease_hash IS NOT NULL AND NOT EXISTS (
                            SELECT 1 FROM capability_tokens c
                            WHERE c.token_hash=r.grant_hash AND c.revoked_at IS NULL
                        )))))
             ORDER BY s.last_claimed_at, COALESCE(r.due_at,s.next_due_at), s.host_id LIMIT 1",
                params![
                    route,
                    serde_json::to_string(&self.grant.allowed_hosts)?,
                    serde_json::to_string(&self.grant.allowed_collectors)?,
                    now,
                    sources.map(serde_json::to_string).transpose()?
                ],
                |row| {
                    Ok((
                        json_column::<HostReviewSchedule>(row, 0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((schedule, due, version, existing_id, expiry, refresh_until, refresh_finalized)) =
            candidate
        else {
            return Ok(InvestigationResponse::HostReviewClaimed {
                lease: None,
                bundle_version: None,
            });
        };
        let deadline = expiry
            .as_deref()
            .map(|value| parse_stamp(value, 4))
            .transpose()?
            .unwrap_or(
                self.now + Duration::seconds(i64::from(schedule.interval_seconds.min(86_400))),
            );
        let review_id = if let Some(id) = existing_id {
            id
        } else {
            let id = uuid();
            db.execute(
                "INSERT INTO host_reviews(review_id, host_id, config_json, due_at, expires_at, assessment_version, status)
                 VALUES (?1,?2,?3,?4,?5,?6,'pending')",
                params![id, schedule.host_id, serde_json::to_string(&schedule)?, due, stamp(deadline), version],
            )?;
            db.execute(
                "UPDATE host_review_schedules SET next_due_at=?2 WHERE host_id=?1",
                params![
                    schedule.host_id,
                    stamp(self.now + Duration::seconds(i64::from(schedule.interval_seconds)))
                ],
            )?;
            id
        };
        let updating = refresh_until.is_some() && !refresh_finalized;
        let mut bundle_version = None;
        if updating {
            let mut grant = (*self.grant).clone();
            grant.allowed_collectors.clone_from(&schedule.collectors);
            if let InvestigationResponse::HostDiscoveryAdvanced {
                bundle_version: issued,
                ..
            } =
                service.advance_discovery(db, &grant, Some(&schedule.host_id), request, self.now)?
            {
                bundle_version = issued;
            }
        }
        let mut assessment =
            discovery::load(db, &schedule.host_id, (!updating).then_some(version))?
                .ok_or_else(|| ControlError::missing("host review assessment is missing"))?;
        discovery::scope_assessment(&mut assessment, &schedule.collectors);
        let mut needs_fresh_evidence = false;
        let cutoff = stamp(self.now - Duration::seconds(i64::from(schedule.interval_seconds)));
        for entry in &assessment.collectors {
            let fresh = match &entry.evidence {
                Some(evidence) if entry.gap.is_none() => db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM observations WHERE observation_id=?1 AND observed_at BETWEEN ?2 AND ?3 AND received_at>=?2)",
                    params![evidence.observation_id, cutoff, now],
                    |row| row.get::<_, bool>(0),
                )?,
                _ => false,
            };
            needs_fresh_evidence |= !fresh;
        }
        let refreshing = updating
            && refresh_until
                .as_deref()
                .is_some_and(|until| until > now.as_str())
            && needs_fresh_evidence;
        if updating {
            db.execute(
                "UPDATE host_reviews SET assessment_version=?2,refresh_finalized=?3 WHERE review_id=?1",
                params![review_id, assessment.version, !refreshing],
            )?;
        }
        let expires_at = deadline
            .min(self.grant.expires_at)
            .min(self.now + Duration::seconds(i64::from(lease_seconds)));
        let lease_token = uuid();
        db.execute(
            "UPDATE host_reviews SET lease_hash=?2, grant_hash=?3, lease_until=?4 WHERE review_id=?1",
            params![review_id, sha256_hex(lease_token.as_bytes()), self.grant_hash, stamp(expires_at)],
        )?;
        db.execute(
            "UPDATE host_review_schedules SET last_claimed_at=?2 WHERE host_id=?1",
            params![schedule.host_id, now],
        )?;
        Ok(InvestigationResponse::HostReviewClaimed {
            lease: Some(HostReviewLease {
                review_id,
                lease_token,
                host_id: schedule.host_id,
                question: schedule.question,
                due_at: parse_stamp(&due, 1)?,
                expires_at,
                needs_fresh_evidence: needs_fresh_evidence && refresh_until.is_none(),
                refreshing,
                assessment,
            }),
            bundle_version,
        })
    }

    pub(crate) fn samples(&self, id: &str, token: &str) -> Result<InvestigationResponse> {
        self.authorize()?;
        require_text(id, "review_id", 128)?;
        require_text(token, "lease_token", 128)?;
        let (schedule, version): (HostReviewSchedule, u32) = self
            .db
            .query_row(
                "SELECT config_json,assessment_version FROM host_reviews
             WHERE review_id=?1 AND lease_hash=?2 AND grant_hash=?3
               AND status='pending' AND lease_until>?4",
                params![
                    id,
                    sha256_hex(token.as_bytes()),
                    self.grant_hash,
                    stamp(self.now)
                ],
                |row| Ok((json_column(row, 0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| ControlError::denied("host review lease is unavailable"))?;
        if !self.grant.allowed_hosts.contains(&schedule.host_id)
            || !schedule
                .collectors
                .iter()
                .all(|c| self.grant.allowed_collectors.contains(c))
        {
            return Err(ControlError::denied(
                "host review is outside the current grant",
            ));
        }
        let mut grant = (*self.grant).clone();
        grant.allowed_collectors = schedule.collectors;
        Ok(InvestigationResponse::HostDiscoverySamples {
            samples: discovery::samples(self.db, &grant, &schedule.host_id, Some(version))?,
        })
    }

    pub(crate) fn refresh(
        &self,
        service: &crate::ControlService,
        id: &str,
        token: &str,
        request: &str,
    ) -> Result<InvestigationResponse> {
        self.authorize()?;
        require_text(id, "review_id", 128)?;
        require_text(token, "lease_token", 128)?;
        let now = stamp(self.now);
        let (schedule, expires, refresh): (HostReviewSchedule, String, Option<String>) = self
            .db
            .query_row(
                "SELECT config_json,expires_at,refresh_until FROM host_reviews
                 WHERE review_id=?1 AND lease_hash=?2 AND grant_hash=?3
                   AND status='pending' AND lease_until>?4 AND refresh_finalized=0",
                params![id, sha256_hex(token.as_bytes()), self.grant_hash, now],
                |row| Ok((json_column(row, 0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| ControlError::denied("host review lease is unavailable"))?;
        if !self.grant.allowed_hosts.contains(&schedule.host_id)
            || !schedule
                .collectors
                .iter()
                .all(|c| self.grant.allowed_collectors.contains(c))
        {
            return Err(ControlError::denied(
                "host review is outside the current grant",
            ));
        }
        let deadline = if let Some(refresh) = refresh {
            parse_stamp(&refresh, 2)?
        } else {
            let deadline = (self.now + Duration::seconds(30))
                .min(parse_stamp(&expires, 1)? - Duration::seconds(10));
            if deadline <= self.now {
                return Ok(InvestigationResponse::HostReviewRefreshed {
                    deferred: false,
                    bundle_version: None,
                });
            }
            discovery::refresh(self.db, &schedule.host_id, &schedule.collectors, deadline)?;
            self.db.execute(
                "UPDATE host_reviews SET refresh_until=?2 WHERE review_id=?1",
                params![id, stamp(deadline)],
            )?;
            deadline
        };
        let mut grant = (*self.grant).clone();
        grant.allowed_collectors = schedule.collectors;
        let InvestigationResponse::HostDiscoveryAdvanced { bundle_version, .. } = service
            .advance_discovery(self.db, &grant, Some(&schedule.host_id), request, self.now)?
        else {
            unreachable!("discovery advance returns its bundle status")
        };
        self.db.execute(
            "UPDATE host_reviews SET lease_hash=NULL,grant_hash=NULL,lease_until=?2 WHERE review_id=?1",
            params![id, stamp((self.now + Duration::seconds(2)).min(deadline))],
        )?;
        Ok(InvestigationResponse::HostReviewRefreshed {
            deferred: true,
            bundle_version,
        })
    }

    pub(crate) fn complete(
        &self,
        id: &str,
        token: &str,
        interpretation: EvidenceInterpretation,
        summary: &str,
        citations: &[i64],
    ) -> Result<InvestigationResponse> {
        self.authorize()?;
        require_text(id, "review_id", 128)?;
        require_text(token, "lease_token", 128)?;
        require_text(summary, "summary", 4096)?;
        if summary.contains(token) {
            return Err(ControlError::invalid(
                "summary contains the lease credential",
            ));
        }
        if citations.len() > discovery::COLLECTORS.len()
            || (interpretation != EvidenceInterpretation::Unresolved && citations.is_empty()) {
            return Err(ControlError::invalid("a determinate review must cite a pinned sample"));
        }
        let mut result = json!({"interpretation": interpretation, "summary": summary});
        if !citations.is_empty() {
            result["citations"] = json!(citations);
        }
        let result = result.to_string();
        let now = stamp(self.now);
        let (schedule, completed): (HostReviewSchedule, bool) = self.db.query_row(
            "SELECT config_json,status='completed' FROM host_reviews
             WHERE review_id=?1 AND lease_hash=?2 AND grant_hash=?3
               AND ((status='pending' AND lease_until>?4) OR (status='completed' AND result_json=?5))",
            params![id, sha256_hex(token.as_bytes()), self.grant_hash, now, result],
            |row| Ok((json_column(row, 0)?, row.get(1)?)),
        ).optional()?.ok_or_else(|| ControlError::denied("host review lease is unavailable"))?;
        if !self.grant.allowed_hosts.contains(&schedule.host_id)
            || !schedule
                .collectors
                .iter()
                .all(|collector| self.grant.allowed_collectors.contains(collector))
        {
            return Err(ControlError::denied(
                "host review is outside the current grant",
            ));
        }
        if !completed {
            if !citations.is_empty() {
                let InvestigationResponse::HostDiscoverySamples { samples } = self.samples(id, token)? else { unreachable!() };
                if citations.iter().enumerate().any(|(index, citation)| citations[..index].contains(citation)
                    || !samples.iter().any(|s| s.evidence.observation_id == *citation && s.evidence.status == defsec_protocol::observation::ObservationStatus::Ok)) {
                    return Err(ControlError::invalid("review cites unavailable or incomplete evidence"));
                }
            }
            self.db.execute(
                "UPDATE host_reviews SET status='completed', result_json=?2, completed_at=?3 WHERE review_id=?1",
                params![id, result, now],
            )?;
        }
        Ok(InvestigationResponse::HostReviewCompleted {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlService;
    use defsec_protocol::watch::CollectorType::{PackagesInventory, SocketsListening};

    fn mint(
        service: &ControlService,
        principal: &str,
        collectors: Vec<defsec_protocol::watch::CollectorType>,
    ) -> String {
        let AdminResponse::TokenMinted { token, .. } =
            service.handle_admin_request(AdminRequest::MintCapabilityToken {
                principal_id: principal.into(),
                role: PrincipalRole::Investigator,
                allowed_hosts: vec!["quiet".into()],
                allowed_purposes: None,
                allowed_collectors: collectors,
                may_spawn_runs: true,
                incident_id: None,
                ttl_seconds: 3600,
            })
        else {
            panic!("mint investigator grant")
        };
        token
    }

    fn call(
        service: &ControlService,
        token: &str,
        request: InvestigationRequest,
    ) -> InvestigationResponse {
        service.handle_investigation_call(InvestigationCall {
            request_id: uuid(),
            capability_token: token.into(),
            request,
        })
    }

    fn claim(service: &ControlService, token: &str) -> Option<HostReviewLease> {
        let response = call(
            service,
            token,
            InvestigationRequest::ClaimHostReview {
                allowed_sources: None,
                route: "supervisory".into(),
                lease_seconds: 60,
            },
        );
        let InvestigationResponse::HostReviewClaimed { lease, .. } = response else {
            panic!("unexpected claim response {response:?}");
        };
        lease
    }

    fn complete(
        service: &ControlService,
        token: &str,
        lease: &HostReviewLease,
    ) -> InvestigationResponse {
        call(
            service,
            token,
            InvestigationRequest::CompleteHostReview {
                review_id: lease.review_id.clone(),
                lease_token: lease.lease_token.clone(),
                interpretation: EvidenceInterpretation::Unresolved,
                citations: vec![],
                summary: "Quiet host has incomplete discovery coverage.".into(),
            },
        )
    }

    #[test]
    fn quiet_review_recovers_after_outage_without_blocking_reactive_work() {
        let dir = std::env::temp_dir().join(uuid());
        std::fs::create_dir(&dir).unwrap();
        let service = ControlService::open(&dir, "test", 1).unwrap();
        assert!(matches!(
            service.handle_admin_request(AdminRequest::EnrollHost {
                host_id: "quiet".into(),
                agent_public_key_hex: None,
            }),
            AdminResponse::HostEnrolled { .. }
        ));
        let schedule = HostReviewSchedule {
            host_id: "quiet".into(),
            interval_seconds: 300,
            route: "supervisory".into(),
            question: "What visibility gaps remain?".into(),
            collectors: vec![SocketsListening, PackagesInventory],
        };
        assert_eq!(
            service.handle_admin_request(AdminRequest::SetHostReviewSchedule {
                schedule: schedule.clone()
            }),
            AdminResponse::HostReviewScheduleUpdated {}
        );
        let original = mint(&service, "original", schedule.collectors.clone());
        let first = std::thread::scope(|scope| {
            let a = scope.spawn(|| claim(&service, &original));
            let b = scope.spawn(|| claim(&service, &original));
            let leases = [a.join().unwrap(), b.join().unwrap()];
            assert_eq!(leases.iter().flatten().count(), 1);
            leases.into_iter().flatten().next().unwrap()
        });
        assert_eq!(first.question, schedule.question);
        assert!(
            first
                .assessment
                .collectors
                .iter()
                .all(|coverage| coverage.evidence.is_none())
        );
        assert_eq!(
            service.handle_admin_request(AdminRequest::SetHostReviewSchedule {
                schedule: schedule.clone()
            }),
            AdminResponse::HostReviewScheduleUpdated {}
        );
        assert!(claim(&service, &original).is_none());

        // An independent incident arrives while the first review is outstanding.
        service.transaction(|db| {
            db.execute_batch(
                "INSERT INTO incidents(incident_id,host_id,status,priority_json,summary,created_at,updated_at)
                 VALUES ('incident','quiet','open','\"medium\"','test','','');
                 INSERT INTO watch_specs(host_id,watch_id,spec_version,spec_json,creator,active,created_at)
                 VALUES ('quiet','watch',1,'{\"collector\":{\"type\":\"sockets.listening\"}}','test',1,'');
                 INSERT INTO trigger_events(incident_id,host_id,watch_id,spec_version,fingerprint,created_at,updated_at,status,outcome_json)
                 VALUES ('incident','quiet','watch',1,'test','','','pending','{}');",
            )?;
            // Simulate an outage past the lease duration without waiting in real time.
            db.execute("UPDATE host_reviews SET lease_until=?1", [stamp(Utc::now() - Duration::seconds(1))])?;
            Ok(())
        }).unwrap();
        drop(service);

        let service = ControlService::open(&dir, "test", 1).unwrap();
        assert!(matches!(
            call(
                &service,
                &original,
                InvestigationRequest::LeaseNextTrigger {
                    lease_owner: "reactive".into(),
                    lease_seconds: 60,
                }
            ),
            InvestigationResponse::TriggerLeased { lease: Some(_) }
        ));
        let narrower = mint(&service, "narrower", vec![SocketsListening]);
        assert!(claim(&service, &narrower).is_none());
        assert!(matches!(
            complete(&service, &narrower, &first),
            InvestigationResponse::Error { .. }
        ));

        let successor = mint(&service, "successor", schedule.collectors.clone());
        let resumed = claim(&service, &successor).unwrap();
        assert_eq!(resumed.review_id, first.review_id);
        assert_eq!(resumed.assessment, first.assessment);
        assert_ne!(resumed.lease_token, first.lease_token);
        assert!(matches!(
            complete(&service, &original, &first),
            InvestigationResponse::Error { .. }
        ));
        for _ in 0..2 {
            assert_eq!(
                complete(&service, &successor, &resumed),
                InvestigationResponse::HostReviewCompleted {}
            );
        }
        let AdminResponse::LatestHostReview {
            review: Some(review),
        } = service.handle_admin_request(AdminRequest::GetLatestHostReview {
            host_id: "quiet".into(),
        })
        else {
            panic!("latest result missing")
        };
        assert_eq!(review.review_id, resumed.review_id);
        assert_eq!(review.assessment_version, resumed.assessment.version);
        assert_eq!(review.interpretation, EvidenceInterpretation::Unresolved);
        assert!(claim(&service, &successor).is_none());

        let report_profile = |tags: Vec<&str>| {
            use defsec_protocol::{
                profile::HostProfileSummary,
                wire::{AgentToControl, ControlToAgent, WIRE_PROTOCOL_VERSION},
            };
            let replies = service.handle_agent_message(AgentToControl::Register {
                protocol_version: WIRE_PROTOCOL_VERSION,
                host_id: "quiet".into(),
                agent_version: "test+host-discovery-v1".into(),
                boot_id: "review-test".into(),
                session_id: "review-test".into(),
                active_bundle_version: 0,
                active_bundle_digest: None,
                sent_at: Utc::now(),
                host_profile: Some(HostProfileSummary {
                    host_tags: tags.into_iter().map(str::to_owned).collect(),
                    expected_services: vec![],
                    enabled_collectors: schedule.collectors.clone(),
                }),
            });
            assert!(matches!(
                replies.first(),
                Some(ControlToAgent::RegisterAck { accepted: true, .. })
            ));
        };
        report_profile(vec!["production"]);
        report_profile(vec!["production", "edge"]);
        let profile_review = claim(&service, &successor).unwrap();
        assert_eq!(profile_review.question, schedule.question);
        assert_eq!(
            complete(&service, &successor, &profile_review),
            InvestigationResponse::HostReviewCompleted {}
        );
        report_profile(vec!["edge", "production"]);
        assert!(claim(&service, &successor).is_none());

        service
            .transaction(|db| {
                assert_eq!(
                    db.query_row(
                        "SELECT COUNT(*) FROM host_reviews WHERE status='completed'",
                        [],
                        |r| r.get::<_, u32>(0)
                    )?,
                    2
                );
                db.execute(
                    "UPDATE host_review_schedules SET next_due_at=?1",
                    [stamp(Utc::now() - Duration::seconds(1))],
                )?;
                Ok(())
            })
            .unwrap();
        let next = claim(&service, &successor).unwrap();
        assert_ne!(next.review_id, first.review_id);
        service
            .transaction(|db| {
                let elapsed = stamp(Utc::now() - Duration::seconds(1));
                db.execute(
                    "UPDATE host_reviews SET expires_at=?2, lease_until=?2 WHERE review_id=?1",
                    params![next.review_id, elapsed],
                )?;
                db.execute(
                    "UPDATE host_review_schedules SET next_due_at=?1",
                    [&elapsed],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            complete(&service, &successor, &next),
            InvestigationResponse::Error { .. }
        ));
        let replacement = claim(&service, &successor).unwrap();
        assert_ne!(replacement.review_id, next.review_id);
        assert_eq!(
            service.handle_admin_request(AdminRequest::CancelHostReviewSchedule {
                host_id: "quiet".into(),
            }),
            AdminResponse::HostReviewScheduleUpdated {}
        );
        assert!(matches!(
            complete(&service, &successor, &replacement),
            InvestigationResponse::Error { .. }
        ));
        assert!(claim(&service, &successor).is_none());
        drop(service);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
