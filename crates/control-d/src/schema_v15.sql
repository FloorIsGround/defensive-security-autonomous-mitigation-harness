-- Refresh replaces the current collector slot. Evidence from its earlier
-- watch revisions retains the original visibility for its entire lifetime.
CREATE TABLE discovery_watch_origins (
    host_id TEXT NOT NULL,
    watch_id TEXT NOT NULL,
    spec_version INTEGER NOT NULL,
    review_only INTEGER NOT NULL,
    PRIMARY KEY (host_id, watch_id, spec_version),
    FOREIGN KEY (host_id,watch_id,spec_version) REFERENCES watch_specs
);
INSERT INTO discovery_watch_origins SELECT host_id,watch_id,spec_version,review_only FROM host_discovery_watches;
INSERT OR IGNORE INTO discovery_watch_origins
SELECT w.host_id,w.watch_id,w.spec_version,1 FROM watch_specs w
WHERE w.watch_id GLOB 'discovery-*' AND json_extract(w.spec_json,'$.class')='ephemeral'
  AND w.incident_id IS NULL AND json_extract(w.spec_json,'$.lifecycle.max_runs')=1;
CREATE TRIGGER remember_discovery_origin AFTER INSERT ON host_discovery_watches BEGIN
    INSERT INTO discovery_watch_origins VALUES (new.host_id,new.watch_id,new.spec_version,new.review_only);
END;
