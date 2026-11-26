ALTER TABLE host_reviews ADD COLUMN refresh_until TEXT;
ALTER TABLE host_reviews ADD COLUMN refresh_finalized INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_discovery_watches ADD COLUMN review_only INTEGER NOT NULL DEFAULT 0;
