-- A reconciliation is bound to the exact receipt reviewed. Zero represents
-- an expired authorization whose executor never delivered a receipt.
CREATE TABLE action_reconciliations (
    intent_id TEXT NOT NULL REFERENCES action_intents,
    receipt_cursor INTEGER NOT NULL,
    evidence_ref TEXT NOT NULL,
    rationale TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (intent_id, receipt_cursor)
);
