-- ndo4git schema v1
CREATE TABLE keys (
    id              INTEGER PRIMARY KEY,
    repo            TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    algo            TEXT    NOT NULL,
    public_key      TEXT    NOT NULL,
    private_key_enc BLOB    NOT NULL,
    nonce           BLOB    NOT NULL,
    fingerprint     TEXT    NOT NULL,
    can_write       INTEGER NOT NULL DEFAULT 0 CHECK (can_write IN (0, 1)),
    created_at      INTEGER NOT NULL,
    rotated_at      INTEGER,
    last_used_at    INTEGER,
    UNIQUE (repo, host)
);

CREATE TABLE key_history (
    id          INTEGER PRIMARY KEY,
    key_id      INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    repo        TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    algo        TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    can_write   INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    retired_at  INTEGER NOT NULL,
    reason      TEXT    NOT NULL
);
CREATE INDEX key_history_key_id ON key_history(key_id);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE aliases (
    alias      TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (alias, host)
);
