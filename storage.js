const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

function nowIso() {
  return new Date().toISOString();
}

function safeParse(json, fallback) {
  if (json === null || json === undefined) return fallback;
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

class DataStore {
  constructor(options) {
    const opts = options || {};
    this.dbFile = path.resolve(String(opts.dbFile || "mt.sqlite"));
    this.legacyJsonFile = opts.legacyJsonFile ? path.resolve(String(opts.legacyJsonFile)) : null;
    this.collections = Array.isArray(opts.collections) ? [...new Set(opts.collections)] : [];

    const dir = path.dirname(this.dbFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.db = new DatabaseSync(this.dbFile);
    this._configure();
    this._migrate();
  }

  _configure() {
    this.db.exec("PRAGMA journal_mode=WAL;");
    this.db.exec("PRAGMA synchronous=NORMAL;");
    this.db.exec("PRAGMA foreign_keys=ON;");
    this.db.exec("PRAGMA busy_timeout=5000;");
  }

  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS kv_store (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS entity_rows (
        collection TEXT NOT NULL,
        id TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (collection, id)
      );
      CREATE INDEX IF NOT EXISTS idx_entity_rows_collection ON entity_rows(collection);
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        actor_user_id TEXT,
        actor_name TEXT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        before_json TEXT,
        after_json TEXT,
        meta_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_user_id, ts DESC);
    `);
  }

  _runTx(work) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = work();
      this.db.exec("COMMIT");
      return out;
    } catch (err) {
      try { this.db.exec("ROLLBACK"); } catch {}
      throw err;
    }
  }

  _getMetaRaw(key) {
    const row = this.db.prepare("SELECT value FROM kv_store WHERE key=?").get(key);
    return row ? row.value : null;
  }

  _setMetaRawTx(key, value) {
    const ts = nowIso();
    this.db.prepare(`
      INSERT INTO kv_store(key,value,updated_at) VALUES(?,?,?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    `).run(key, value, ts);
  }

  _getStateVersionTx() {
    const raw = this._getMetaRaw("stateVersion");
    const parsed = safeParse(raw, 1);
    return Number.isFinite(Number(parsed)) ? Number(parsed) : 1;
  }

  _setStateVersionTx(version) {
    this._setMetaRawTx("stateVersion", JSON.stringify(Number(version) || 1));
  }

  _bumpStateVersionTx() {
    const next = this._getStateVersionTx() + 1;
    this._setStateVersionTx(next);
    return next;
  }

  _insertAuditTx(audit) {
    const a = audit || {};
    this.db.prepare(`
      INSERT INTO audit_log(
        id, ts, actor_user_id, actor_name, action, entity_type, entity_id, before_json, after_json, meta_json
      ) VALUES(?,?,?,?,?,?,?,?,?,?)
    `).run(
      crypto.randomUUID(),
      String(a.ts || nowIso()),
      a.actorUserId ? String(a.actorUserId) : null,
      a.actorName ? String(a.actorName) : null,
      String(a.action || "update"),
      String(a.entityType || "unknown"),
      a.entityId ? String(a.entityId) : null,
      a.before === undefined ? null : JSON.stringify(a.before),
      a.after === undefined ? null : JSON.stringify(a.after),
      a.meta === undefined ? null : JSON.stringify(a.meta),
    );
  }

  _normalizeState(seed) {
    const base = deepClone(seed || {});
    for (const c of this.collections) {
      if (!Array.isArray(base[c])) base[c] = [];
    }
    if (!base.userPerms || typeof base.userPerms !== "object" || Array.isArray(base.userPerms)) base.userPerms = {};
    if (!base.uploadFiles || typeof base.uploadFiles !== "object" || Array.isArray(base.uploadFiles)) base.uploadFiles = {};
    if (!base.parasutConfig || typeof base.parasutConfig !== "object" || Array.isArray(base.parasutConfig)) {
      base.parasutConfig = { clientId: "", clientSecret: "", companyId: "" };
    }
    base._version = Number(base._version || 1);
    base._createdAt = String(base._createdAt || nowIso());
    return base;
  }

  _readLegacyOrSeed(seedState) {
    if (!this.legacyJsonFile || !fs.existsSync(this.legacyJsonFile)) {
      return this._normalizeState(seedState);
    }
    try {
      const raw = fs.readFileSync(this.legacyJsonFile, "utf8");
      const parsed = JSON.parse(raw);
      return this._normalizeState({ ...(seedState || {}), ...(parsed || {}) });
    } catch {
      return this._normalizeState(seedState);
    }
  }

  init(seedState) {
    const initializedAt = safeParse(this._getMetaRaw("initializedAt"), null);
    if (initializedAt) return;
    const source = this._readLegacyOrSeed(seedState);
    this.importState(source, {
      actor: { id: "system", name: "Sistem" },
      reason: "initial-import",
      skipAudit: true,
    });
    this._runTx(() => {
      this._setMetaRawTx("initializedAt", JSON.stringify(nowIso()));
    });
  }

  importState(state, options) {
    const opts = options || {};
    const normalized = this._normalizeState(state);
    const actor = opts.actor || { id: "system", name: "Sistem" };
    const reason = String(opts.reason || "import");
    const skipAudit = !!opts.skipAudit;

    const stamp = nowIso();
    const rows = [];
    for (const collection of this.collections) {
      const arr = Array.isArray(normalized[collection]) ? normalized[collection] : [];
      for (const item of arr) {
        if (!item || typeof item !== "object") continue;
        const id = String(item.id || "").trim();
        if (!id) continue;
        rows.push({
          collection,
          id,
          data: JSON.stringify(item),
          ts: stamp,
        });
      }
    }

    this._runTx(() => {
      this.db.exec("DELETE FROM entity_rows");
      this.db.exec("DELETE FROM kv_store");
      this.db.exec("DELETE FROM audit_log");
      const insert = this.db.prepare(`
        INSERT INTO entity_rows(collection,id,version,data,created_at,updated_at)
        VALUES(?,?,?,?,?,?)
      `);
      for (const row of rows) {
        insert.run(row.collection, row.id, 1, row.data, row.ts, row.ts);
      }
      this._setMetaRawTx("userPerms", JSON.stringify(normalized.userPerms || {}));
      this._setMetaRawTx("uploadFiles", JSON.stringify(normalized.uploadFiles || {}));
      this._setMetaRawTx("parasutConfig", JSON.stringify(normalized.parasutConfig || { clientId: "", clientSecret: "", companyId: "" }));
      this._setMetaRawTx("createdAt", JSON.stringify(normalized._createdAt || stamp));
      this._setMetaRawTx("stateVersion", JSON.stringify(Number(normalized._version || 1)));
      this._setMetaRawTx("schemaVersion", JSON.stringify(1));
      if (!skipAudit) {
        this._insertAuditTx({
          actorUserId: actor.id,
          actorName: actor.name,
          action: "import_state",
          entityType: "system",
          entityId: "state",
          before: null,
          after: { collections: this.collections.length, rows: rows.length },
          meta: { reason },
        });
      }
    });
  }

  loadState(seedState) {
    const seed = this._normalizeState(seedState);
    const state = this._normalizeState(seed);
    for (const collection of this.collections) {
      state[collection] = this.getCollection(collection);
    }
    state.userPerms = this.getMeta("userPerms", state.userPerms || {});
    state.uploadFiles = this.getMeta("uploadFiles", state.uploadFiles || {});
    state.parasutConfig = this.getMeta("parasutConfig", state.parasutConfig || { clientId: "", clientSecret: "", companyId: "" });
    state._createdAt = String(this.getMeta("createdAt", state._createdAt || nowIso()));
    state._version = Number(this.getMeta("stateVersion", state._version || 1));
    return state;
  }

  getMeta(key, fallbackValue) {
    const raw = this._getMetaRaw(String(key));
    if (raw === null) return fallbackValue;
    return safeParse(raw, fallbackValue);
  }

  setMeta(key, value, options) {
    const k = String(key);
    const opts = options || {};
    const actor = opts.actor || { id: "system", name: "Sistem" };
    const reason = String(opts.reason || "meta-update");
    return this._runTx(() => {
      const before = this.getMeta(k, null);
      this._setMetaRawTx(k, JSON.stringify(value));
      const stateVersion = this._bumpStateVersionTx();
      this._insertAuditTx({
        actorUserId: actor.id,
        actorName: actor.name,
        action: "meta_update",
        entityType: `meta:${k}`,
        entityId: k,
        before,
        after: value,
        meta: { reason },
      });
      return stateVersion;
    });
  }

  getCollection(collection) {
    const rows = this.db.prepare(`
      SELECT data FROM entity_rows
      WHERE collection=?
      ORDER BY created_at ASC, id ASC
    `).all(String(collection));
    return rows.map((row) => safeParse(row.data, null)).filter(Boolean);
  }

  getItem(collection, id) {
    const row = this.db.prepare(`
      SELECT data, version, created_at, updated_at FROM entity_rows
      WHERE collection=? AND id=?
    `).get(String(collection), String(id));
    if (!row) return null;
    const payload = safeParse(row.data, null);
    if (!payload) return null;
    return { item: payload, version: Number(row.version), createdAt: row.created_at, updatedAt: row.updated_at };
  }

  createItem(collection, item, options) {
    const c = String(collection);
    const obj = deepClone(item || {});
    const id = String(obj.id || "").trim();
    if (!id) throw new Error("id gerekli");
    const opts = options || {};
    const actor = opts.actor || { id: "system", name: "Sistem" };
    const meta = opts.meta || {};
    const action = String(opts.action || "create");

    const ts = nowIso();
    return this._runTx(() => {
      const exists = this.db.prepare(`
        SELECT id FROM entity_rows WHERE collection=? AND id=?
      `).get(c, id);
      if (exists) throw new Error(`Kayıt zaten mevcut: ${id}`);
      this.db.prepare(`
        INSERT INTO entity_rows(collection,id,version,data,created_at,updated_at)
        VALUES(?,?,?,?,?,?)
      `).run(c, id, 1, JSON.stringify(obj), ts, ts);
      const stateVersion = this._bumpStateVersionTx();
      this._insertAuditTx({
        actorUserId: actor.id,
        actorName: actor.name,
        action,
        entityType: c,
        entityId: id,
        before: null,
        after: obj,
        meta,
      });
      return { item: obj, stateVersion, rowVersion: 1 };
    });
  }

  updateItem(collection, id, changes, options) {
    const c = String(collection);
    const key = String(id || "").trim();
    if (!key) throw new Error("id gerekli");
    const patch = deepClone(changes || {});
    delete patch.id;

    const opts = options || {};
    const actor = opts.actor || { id: "system", name: "Sistem" };
    const meta = opts.meta || {};
    const action = String(opts.action || "update");

    return this._runTx(() => {
      const row = this.db.prepare(`
        SELECT version, data FROM entity_rows WHERE collection=? AND id=?
      `).get(c, key);
      if (!row) throw new Error(`Kayıt bulunamadı: ${key}`);
      const before = safeParse(row.data, null);
      if (!before || typeof before !== "object") throw new Error("Kayıt bozuk");
      const after = { ...before, ...patch, id: key };
      const currentVersion = Number(row.version || 0);
      const nextVersion = currentVersion + 1;
      const ts = nowIso();
      const result = this.db.prepare(`
        UPDATE entity_rows
        SET data=?, version=?, updated_at=?
        WHERE collection=? AND id=? AND version=?
      `).run(JSON.stringify(after), nextVersion, ts, c, key, currentVersion);
      if (!result || result.changes !== 1) throw new Error("Versiyon çakışması");
      const stateVersion = this._bumpStateVersionTx();
      this._insertAuditTx({
        actorUserId: actor.id,
        actorName: actor.name,
        action,
        entityType: c,
        entityId: key,
        before,
        after,
        meta,
      });
      return { item: after, stateVersion, rowVersion: nextVersion };
    });
  }

  deleteItem(collection, id, options) {
    const c = String(collection);
    const key = String(id || "").trim();
    if (!key) throw new Error("id gerekli");
    const opts = options || {};
    const actor = opts.actor || { id: "system", name: "Sistem" };
    const meta = opts.meta || {};
    const action = String(opts.action || "delete");

    return this._runTx(() => {
      const row = this.db.prepare(`
        SELECT version, data FROM entity_rows WHERE collection=? AND id=?
      `).get(c, key);
      if (!row) throw new Error(`Kayıt bulunamadı: ${key}`);
      const before = safeParse(row.data, null);
      const currentVersion = Number(row.version || 0);
      const result = this.db.prepare(`
        DELETE FROM entity_rows WHERE collection=? AND id=? AND version=?
      `).run(c, key, currentVersion);
      if (!result || result.changes !== 1) throw new Error("Versiyon çakışması");
      const stateVersion = this._bumpStateVersionTx();
      this._insertAuditTx({
        actorUserId: actor.id,
        actorName: actor.name,
        action,
        entityType: c,
        entityId: key,
        before,
        after: null,
        meta,
      });
      return { item: before, stateVersion };
    });
  }

  listAudit(filters) {
    const f = filters || {};
    const where = [];
    const params = [];
    if (f.entityType) { where.push("entity_type = ?"); params.push(String(f.entityType)); }
    if (f.entityId) { where.push("entity_id = ?"); params.push(String(f.entityId)); }
    if (f.actorUserId) { where.push("actor_user_id = ?"); params.push(String(f.actorUserId)); }
    if (f.action) { where.push("action = ?"); params.push(String(f.action)); }
    if (f.fromTs) { where.push("ts >= ?"); params.push(String(f.fromTs)); }
    if (f.toTs) { where.push("ts <= ?"); params.push(String(f.toTs)); }
    const limit = Math.max(1, Math.min(1000, Number(f.limit || 100)));
    const offset = Math.max(0, Number(f.offset || 0));
    const sql = `
      SELECT id, ts, actor_user_id, actor_name, action, entity_type, entity_id, before_json, after_json, meta_json
      FROM audit_log
      ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY ts DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
    const rows = this.db.prepare(sql).all(...params);
    return rows.map((row) => ({
      id: row.id,
      ts: row.ts,
      actorUserId: row.actor_user_id,
      actorName: row.actor_name,
      action: row.action,
      entityType: row.entity_type,
      entityId: row.entity_id,
      before: safeParse(row.before_json, null),
      after: safeParse(row.after_json, null),
      meta: safeParse(row.meta_json, null),
    }));
  }

  backupTo(destFile) {
    const destination = path.resolve(String(destFile));
    const dir = path.dirname(destination);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    this.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    fs.copyFileSync(this.dbFile, destination);
  }

  close() {
    if (this.db) this.db.close();
  }
}

module.exports = { DataStore };
