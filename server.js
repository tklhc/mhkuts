const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const compression = require("compression");
const { DataStore } = require("./storage");
const { APPROVAL_TYPES, detectApprovalRequirements, computeSpcSummary } = require("./workflow-utils");


const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : ["http://localhost:3000", "http://127.0.0.1:3000"];

// ===========================================
// [FIX #4] PERSISTENT JWT SECRET
// ===========================================
const DATA_DIR = process.env.DATA_DIR || __dirname;
const SECRET_FILE = path.join(DATA_DIR, ".jwt-secret");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const DB_FILE = path.join(DATA_DIR, "mt.sqlite");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  try { if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, "utf8").trim(); } catch (e) { }
  const secret = crypto.randomBytes(64).toString("hex");
  try { fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 }); } catch (e) { console.warn("?? JWT secret dosyas yazlamad"); }
  return secret;
}
const JWT_SECRET = getJwtSecret();

// ===========================================
// [FIX #5] CORS  RESTRICTED
// ===========================================
const io = new Server(server, {
  cors: { origin: (origin, cb) => { if (!origin || ALLOWED_ORIGINS.includes(origin) || !IS_PROD) return cb(null, true); cb(new Error("CORS denied")); }, credentials: true },
  pingTimeout: 60000, pingInterval: 25000,
  maxHttpBufferSize: 5e6,
});

// ===========================================
// MIDDLEWARE
// ===========================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"], fontSrc: ["'self'", "fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:"], imgSrc: ["'self'", "data:", "blob:"],
    }
  }
}));
app.use(compression());
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());

// ===========================================
// [FIX #12] RATE LIMITING
// ===========================================
const rateLimiters = new Map();
function checkRate(ip, type, max, windowMs) {
  const now = Date.now(), key = `${type}:${ip}`;
  const r = rateLimiters.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++; rateLimiters.set(key, r);
  return r.count <= max;
}
function checkLoginRate(ip) { return checkRate(ip, "login", 5, 60000); }
function checkApiRate(ip) { return checkRate(ip, "api", 100, 60000); }
setInterval(() => { const now = Date.now(); rateLimiters.forEach((v, k) => { if (now > v.resetAt) rateLimiters.delete(k); }); }, 300000);

app.use("/api", (req, res, next) => {
  if (req.path === "/health") return next();
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkApiRate(ip)) return res.status(429).json({ error: "Çok fazla istek." });
  next();
});

app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

// ===========================================
// PERMISSIONS & ROLES
// ===========================================
const PERMISSIONS = {
  orders_view: "Siparişleri Görüntüle", orders_edit: "Sipariş Oluştur/Düzenle",
  orders_price: "Fiyat Bilgisi Görüntüle", workorders_view: "İş Emirlerini Görüntüle",
  workorders_edit: "İş Emri Düzenle", cutting_view: "Kesimi Görüntüle",
  cutting_edit: "Kesim İşlemleri", grinding_view: "Taşlamayı Görüntüle",
  grinding_edit: "Taşlama İşlemleri", planning_view: "Planlamayı Görüntüle",
  planning_edit: "Planlama Düzenle", production_view: "Üretimi Görüntüle",
  production_edit: "Üretim Başlat/Bitir", qc_view: "Kalite Kontrolü Görüntüle",
  qc_edit: "KK Onayı Ver", coating_view: "Kaplamayı Görüntüle",
  coating_edit: "Kaplama İşlemleri", shipping_view: "Sevkiyatı Görüntüle",
  shipping_edit: "Sevkiyat İşlemleri", stock_view: "Stok Görüntüle",
  stock_edit: "Stok Düzenle", purchasing_view: "Satın Almayı Görüntüle",
  purchasing_edit: "Satın Alma İşlemleri", machines_view: "Makinaları Görüntüle",
  operators_view: "Operatörleri Görüntüle", invoices_view: "Faturaları Görüntüle",
  invoices_edit: "Fatura İşlemleri", admin: "Yönetici (Tüm Yetkiler)",
};

const DEFAULT_ROLES = {
  admin: { label: "Yönetici", permissions: Object.keys(PERMISSIONS) },
  manager: { label: "Üretim Müdürü", permissions: ["orders_view", "orders_edit", "orders_price", "workorders_view", "workorders_edit", "cutting_view", "cutting_edit", "grinding_view", "grinding_edit", "planning_view", "planning_edit", "production_view", "production_edit", "qc_view", "qc_edit", "coating_view", "coating_edit", "shipping_view", "shipping_edit", "invoices_view", "invoices_edit", "stock_view", "stock_edit", "purchasing_view", "purchasing_edit", "machines_view", "operators_view"] },
  planner: { label: "Planlama Sorumlusu", permissions: ["orders_view", "workorders_view", "workorders_edit", "cutting_view", "grinding_view", "planning_view", "planning_edit", "production_view", "purchasing_view", "machines_view", "operators_view"] },
  operator: { label: "Operatör", permissions: ["orders_view", "workorders_view", "workorders_edit", "cutting_view", "cutting_edit", "grinding_view", "grinding_edit", "production_view", "production_edit", "qc_view", "qc_edit", "stock_view", "purchasing_view", "machines_view"] },
  viewer: { label: "İzleyici", permissions: ["orders_view", "workorders_view", "cutting_view", "grinding_view", "planning_view", "production_view", "qc_view", "coating_view", "shipping_view", "stock_view", "purchasing_view", "machines_view", "operators_view"] },
};

// [FIX #1] Socket handler  required permission mapping
const HANDLER_PERMISSIONS = {
  "orders:set": "orders_edit", "workOrders:set": "workorders_edit", "productionJobs:set": "production_edit",
  "machines:set": "admin", "operators:set": "admin", "barStock:set": "stock_edit",
  "coatingQueue:set": "coating_edit", "grindingQueue:set": "grinding_edit",
  "purchaseRequests:set": "purchasing_edit", "invoices:set": "invoices_edit",
};

// ===========================================
// [PHASE 2] DELTA HANDLER CONFIG
// ===========================================
const DELTA_COLLECTIONS = {
  orders: { key: "orders", perm: "orders_edit", schema: { required: ["customerName", "items"], types: { id: "string", items: "array" } } },
  workOrders: { key: "workOrders", perm: "workorders_edit", schema: { required: ["id", "orderId"], types: { id: "string" } } },
  productionJobs: { key: "productionJobs", perm: "production_edit", schema: { required: ["id", "woId"], types: { id: "string" } } },
  barStock: { key: "barStock", perm: "stock_edit", schema: { required: ["id"], types: { id: "string" } } },
  preCutStock: { key: "preCutStock", perm: "stock_edit", schema: { required: ["id"], types: { id: "string" } } },
  materialCodes: { key: "materialCodes", perm: "admin", schema: { required: ["id", "value"], types: { id: "string", value: "string" } } },
  coatingQueue: { key: "coatingQueue", perm: "coating_edit", schema: { required: ["id"], types: { id: "string" } } },
  grindingQueue: { key: "grindingQueue", perm: "grinding_edit", schema: { required: ["id"], types: { id: "string" } } },
  purchaseRequests: { key: "purchaseRequests", perm: "purchasing_edit", schema: { required: ["id"], types: { id: "string" } } },
  invoices: { key: "invoices", perm: "invoices_edit", schema: { required: ["id"], types: { id: "string" } } },
  traceLots: { key: "traceLots", perm: "production_edit", schema: { required: ["id", "lotNo"], types: { id: "string", lotNo: "string" } } },
  ncrs: { key: "ncrs", perm: "qc_edit", schema: { required: ["id", "title", "status"], types: { id: "string" } } },
  capas: { key: "capas", perm: "qc_edit", schema: { required: ["id", "ncrId", "status"], types: { id: "string" } } },
  spcSamples: { key: "spcSamples", perm: "qc_edit", schema: { required: ["id", "characteristic", "value"], types: { id: "string", characteristic: "string", value: "number" } } },
  machines: { key: "machines", perm: "admin", schema: { required: ["id", "name"], types: { id: "string" } } },
  operators: { key: "operators", perm: "admin", schema: { required: ["id", "name"], types: { id: "string" } } },
};

// [PHASE 2.3] Schema validation for single item
function validateItem(item, schema) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return "Kayıt nesne olmalıdır";
  for (const f of (schema.required || [])) {
    if (item[f] === undefined || item[f] === null || item[f] === "") return `Zorunlu alan eksik: ${f}`;
  }
  for (const [f, t] of Object.entries(schema.types || {})) {
    if (item[f] !== undefined) {
      if (t === "array" && !Array.isArray(item[f])) return `${f} bir dizi olmalıdır`;
      if (t !== "array" && typeof item[f] !== t) return `${f} tipi hatal (beklenen: ${t})`;
    }
  }
  if (String(item.id || "").length > 200) return "id ok uzun";
  return null;
}

// ===========================================
// DEFAULT DATA
// ===========================================
function createDefaultData() {
  const salt = bcrypt.genSaltSync(10);
  const pw = bcrypt.hashSync("1234", salt);
  return {
    users: [
      { id: "U1", name: "Taha", username: "taha", passwordHash: pw, role: "admin", avatar: "T", mustChangePassword: true },
      { id: "U2", name: "Ahmet Yılmaz", username: "ahmet", passwordHash: pw, role: "operator", avatar: "A", mustChangePassword: true },
      { id: "U3", name: "Mehmet Kaya", username: "mehmet", passwordHash: pw, role: "operator", avatar: "M", mustChangePassword: true },
      { id: "U4", name: "Fatma Demir", username: "fatma", passwordHash: pw, role: "manager", avatar: "F", mustChangePassword: true },
      { id: "U5", name: "Zeynep Acar", username: "zeynep", passwordHash: pw, role: "planner", avatar: "Z", mustChangePassword: true },
      { id: "U6", name: "Emre Şahin", username: "emre", passwordHash: pw, role: "viewer", avatar: "E", mustChangePassword: true },
    ],
    userPerms: {}, orders: [], workOrders: [], productionJobs: [],
    machines: [
      { id: "M1", name: "S20-1", type: "CNC", status: "active" }, { id: "M2", name: "S20-2", type: "CNC", status: "active" },
      { id: "M3", name: "S20-3", type: "CNC", status: "active" }, { id: "M4", name: "Studer Taşlama", type: "Taşlama", status: "active" },
      { id: "M5", name: "Lazer Markalama", type: "Lazer", status: "active" }, { id: "M6", name: "Kesim Tezgahı", type: "Kesim", status: "active" },
      { id: "M8", name: "S22-1", type: "CNC", status: "active" }, { id: "M9", name: "S22-2", type: "CNC", status: "active" },
      { id: "M10", name: "Saacke", type: "CNC", status: "active" },
    ],
    operators: [
      { id: "O1", name: "Ahmet Yılmaz", role: "CNC Operatör", shift: "Gündüz" },
      { id: "O2", name: "Mehmet Kaya", role: "CNC Operatör", shift: "Gündüz" },
      { id: "O3", name: "Ali Demir", role: "CNC Operatör", shift: "Gece" },
      { id: "O4", name: "Hasan Çelik", role: "Taşlamacı", shift: "Gündüz" },
      { id: "O5", name: "Veli Acar", role: "Kesimci", shift: "Gündüz" },
      { id: "O6", name: "Emre Şahin", role: "Lazer Operatör", shift: "Gündüz" },
    ],
    barStock: [], preCutStock: [], materialCodes: [], coatingQueue: [], grindingQueue: [], purchaseRequests: [], invoices: [],
    traceLots: [], ncrs: [], capas: [], spcSamples: [], approvalRequests: [],
    uploadFiles: {},
    parasutConfig: { clientId: "", clientSecret: "", companyId: "" },
    _version: 1, _createdAt: new Date().toISOString(),
  };
}

// ===========================================
// DATA PERSISTENCE  SQLite (Transaction + Row Versioning)
let DATA = null;

const PERSISTED_COLLECTIONS = [
  "users", "orders", "workOrders", "productionJobs", "machines", "operators",
  "barStock", "preCutStock", "materialCodes", "coatingQueue", "grindingQueue", "purchaseRequests", "invoices",
  "traceLots", "ncrs", "capas", "spcSamples", "approvalRequests",
];

const store = new DataStore({
  dbFile: DB_FILE,
  legacyJsonFile: DATA_FILE,
  collections: PERSISTED_COLLECTIONS,
});

function actorFromUser(user) {
  if (user && user.id) return { id: String(user.id), name: String(user.name || user.username || "Bilinmeyen") };
  return { id: "system", name: "Sistem" };
}

function normalizeLoadedState(state) {
  const seed = createDefaultData();
  const next = { ...seed, ...(state || {}) };
  for (const key of PERSISTED_COLLECTIONS) {
    if (!Array.isArray(next[key])) next[key] = [];
  }
  if (!next.userPerms || typeof next.userPerms !== "object" || Array.isArray(next.userPerms)) next.userPerms = {};
  if (!next.uploadFiles || typeof next.uploadFiles !== "object" || Array.isArray(next.uploadFiles)) next.uploadFiles = {};
  if (!next.parasutConfig || typeof next.parasutConfig !== "object" || Array.isArray(next.parasutConfig)) {
    next.parasutConfig = { clientId: "", clientSecret: "", companyId: "" };
  }
  next.parasutConfig.clientId = String(next.parasutConfig.clientId || "");
  next.parasutConfig.clientSecret = String(next.parasutConfig.clientSecret || "");
  next.parasutConfig.companyId = String(next.parasutConfig.companyId || "");
  next._version = Number(next._version || 1);
  next._createdAt = String(next._createdAt || new Date().toISOString());
  return next;
}

function updateStateVersion(version) {
  DATA._version = Number(version || DATA._version || 1);
}

function shallowChanges(before, after) {
  const b = before || {};
  const a = after || {};
  const out = {};
  const keys = new Set([...Object.keys(b), ...Object.keys(a)]);
  keys.forEach((key) => {
    if (key === "id") return;
    if (JSON.stringify(b[key]) !== JSON.stringify(a[key])) out[key] = a[key];
  });
  return out;
}

function persistMeta(key, value, user, reason) {
  const current = store.getMeta(key, null);
  if (JSON.stringify(current) === JSON.stringify(value)) return;
  const stateVersion = store.setMeta(key, value, {
    actor: actorFromUser(user),
    reason: reason || "meta-update",
  });
  updateStateVersion(stateVersion);
}

function dbInsert(collection, item, user, meta) {
  const result = store.createItem(collection, item, {
    actor: actorFromUser(user),
    meta: meta || {},
    action: "create",
  });
  updateStateVersion(result.stateVersion);
}

function dbUpdate(collection, id, changes, user, meta) {
  const result = store.updateItem(collection, id, changes, {
    actor: actorFromUser(user),
    meta: meta || {},
    action: "update",
  });
  updateStateVersion(result.stateVersion);
}

function dbDelete(collection, id, user, meta) {
  const result = store.deleteItem(collection, id, {
    actor: actorFromUser(user),
    meta: meta || {},
    action: "delete",
  });
  updateStateVersion(result.stateVersion);
}

function dbSyncCollection(collection, nextItems, user, reason) {
  const currentItems = store.getCollection(collection);
  const next = Array.isArray(nextItems) ? nextItems : [];
  const currentMap = new Map(currentItems.map((x) => [x.id, x]));
  const nextMap = new Map(next.map((x) => [x.id, x]));

  next.forEach((item) => {
    if (!item || typeof item !== "object") return;
    const id = String(item.id || "").trim();
    if (!id) return;
    const prev = currentMap.get(id);
    if (!prev) {
      dbInsert(collection, item, user, { reason: reason || "sync-collection" });
      return;
    }
    const changes = shallowChanges(prev, item);
    if (Object.keys(changes).length > 0) {
      dbUpdate(collection, id, changes, user, { reason: reason || "sync-collection" });
    }
  });

  currentItems.forEach((item) => {
    const id = String(item?.id || "").trim();
    if (!id) return;
    if (!nextMap.has(id)) {
      dbDelete(collection, id, user, { reason: reason || "sync-collection" });
    }
  });
}

function saveData(user, reason) {
  const actor = user || null;
  for (const collection of PERSISTED_COLLECTIONS) {
    dbSyncCollection(collection, DATA[collection] || [], actor, reason || "full-sync");
  }
  persistMeta("userPerms", DATA.userPerms || {}, actor, reason || "full-sync");
  persistMeta("uploadFiles", DATA.uploadFiles || {}, actor, reason || "full-sync");
  persistMeta("parasutConfig", DATA.parasutConfig || { clientId: "", clientSecret: "", companyId: "" }, actor, reason || "full-sync");
}

function saveDataSync(user, reason) {
  saveData(user, reason || "sync");
}

function dbVersionBump() {
  // Version is handled by transactional writes.
}

function loadData() {
  try {
    const defaults = createDefaultData();
    store.init(defaults);
    DATA = normalizeLoadedState(store.loadState(defaults));
    console.log("? Veri yklendi:", DB_FILE, " version:", DATA._version);
  } catch (e) {
    console.error("Veri ykleme hatas:", e.message);
    DATA = normalizeLoadedState(createDefaultData());
    store.importState(DATA, { actor: { id: "system", name: "Sistem" }, reason: "recovery-import", skipAudit: false });
    DATA = normalizeLoadedState(store.loadState(DATA));
  }
}

// AUTO-BACKUP
function createBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const backupPath = path.join(BACKUP_DIR, `mt-${stamp}.sqlite`);
    store.backupTo(backupPath);
    const files = fs.readdirSync(BACKUP_DIR).filter((f) => f.startsWith("mt-") && f.endsWith(".sqlite")).sort();
    while (files.length > 30) {
      fs.unlinkSync(path.join(BACKUP_DIR, files.shift()));
    }
  } catch (e) {
    console.error("Yedekleme hatas:", e.message);
  }
}
setInterval(createBackup, 6 * 60 * 60 * 1000);

// ===========================================
// AUTH HELPERS
// ===========================================
// [FIX #16] Token includes pwAt for revocation on password change
function createToken(user) { return jwt.sign({ id: user.id, username: user.username, role: user.role, pwAt: user.passwordChangedAt || 0 }, JWT_SECRET, { expiresIn: "7d" }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }

// [FIX #16] Reject tokens issued before password change
function getUser(decoded) {
  if (!decoded) return null;
  const user = DATA.users.find(u => u.id === decoded.id);
  if (!user) return null;
  if (user.passwordChangedAt && decoded.pwAt !== undefined && user.passwordChangedAt > decoded.pwAt) return null;
  return user;
}
function hasPerm(user, perm) {
  if (!user) return false;
  const perms = DATA.userPerms[user.id] || DEFAULT_ROLES[user.role]?.permissions || [];
  return perms.includes("admin") || perms.includes(perm);
}
function sanitizeUser(u) { const { passwordHash, ...safe } = u; return safe; }

// [FIX #15] Role-filtered state
// [PHASE 1] buildState devre dışı bırakıldı. Chunking yapıyoruz.
function filterOrdersPrices(canPrice, orders) {
  if (canPrice || !orders) return orders;
  return orders.map(o => ({ ...o, items: o.items.map(it => { const { unitPrice, ...rest } = it; return rest; }) }));
}

// [PHASE 2] Dashboard Istatistikleri
function computeDashboardStats(user) {
  const isOperatorRole = user?.role === "operator";
  const myOperatorId = user?.operatorId || null;
  const productionJobs = DATA.productionJobs || [];
  const workOrders = DATA.workOrders || [];
  const orders = DATA.orders || [];
  const machines = DATA.machines || [];
  const coatingQueue = DATA.coatingQueue || [];
  const grindingQueue = DATA.grindingQueue || [];
  const purchaseRequests = DATA.purchaseRequests || [];
  const operators = DATA.operators || [];

  const myJobs = isOperatorRole && myOperatorId ? productionJobs.filter(j => j.operatorId === myOperatorId) : productionJobs;
  const isMyWoItem = (it) => isOperatorRole ? it.operatorId === myOperatorId : true;
  const myWoItems = isOperatorRole && myOperatorId ? workOrders.flatMap(wo => wo.items.filter(it => isMyWoItem(it))) : workOrders.flatMap(wo => wo.items);

  const t = orders.length;
  const a = orders.filter(o => o.status !== "completed" && o.status !== "pending").length;
  const pend = orders.filter(o => o.status === "pending").length;
  const pr = orders.filter(o => o.orderType === "production").length;
  const bl = orders.filter(o => o.orderType === "bileme").length;
  const run = myJobs.filter(j => j.status === "running").length;

  const ml = machines.map(m => ({
    ...m,
    jobs: myJobs.filter(j => j.machineId === m.id && j.status !== "completed").length,
    done: myJobs.filter(j => j.machineId === m.id && j.status === "completed").length
  }));

  const cp = coatingQueue.filter(c => c.status === "sent").length;
  const cutting = workOrders.flatMap(wo => wo.items.filter(it => it.woStatus === "pending" || it.woStatus === "pending_stock")).length;
  const grindPend = workOrders.flatMap(wo => wo.items).filter(it => ["grinding", "grinding_dispatch", "grinding_shipped"].includes(it.woStatus)).length;
  const myActive = myJobs.filter(j => j.status !== "completed").length;
  const myDone = myJobs.filter(j => j.status === "completed").length;
  const myQc = myWoItems.filter(it => it.woStatus === "qc").length;
  const myAssigned = myJobs.filter(j => j.status === "assigned").length;
  const myRunning = myJobs.filter(j => j.status === "running").length;

  const now = new Date();
  const thisMonthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const allItems = workOrders.flatMap(wo => wo.items.map(it => ({ ...it, woId: wo.id, orderType: wo.orderType, customerName: wo.customerName, customerCode: wo.customerCode })));

  const completedJobs = productionJobs.filter(j => j.status === "completed");
  const completedThisMonth = completedJobs.filter(j => j.endTime && j.endTime >= thisMonthStart).length;
  const completedWosThisMonth = workOrders.filter(wo => wo.status === "completed" && wo.items.some(it => it.endTime && it.endTime >= thisMonthStart)).length;

  const jobsWithTime = completedJobs.filter(j => j.startTime && j.endTime);
  const avgProdMin = jobsWithTime.length > 0 ? Math.round(jobsWithTime.reduce((s, j) => s + (new Date(j.endTime) - new Date(j.startTime)) / 60000, 0) / jobsWithTime.length) : 0;

  const totalProduced = allItems.reduce((s, it) => s + (Number(it.qty) || 0), 0);
  const totalReject = allItems.reduce((s, it) => s + (Number(it.rejectQty) || 0), 0);
  const defectRate = totalProduced > 0 ? ((totalReject / totalProduced) * 100).toFixed(1) : 0;

  const stageMap = {};
  allItems.forEach(it => { const st = it.woStatus || "pending"; stageMap[st] = (stageMap[st] || 0) + 1; });
  const stageLabels = { pending: "Bekleyen", pending_stock: "Stok Bekl.", cut: "Kesildi", grinding: "Taşlamada", grinding_dispatch: "Taş. Sevk Bekl.", grinding_shipped: "Kares'te", assigned: "Atandı", running: "Üretimde", qc: "Kalite Kontrol", laser: "Lazer", coating_ready: "Kaplama Haz.", coating: "Kaplamada", shipping: "Sevkiyat", arge: "ARGE", completed: "Tamamlandı" };
  const stageColors = { pending: "#94a3b8", pending_stock: "#ef4444", cut: "#8b5cf6", grinding: "#d946ef", grinding_dispatch: "#d946ef", grinding_shipped: "#d946ef", assigned: "#f59e0b", running: "#3b82f6", qc: "#14b8a6", laser: "#a855f7", coating_ready: "#14b8a6", coating: "#06b6d4", shipping: "#f97316", arge: "#f59e0b", completed: "#10b981" };
  const stageDist = Object.entries(stageMap).map(([k, v]) => ({ key: k, label: stageLabels[k] || k, count: v, color: stageColors[k] || "#64748b" })).sort((a, b) => b.count - a.count);

  const machineUtil = machines.map(m => {
    const mJobs = productionJobs.filter(j => j.machineId === m.id);
    const mDone = mJobs.filter(j => j.status === "completed");
    const mActive = mJobs.filter(j => j.status === "running" || j.status === "assigned");
    const totalMin = mDone.filter(j => j.startTime && j.endTime).reduce((s, j) => s + (new Date(j.endTime) - new Date(j.startTime)) / 60000, 0);
    return { id: m.id, name: m.name, active: mActive.length, done: mDone.length, totalJobs: mJobs.length, totalMin: Math.round(totalMin) };
  });

  const custMap = {};
  orders.forEach(o => {
    const key = o.customerCode || o.customerName;
    if (!custMap[key]) custMap[key] = { name: o.customerName, code: o.customerCode, orders: 0, items: 0, completed: 0 };
    custMap[key].orders++; custMap[key].items += o.items.length;
    if (o.status === "completed") custMap[key].completed++;
  });
  const topCustomers = Object.values(custMap).sort((a, b) => b.orders - a.orders).slice(0, 6);

  const operatorPerf = operators.map(op => {
    const opJobs = completedJobs.filter(j => j.operatorId === op.id);
    const opMin = opJobs.filter(j => j.startTime && j.endTime).reduce((s, j) => s + (new Date(j.endTime) - new Date(j.startTime)) / 60000, 0);
    const opReject = allItems.filter(it => it.operatorId === op.id).reduce((s, it) => s + (Number(it.rejectQty) || 0), 0);
    return { id: op.id, name: op.name, completed: opJobs.length, totalMin: Math.round(opMin), avgMin: opJobs.length > 0 ? Math.round(opMin / opJobs.length) : 0, rejects: opReject };
  }).filter(op => op.completed > 0).sort((a, b) => b.completed - a.completed);

  const monthlyTrend = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const mStart = d.toISOString();
    const mEnd = new Date(d.getFullYear(), d.getMonth() + 1, 1).toISOString();
    const mName = d.toLocaleDateString("tr", { month: "short" });
    const created = orders.filter(o => o.date >= mStart && o.date < mEnd).length;
    const done = orders.filter(o => o.status === "completed" && workOrders.filter(wo => wo.orderId === o.id).some(wo => wo.items.some(it => it.endTime && it.endTime >= mStart && it.endTime < mEnd))).length;
    monthlyTrend.push({ month: mName, created, done });
  }

  return {
    total: t, active: a, pending: pend, production: pr, bileme: bl, running: run, machineLoad: ml, coatingPending: cp, cuttingPending: cutting, grindingPending: grindPend, purchasePending: purchaseRequests.filter(p => p.status !== "received").length, myActive, myDone, myQc, myAssigned, myRunning,
    completedThisMonth, completedWosThisMonth, avgProdMin, defectRate, totalReject, totalProduced,
    stageDist, machineUtil, topCustomers, operatorPerf, monthlyTrend
  };
}


// [FIX #11] Password complexity
function validatePassword(pw) {
  if (!pw || pw.length < 8) return "ifre en az 8 karakter olmalıdır";
  if (!/[A-Za-z]/.test(pw)) return "ifre en az bir harf iermelidir";
  if (!/[0-9]/.test(pw)) return "ifre en az bir rakam iermelidir";
  return null;
}

// [FIX #6] Data validation
function validateSocketData(key, data) {
  if (!Array.isArray(data)) return "Veri bir dizi olmal?d?r";
  const size = JSON.stringify(data).length;
  if (size > 4 * 1024 * 1024) return "Veri boyutu ?ok b?y?k (>4MB)";
  const limits = { orders: 10000, workOrders: 10000, productionJobs: 50000, machines: 100, operators: 200, barStock: 1000, coatingQueue: 10000, grindingQueue: 10000, purchaseRequests: 10000, invoices: 50000, traceLots: 100000, ncrs: 50000, capas: 50000, spcSamples: 500000, approvalRequests: 200000 };
  if (limits[key] && data.length > limits[key]) return `?Çok fazla kay?t (${data.length}>${limits[key]})`;
  return null;
}

function canUploadDocuments(user) {
  if (!user) return false;
  return ["admin", "orders_edit", "workorders_edit", "production_edit", "qc_edit", "coating_edit", "shipping_edit", "invoices_edit"].some(p => hasPerm(user, p));
}
function canViewDocuments(user) {
  if (!user) return false;
  return ["admin", "orders_view", "workorders_view", "production_view", "qc_view", "coating_view", "shipping_view", "stock_view", "invoices_view", "planning_view", "purchasing_view", "grinding_view", "cutting_view"].some(p => hasPerm(user, p));
}
function nextOrderId() {
  const year = new Date().getFullYear();
  const max = (DATA.orders || []).reduce((m, o) => {
    const mm = String((o && o.id) || "").match(/^SIP-(\d{4})-(\d+)$/);
    if (!mm) return m;
    if (Number(mm[1]) !== year) return m;
    return Math.max(m, Number(mm[2]) || 0);
  }, 0);
  return `SIP-${year}-${String(max + 1).padStart(3, "0")}`;
}

// ===========================================
function canRequestApproval(user) {
  if (!user) return false;
  return ["admin", "orders_edit", "workorders_edit", "qc_edit", "shipping_edit", "invoices_edit"].some((p) => hasPerm(user, p));
}

function canDecideApproval(user) {
  if (!user) return false;
  return ["admin", "manager"].includes(user.role) || hasPerm(user, "admin") || hasPerm(user, "qc_edit") || hasPerm(user, "invoices_edit") || hasPerm(user, "shipping_edit") || hasPerm(user, "orders_edit");
}

function buildApprovalId() {
  const y = new Date().getFullYear();
  return `APR-${y}-${crypto.randomBytes(4).toString("hex")}`;
}

function createApprovalRequest(input) {
  const payload = input || {};
  const user = payload.user || null;
  const req = {
    id: buildApprovalId(),
    type: String(payload.type || "generic"),
    entityType: String(payload.entityType || "unknown"),
    entityId: String(payload.entityId || ""),
    status: "pending",
    reason: String(payload.reason || "Onay gerekli"),
    requestedById: String(user?.id || "system"),
    requestedByName: String(user?.name || user?.username || "Sistem"),
    requestedAt: new Date().toISOString(),
    decidedById: null,
    decidedByName: null,
    decidedAt: null,
    decisionNote: null,
    consumedAt: null,
    consumedById: null,
    consumedByName: null,
    payload: payload.payload && typeof payload.payload === "object" ? payload.payload : {},
  };
  DATA.approvalRequests = [...(DATA.approvalRequests || []), req];
  dbInsert("approvalRequests", req, user, { reason: "approval-request" });
  io.emit("approvalRequests:created", req);
  return req;
}

function decideApprovalRequest(id, decision, note, user) {
  const key = String(id || "").trim();
  if (!key) throw new Error("Geçersiz onay id");
  const status = String(decision || "").toLowerCase();
  if (!["approved", "rejected"].includes(status)) throw new Error("Karar approved/rejected olmal");
  const idx = (DATA.approvalRequests || []).findIndex((x) => x.id === key);
  if (idx < 0) throw new Error(`Onay kayd bulunamad: ${key}`);

  const changes = {
    status,
    decidedById: user.id,
    decidedByName: user.name,
    decidedAt: new Date().toISOString(),
    decisionNote: String(note || ""),
  };
  DATA.approvalRequests[idx] = { ...DATA.approvalRequests[idx], ...changes };
  dbUpdate("approvalRequests", key, changes, user, { reason: "approval-decision" });
  io.emit("approvalRequests:patched", { id: key, changes });
  return DATA.approvalRequests[idx];
}
// REST API
// ===========================================
app.get("/api/health", (req, res) => res.json({ status: "ok", uptime: process.uptime(), connections: connectedUsers.size, version: DATA._version, db: "sqlite" }));

// Manuel backup tetikle (admin only)
app.post("/api/backup", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !hasPerm(user, "admin")) return res.status(403).json({ error: "Yetkisiz" });
  try { createBackup(); res.json({ ok: true, message: "Yedek alnd" }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ===========================================
// [PHASE 2.4] PDF UPLOAD  Multer tabanl dosya depolama
// base64 data.json'a gmlmesi yerine disk'e kaydedilir
// ===========================================
app.get("/api/audit", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !hasPerm(user, "admin")) return res.status(403).json({ error: "Yetkisiz" });

  const limit = Number(req.query.limit || 100);
  const offset = Number(req.query.offset || 0);
  const rows = store.listAudit({
    limit,
    offset,
    entityType: req.query.entityType,
    entityId: req.query.entityId,
    actorUserId: req.query.actorUserId,
    action: req.query.action,
    fromTs: req.query.from,
    toTs: req.query.to,
  });
  res.json({ rows, limit, offset });
});

app.get("/api/approvals", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !canRequestApproval(user)) return res.status(403).json({ error: "Yetkisiz" });

  const status = String(req.query.status || "").trim();
  const type = String(req.query.type || "").trim();
  const entityType = String(req.query.entityType || "").trim();
  const entityId = String(req.query.entityId || "").trim();

  let rows = [...(DATA.approvalRequests || [])];
  if (status) rows = rows.filter((r) => String(r.status || "") === status);
  if (type) rows = rows.filter((r) => String(r.type || "") === type);
  if (entityType) rows = rows.filter((r) => String(r.entityType || "") === entityType);
  if (entityId) rows = rows.filter((r) => String(r.entityId || "") === entityId);

  rows.sort((a, b) => String(b.requestedAt || "").localeCompare(String(a.requestedAt || "")));
  res.json({ rows });
});

app.post("/api/approvals/request", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !canRequestApproval(user)) return res.status(403).json({ error: "Yetkisiz" });

  const type = String(req.body?.type || "").trim();
  const entityType = String(req.body?.entityType || "").trim();
  const entityId = String(req.body?.entityId || "").trim();
  if (!type || !entityType || !entityId) {
    return res.status(400).json({ error: "type, entityType ve entityId zorunludur" });
  }

  const created = createApprovalRequest({
    type,
    entityType,
    entityId,
    reason: String(req.body?.reason || "Manuel onay talebi"),
    payload: req.body?.payload && typeof req.body.payload === "object" ? req.body.payload : {},
    user,
  });
  res.status(201).json({ ok: true, approval: created });
});

app.post("/api/approvals/:id/decision", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !canDecideApproval(user)) return res.status(403).json({ error: "Yetkisiz" });
  try {
    const approval = decideApprovalRequest(req.params.id, req.body?.decision, req.body?.note, user);
    res.json({ ok: true, approval });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get("/api/quality/spc", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !hasPerm(user, "qc_view")) return res.status(403).json({ error: "Yetkisiz" });

  let samples = Array.isArray(DATA.spcSamples) ? DATA.spcSamples : [];
  const characteristic = String(req.query.characteristic || "").trim();
  if (characteristic) {
    samples = samples.filter((x) => String(x.characteristic || "") === characteristic);
  }

  const summary = computeSpcSummary(samples);
  res.json({ characteristic: characteristic || null, summary, totalSamples: samples.length });
});

app.get("/api/quality/trace/:query", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || (!hasPerm(user, "qc_view") && !hasPerm(user, "production_view") && !hasPerm(user, "stock_view"))) {
    return res.status(403).json({ error: "Yetkisiz" });
  }

  const q = String(req.params.query || "").trim().toLowerCase();
  if (!q) return res.status(400).json({ error: "Arama parametresi gerekli" });

  const matches = (DATA.traceLots || []).filter((x) => {
    const fields = [x.id, x.lotNo, x.serialNo, x.heatNo, x.woId, x.orderId, x.productCode].map((v) => String(v || "").toLowerCase());
    return fields.some((v) => v.includes(q));
  });
  res.json({ rows: matches });
});
const multer = require("multer");
const ALLOWED_MIMES = { "application/pdf": ".pdf", "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp" };
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // Gvenli dosya ad: timestamp + uuid + doru uzant
    const ext = ALLOWED_MIMES[file.mimetype] || ".pdf";
    const safeName = crypto.randomBytes(16).toString("hex") + ext;
    cb(null, safeName);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIMES[file.mimetype]) {
      return cb(new Error("Sadece PDF ve resim dosyalar kabul edilir (PDF, JPG, PNG, GIF, WebP)"));
    }
    cb(null, true);
  },
});

// POST /api/upload  Dosya ykle (PDF veya resim), path dndr
app.post("/api/upload", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });
  if (!canUploadDocuments(user)) return res.status(403).json({ error: "Dosya y?kleme yetkiniz yok" });

  upload.single("pdf")(req, res, (err) => {
    if (err) {
      const msg = err.code === "LIMIT_FILE_SIZE" ? "Dosya 10MB'? a?amaz" : err.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) return res.status(400).json({ error: "Dosya bulunamad?" });
    if (!DATA.uploadFiles || typeof DATA.uploadFiles !== "object") DATA.uploadFiles = {};
    DATA.uploadFiles[req.file.filename] = {
      uploaderId: user.id,
      uploaderName: user.name,
      originalName: req.file.originalname,
      size: req.file.size,
      createdAt: new Date().toISOString(),
    };
    saveData(user);
    console.log(`?? ${user.name} dosya y?kledi: ${req.file.filename} (${Math.round(req.file.size / 1024)}KB)`);
    res.json({ path: `/uploads/${req.file.filename}`, name: req.file.originalname, size: req.file.size });
  });
});
// DELETE /api/upload/:filename  Dosya sil
app.delete("/api/upload/:filename", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });

  const filename = req.params.filename;
  // G?venlik: hex + izin verilen uzant? format?na izin ver, path traversal engelle
  if (!/^[a-f0-9]{32}\.(pdf|jpg|png|gif|webp)$/.test(filename)) return res.status(400).json({ error: "Ge?ersiz dosya ad?" });

  const meta = DATA.uploadFiles?.[filename] || null;
  const isOwner = !!meta && meta.uploaderId === user.id;
  if (!hasPerm(user, "admin") && !isOwner) return res.status(403).json({ error: "Dosya silme yetkiniz yok" });

  const filepath = path.join(UPLOAD_DIR, filename);
  try {
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
      console.log(`??? ${user.name} dosya sildi: ${filename}`);
    }
    if (DATA.uploadFiles && DATA.uploadFiles[filename]) {
      delete DATA.uploadFiles[filename];
      saveData(user);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Dosya silinemedi" });
  }
});
// Statik dosya servisi  yklenen PDF'lere eriim
app.use("/uploads", (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });
  if (!canViewDocuments(user)) return res.status(403).json({ error: "Dosya g?r?nt?leme yetkiniz yok" });
  next();
}, express.static(UPLOAD_DIR, { maxAge: "7d" }));

// [FIX #2] Login with mustChangePassword
app.post("/api/login", (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkLoginRate(ip)) return res.status(429).json({ error: "Çok fazla deneme! 1 dakika bekleyin." });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Kullanc ad ve ifre gerekli" });
  const user = DATA.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: "Kullanc ad veya ifre hatal!" });
  const token = createToken(user);
  // [FIX #8] Secure cookie
  res.cookie("token", token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax", secure: IS_PROD });
  console.log(`?? ${user.name} giri yapt (${ip})`);
  res.json({ user: sanitizeUser(user), mustChangePassword: !!user.mustChangePassword });
});

// [FIX #2] Force password change endpoint
app.post("/api/change-password", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Oturum geersiz" });
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !bcrypt.compareSync(currentPassword, user.passwordHash)) return res.status(400).json({ error: "Mevcut ifre hatal" });
  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });
  user.passwordHash = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
  user.mustChangePassword = false;
  user.passwordChangedAt = Date.now();
  saveData();
  const newToken = createToken(user);
  res.cookie("token", newToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax", secure: IS_PROD });
  res.json({ ok: true, user: sanitizeUser(user) });
});

app.post("/api/logout", (req, res) => { res.clearCookie("token"); res.json({ ok: true }); });

app.get("/api/me", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Oturum geersiz" });
  res.json({ user: sanitizeUser(user) });
});

// [FIX #15] Role-filtered state
app.get("/api/state", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });
  res.json(buildState(user));
});

// ===========================================
// [FIX #9] PARAT API PROXY  VALIDATED
// ===========================================
const https = require("https");
const PARASUT_ALLOWED = ["sales_invoices", "contacts", "accounts", "products", "item_categories", "tags", "e_invoices", "e_archives"];

function readParasutConfig() {
  const envClient = String(process.env.PARASUT_CLIENT_ID || "").trim();
  const envSecret = String(process.env.PARASUT_CLIENT_SECRET || "").trim();
  const envCompany = String(process.env.PARASUT_COMPANY_ID || "").trim();
  if (envClient && envSecret && envCompany) {
    return { clientId: envClient, clientSecret: envSecret, companyId: envCompany, source: "env" };
  }
  const cfg = DATA.parasutConfig || {};
  return {
    clientId: String(cfg.clientId || "").trim(),
    clientSecret: String(cfg.clientSecret || "").trim(),
    companyId: String(cfg.companyId || "").trim(),
    source: "data",
  };
}
function parasutConfigReady(cfg) {
  return !!(cfg.clientId && cfg.clientSecret && /^\d+$/.test(cfg.companyId));
}

function parasutProxy(method, apiPath, body, token) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: "api.parasut.com", path: apiPath, method, headers: { "Content-Type": "application/json" } };
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    const req = https.request(opts, (resp) => { let d = ""; resp.on("data", c => d += c); resp.on("end", () => { try { resolve({ status: resp.statusCode, data: JSON.parse(d) }); } catch (e) { resolve({ status: resp.statusCode, data: d }); } }); });
    req.on("error", e => reject(e));
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

app.get("/api/parasut/config", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !hasPerm(user, "admin")) return res.status(403).json({ error: "Yetkisiz" });
  const cfg = readParasutConfig();
  res.json({ client_id: cfg.clientId, company_id: cfg.companyId, has_secret: !!cfg.clientSecret, source: cfg.source });
});

app.post("/api/parasut/config", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user || !hasPerm(user, "admin")) return res.status(403).json({ error: "Yetkisiz" });

  const current = readParasutConfig();
  if (current.source === "env") return res.status(409).json({ error: "Para??t ayarlar? ortam de?i?keninden y?netiliyor" });

  const clientId = String(req.body?.client_id || "").trim();
  const companyId = String(req.body?.company_id || "").trim();
  const secretProvided = Object.prototype.hasOwnProperty.call(req.body || {}, "client_secret");
  const nextSecret = secretProvided ? String(req.body?.client_secret || "").trim() : String(DATA.parasutConfig?.clientSecret || "").trim();

  if (!clientId) return res.status(400).json({ error: "Client ID gerekli" });
  if (!/^\d+$/.test(companyId)) return res.status(400).json({ error: "Ge?erli Company ID gerekli" });

  DATA.parasutConfig = { clientId, clientSecret: nextSecret, companyId };
  saveData();
  res.json({ ok: true, client_id: clientId, company_id: companyId, has_secret: !!nextSecret, source: "data" });
});

app.post("/api/parasut/token", async (req, res) => {
  const authToken = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(authToken));
  if (!user || !hasPerm(user, "invoices_edit")) return res.status(403).json({ error: "Yetkisiz" });
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const cfg = readParasutConfig();
    const effective = {
      clientId: String(body.client_id || cfg.clientId || "").trim(),
      clientSecret: String(body.client_secret || cfg.clientSecret || "").trim(),
      companyId: String(body.company_id || cfg.companyId || "").trim(),
    };
    if (!parasutConfigReady(effective)) return res.status(400).json({ error: "Para??t yap?land?rmas? eksik" });

    const result = await parasutProxy("POST", "/oauth/token", { grant_type: "client_credentials", client_id: effective.clientId, client_secret: effective.clientSecret, redirect_uri: "urn:ietf:wg:oauth:2.0:oob" }, null);
    if (typeof result.data === "object" && result.data) {
      return res.status(result.status || 200).json({ ...result.data, company_id: effective.companyId });
    }
    return res.status(result.status || 500).json({ error: "Para??t token yan?t? ??z?mlenemedi" });
  } catch (e) { res.status(500).json({ error: IS_PROD ? "Para??t ba?lant? hatas?" : e.message }); }
});

// [FIX #9] Path validation + companyId numeric check
app.all("/api/parasut/v4/:companyId/*", async (req, res) => {
  const authToken = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(authToken));
  if (!user || !hasPerm(user, "invoices_edit")) return res.status(403).json({ error: "Yetkisiz" });
  try {
    const cid = req.params.companyId;
    if (!/^\d+$/.test(cid)) return res.status(400).json({ error: "Ge?ersiz ?irket ID" });

    const cfg = readParasutConfig();
    if (cfg.companyId && cid !== cfg.companyId) return res.status(403).json({ error: "Yetkisiz ?irket eri?imi" });

    const resourcePath = req.params[0];
    if (/\.\./.test(resourcePath)) return res.status(400).json({ error: "Ge?ersiz path" });
    const resource = resourcePath.split("/")[0];
    if (!PARASUT_ALLOWED.includes(resource)) return res.status(403).json({ error: "?zin verilmeyen kaynak: " + resource });
    const parasutToken = req.headers["x-parasut-token"];
    if (!parasutToken) return res.status(400).json({ error: "Para??t token gerekli" });
    const apiPath = "/v4/" + cid + "/" + req.params[0];
    const query = require("url").parse(req.url).search || "";
    const result = await parasutProxy(req.method, apiPath + query, ["POST", "PUT", "PATCH"].includes(req.method) ? req.body : null, parasutToken);
    res.status(result.status).json(result.data);
  } catch (e) { res.status(500).json({ error: IS_PROD ? "Para??t API hatas?" : e.message }); }
});
// SOCKET.IO ? SECURED
// ===========================================
const connectedUsers = new Map();
const socketRates = new Map();
function checkSocketRate(sid, max = 120) { const now = Date.now(); const r = socketRates.get(sid) || { count: 0, resetAt: now + 60000 }; if (now > r.resetAt) { r.count = 0; r.resetAt = now + 60000; } r.count++; socketRates.set(sid, r); return r.count <= max; }

io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.cookie?.split("token=")[1]?.split(";")[0];
  const user = getUser(verifyToken(token));
  if (!user) return next(new Error("Yetkisiz"));
  socket.user = sanitizeUser(user);
  next();
});

io.on("connection", (socket) => {
  console.log(`? ${socket.user.name} baland (${socket.id})`);
  connectedUsers.set(socket.id, { userId: socket.user.id, username: socket.user.username, name: socket.user.name });
  broadcastOnlineUsers();

  // [PHASE 1] State Chunking (Lazy Loading / Pagination on connect)
  socket.on("state:request", () => {
    const user = DATA.users.find(u => u.id === socket.user.id);
    if (!user) return socket.emit("auth:invalid");

    const perms = DATA.userPerms[user.id] || DEFAULT_ROLES[user.role]?.permissions || [];
    const can = p => perms.includes("admin") || perms.includes(p);

    // 1. Send base metadata first
    socket.emit("state:init", {
      users: DATA.users.map(sanitizeUser),
      userPerms: DATA.userPerms,
      machines: DATA.machines,
      operators: DATA.operators,
      _version: DATA._version,
      materialCodes: DATA.materialCodes?.length ? DATA.materialCodes : null,
      dashboardStats: computeDashboardStats(user)
    });

    // 2. Send large collections iteratively (Exclude completed ones for main tables to save memory)
    const activeOrders = DATA.orders.filter(o => o.status !== "completed");
    const activeWos = DATA.workOrders.filter(wo => wo.status !== "completed");
    const activeJobs = DATA.productionJobs.filter(j => j.status !== "completed");

    socket.emit("state:chunk", { key: "orders", data: can("orders_view") ? filterOrdersPrices(can("orders_price"), activeOrders) : [] });
    socket.emit("state:chunk", { key: "workOrders", data: can("workorders_view") ? activeWos : [] });
    socket.emit("state:chunk", { key: "productionJobs", data: can("production_view") ? activeJobs : [] });

    socket.emit("state:chunk", { key: "barStock", data: can("stock_view") ? DATA.barStock : [] });
    socket.emit("state:chunk", { key: "preCutStock", data: can("stock_view") ? (DATA.preCutStock || []) : [] });
    socket.emit("state:chunk", { key: "coatingQueue", data: can("coating_view") ? DATA.coatingQueue : [] });
    socket.emit("state:chunk", { key: "grindingQueue", data: can("grinding_view") ? DATA.grindingQueue : [] });
    socket.emit("state:chunk", { key: "purchaseRequests", data: can("purchasing_view") ? DATA.purchaseRequests : [] });
    socket.emit("state:chunk", { key: "invoices", data: can("invoices_view") ? (DATA.invoices || []) : [] });

    // Trace and QC tables are often small individually, but can be chunked completely as they are.
    socket.emit("state:chunk", { key: "traceLots", data: (can("production_view") || can("qc_view") || can("stock_view")) ? (DATA.traceLots || []) : [] });
    socket.emit("state:chunk", { key: "ncrs", data: can("qc_view") ? (DATA.ncrs || []) : [] });
    socket.emit("state:chunk", { key: "capas", data: can("qc_view") ? (DATA.capas || []) : [] });
    socket.emit("state:chunk", { key: "spcSamples", data: can("qc_view") ? (DATA.spcSamples || []) : [] });
    socket.emit("state:chunk", { key: "approvalRequests", data: (can("admin") || can("orders_edit") || can("workorders_edit") || can("qc_edit") || can("shipping_edit") || can("invoices_edit")) ? (DATA.approvalRequests || []) : [] });

    // 3. Signal completion
    socket.emit("state:done");
  });

  // [PHASE 2] Lazy loading for historical completed data
  socket.on("archive:request", (collection) => {
    if (!checkSocketRate(socket.id)) return;
    if (!["orders", "workOrders", "productionJobs"].includes(collection)) return;
    const user = getUser({ id: socket.user.id });
    if (!user) return;
    const perms = DATA.userPerms[user.id] || DEFAULT_ROLES[user.role]?.permissions || [];
    const can = p => perms.includes("admin") || perms.includes(p);

    let data = [];
    if (collection === "orders" && can("orders_view")) {
      data = filterOrdersPrices(can("orders_price"), DATA.orders.filter(o => o.status === "completed"));
    } else if (collection === "workOrders" && can("workorders_view")) {
      data = DATA.workOrders.filter(wo => wo.status === "completed");
    } else if (collection === "productionJobs" && can("production_view")) {
      data = DATA.productionJobs.filter(j => j.status === "completed");
    }

    socket.emit("archive:response", { collection, data });
  });

  // ===========================================
  // [FIX #1] Bulk :set handlers are disabled to prevent whole-collection overwrite risks.
  const legacySetEvents = ["orders:set", "workOrders:set", "productionJobs:set", "machines:set", "operators:set", "barStock:set", "coatingQueue:set", "grindingQueue:set", "purchaseRequests:set", "invoices:set"];
  legacySetEvents.forEach((ev) => {
    socket.on(ev, () => {
      socket.emit("error", { message: ev + " devre disi. Delta olaylarini kullanin." });
    });
  });

  // [PHASE 2] GENERIC DELTA HANDLERS
  // create / update / delete - sadece degisen kayit gonderilir
  Object.entries(DELTA_COLLECTIONS).forEach(([collection, cfg]) => {
    // -- CREATE --
    socket.on(`${collection}:create`, (item) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`YETKISIZ: ${socket.user.name} -> ${collection}:create`);
        return socket.emit("error", { message: `${collection}:create icin yetkiniz yok` });
      }

      const payload = { ...(item || {}) };
      if (collection === "orders") {
        const incomingId = typeof payload.id === "string" ? payload.id.trim() : "";
        payload.id = incomingId || nextOrderId();
      }

      const err = validateItem(payload, cfg.schema);
      if (err) return socket.emit("error", { message: err });

      if (DATA[cfg.key].find(x => x.id === payload.id)) {
        return socket.emit("error", { message: `Kayıt zaten mevcut: ${payload.id}` });
      }

      DATA[cfg.key].push(payload);
      dbInsert(cfg.key, payload, user, { source: "socket", collection });
      dbVersionBump();
      io.emit(`${collection}:created`, payload);
      console.log(`OK ${socket.user.name} -> ${collection}:create [${payload.id}]`);
    });

    // -- UPDATE (patch - sadece gelen alanlar güncellenir) --
    socket.on(`${collection}:update`, ({ id, changes }) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`?? YETKİSİZ: ${socket.user.name}  ${collection}:update`);
        return socket.emit("error", { message: `${collection}:update için yetkiniz yok` });
      }
      if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
      if (!changes || typeof changes !== "object" || Array.isArray(changes)) return socket.emit("error", { message: "changes nesne olmalıdır" });
      // id değiştirilemez
      delete changes.id;
      const idx = DATA[cfg.key].findIndex(x => x.id === id);
      if (idx === -1) return socket.emit("error", { message: `Kayıt bulunamadı: ${id}` });
      const requiredApprovals = detectApprovalRequirements(collection, DATA[cfg.key][idx], changes);
      if (requiredApprovals.length > 0) {
        const providedApprovalIds = [];
        if (typeof changes.__approvalId === "string" && changes.__approvalId.trim()) providedApprovalIds.push(changes.__approvalId.trim());
        if (Array.isArray(changes.__approvalIds)) {
          changes.__approvalIds.forEach((aid) => {
            const key = String(aid || "").trim();
            if (key) providedApprovalIds.push(key);
          });
        }
        delete changes.__approvalId;
        delete changes.__approvalIds;
        const approvedSet = new Set((DATA.approvalRequests || [])
          .filter((a) => providedApprovalIds.includes(a.id) && a.status === "approved" && a.entityType === collection && String(a.entityId || "") === String(id || ""))
          .map((a) => a.type));
        const missing = requiredApprovals.filter((type) => !approvedSet.has(type));
        if (missing.length > 0) {
          const created = missing.map((type) => createApprovalRequest({
            type,
            entityType: collection,
            entityId: id,
            reason: "Değişiklik onayı gerekli",
            payload: { proposedChanges: changes },
            user,
          }));
          return socket.emit("approval:required", { collection, id, required: requiredApprovals, created, missing });
        }
      }
      DATA[cfg.key][idx] = { ...DATA[cfg.key][idx], ...changes };
      dbUpdate(cfg.key, id, changes, user, { source: "socket", collection });
      dbVersionBump();
      io.emit(`${collection}:patched`, { id, changes });
      console.log(`? ${socket.user.name}  ${collection}:update [${id}]`);
    });

    //  DELETE 
    socket.on(`${collection}:delete`, (id) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`?? YETKİSİZ: ${socket.user.name}  ${collection}:delete`);
        return socket.emit("error", { message: `${collection}:delete için yetkiniz yok` });
      }
      if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
      const before = DATA[cfg.key].length;
      DATA[cfg.key] = DATA[cfg.key].filter(x => x.id !== id);
      if (DATA[cfg.key].length === before) return socket.emit("error", { message: `Kayıt bulunamad: ${id}` });
      dbDelete(cfg.key, id, user, { source: "socket", collection });
      dbVersionBump();
      io.emit(`${collection}:deleted`, id);
      console.log(`? ${socket.user.name}  ${collection}:delete [${id}]`);
    });
  });
  // [PHASE 2] USERS DELTA HANDLERS — granüler kullanıcı işlemleri
  socket.on("users:create", (userData) => {
    if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
    const reqUser = getUser({ id: socket.user.id });
    if (!reqUser || !hasPerm(reqUser, "admin")) return socket.emit("error", { message: "users:create için yetkiniz yok" });
    if (!userData || typeof userData !== "object") return socket.emit("error", { message: "Geçersiz kullanıcı verisi" });
    const id = String(userData.id || "U" + Date.now()).trim();
    if (DATA.users.find(u => u.id === id)) return socket.emit("error", { message: `Kullanıcı zaten mevcut: ${id}` });
    const username = String(userData.username || "").trim().toLowerCase();
    if (!username) return socket.emit("error", { message: "Kullanıcı adı zorunlu" });
    if (DATA.users.find(u => u.username.toLowerCase() === username)) return socket.emit("error", { message: `Kullanıcı adı zaten kullanılıyor: ${username}` });
    const pw = String(userData.password || "Miheng2026!");
    const newUser = {
      id, name: String(userData.name || "").trim(), username,
      passwordHash: bcrypt.hashSync(pw, bcrypt.genSaltSync(10)),
      role: String(userData.role || "operator"), avatar: String(userData.avatar || (userData.name || "U")[0]).toUpperCase(),
      mustChangePassword: true,
    };
    DATA.users.push(newUser);
    dbInsert("users", newUser, reqUser, { source: "socket", reason: "user-create" });
    io.emit("users:created", sanitizeUser(newUser));
    console.log(`OK ${reqUser.name} -> users:create [${id}]`);
  });

  socket.on("users:update", ({ id, changes }) => {
    if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
    const reqUser = getUser({ id: socket.user.id });
    if (!reqUser || !hasPerm(reqUser, "admin")) return socket.emit("error", { message: "users:update için yetkiniz yok" });
    if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
    if (!changes || typeof changes !== "object" || Array.isArray(changes)) return socket.emit("error", { message: "changes nesne olmalıdır" });
    const idx = DATA.users.findIndex(u => u.id === id);
    if (idx === -1) return socket.emit("error", { message: `Kullanıcı bulunamadı: ${id}` });
    const safeChanges = {};
    if (changes.name !== undefined) safeChanges.name = String(changes.name).trim();
    if (changes.username !== undefined) {
      const newUsername = String(changes.username).trim().toLowerCase();
      if (DATA.users.find(u => u.username.toLowerCase() === newUsername && u.id !== id)) return socket.emit("error", { message: `Kullanıcı adı zaten kullanılıyor: ${newUsername}` });
      safeChanges.username = newUsername;
    }
    if (changes.role !== undefined) safeChanges.role = String(changes.role);
    if (changes.avatar !== undefined) safeChanges.avatar = String(changes.avatar);
    if (Object.keys(safeChanges).length === 0) return;
    delete safeChanges.id; delete safeChanges.passwordHash;
    DATA.users[idx] = { ...DATA.users[idx], ...safeChanges };
    dbUpdate("users", id, safeChanges, reqUser, { source: "socket", reason: "user-update" });
    io.emit("users:patched", { id, changes: safeChanges });
    console.log(`OK ${reqUser.name} -> users:update [${id}]`);
  });

  socket.on("users:delete", (id) => {
    if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
    const reqUser = getUser({ id: socket.user.id });
    if (!reqUser || !hasPerm(reqUser, "admin")) return socket.emit("error", { message: "users:delete için yetkiniz yok" });
    if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
    if (id === reqUser.id) return socket.emit("error", { message: "Kendinizi silemezsiniz" });
    const before = DATA.users.length;
    DATA.users = DATA.users.filter(u => u.id !== id);
    if (DATA.users.length === before) return socket.emit("error", { message: `Kullanıcı bulunamadı: ${id}` });
    dbDelete("users", id, reqUser, { source: "socket", reason: "user-delete" });
    if (DATA.userPerms[id]) { delete DATA.userPerms[id]; persistMeta("userPerms", DATA.userPerms, reqUser, "user-delete-perms"); }
    io.emit("users:deleted", id);
    console.log(`OK ${reqUser.name} -> users:delete [${id}]`);
  });

  // Legacy users:set — devre dışı
  socket.on("users:set", () => {
    socket.emit("error", { message: "users:set devre dışı. Delta olaylarını kullanın (users:create/update/delete)." });
  });

  // [FIX #11] Password change with complexity
  socket.on("users:changePassword", ({ userId, newPassword }) => {
    const reqUser = getUser({ id: socket.user.id });
    if (!hasPerm(reqUser, "admin") && reqUser?.id !== userId) return;
    const user = DATA.users.find(u => u.id === userId);
    if (!user) return;
    const pwErr = validatePassword(newPassword);
    if (pwErr) return socket.emit("password:changed", { ok: false, error: pwErr });
    user.passwordHash = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
    user.mustChangePassword = false;
    user.passwordChangedAt = Date.now(); // [FIX #16]
    saveData(user); socket.emit("password:changed", { ok: true });
    console.log(`?? ${user.name} ifre deitirildi`);
  });

  // [FIX] Server-side log ekleme  client log maniplasyonunu nler
  socket.on("woLog:add", ({ woId, action, detail }) => {
    if (!woId || !action || typeof action !== "string") return;
    const user = getUser({ id: socket.user.id });
    if (!user) return;
    const wo = DATA.workOrders.find(w => w.id === woId);
    if (!wo) return;
    const entry = { ts: new Date().toISOString(), user: user.name, action: String(action).slice(0, 200), detail: String(detail || "").slice(0, 500) };
    wo.log = [...(wo.log || []), entry];
    dbUpdate("workOrders", woId, { log: wo.log }, user, { source: "socket", reason: "wo-log" });
    dbVersionBump();
    // Sadece deien WO'nun log alann yaynla  tm diziyi gndermek race condition yaratr
    io.emit("workOrders:patched", { id: woId, changes: { log: wo.log } });
  });

  socket.on("userPerms:set", perms => {
    if (!hasPerm(getUser({ id: socket.user.id }), "admin")) return;
    if (!perms || typeof perms !== "object" || Array.isArray(perms)) return;
    DATA.userPerms = perms; saveData(getUser({ id: socket.user.id })); io.emit("userPerms:updated", perms);
  });

  socket.on("approvalRequests:request", (payload) => {
    const user = getUser({ id: socket.user.id });
    if (!user || !canRequestApproval(user)) return;
    if (!payload || typeof payload !== "object") return;

    const type = String(payload.type || "").trim();
    const entityType = String(payload.entityType || "").trim();
    const entityId = String(payload.entityId || "").trim();
    if (!type || !entityType || !entityId) {
      return socket.emit("error", { message: "Onay talebi için type/entityType/entityId zorunlu" });
    }

    const created = createApprovalRequest({
      type,
      entityType,
      entityId,
      reason: String(payload.reason || "Socket onay talebi"),
      payload: payload.payload && typeof payload.payload === "object" ? payload.payload : {},
      user,
    });
    socket.emit("approvalRequests:created", created);
  });

  socket.on("approvalRequests:decide", ({ id, decision, note }) => {
    const user = getUser({ id: socket.user.id });
    if (!user || !canDecideApproval(user)) return;
    try {
      const updated = decideApprovalRequest(id, decision, note, user);
      socket.emit("approvalRequests:patched", { id: updated.id, changes: updated });
    } catch (e) {
      socket.emit("error", { message: e.message || "Onay karar kaydedilemedi" });
    }
  });
  // [FIX #10] Notification broadcast  requires edit permission
  socket.on("notification:broadcast", (data) => {
    const user = getUser({ id: socket.user.id });
    if (!user) return;
    const perms = DATA.userPerms[user.id] || DEFAULT_ROLES[user.role]?.permissions || [];
    const canBroadcast = perms.includes("admin") || perms.some(p => p.endsWith("_edit"));
    if (!canBroadcast) return socket.emit("error", { message: "Bildirim gonderme yetkiniz yok" });
    if (!data || typeof data !== "object" || Array.isArray(data)) return;

    const title = String(data.title || data.message || "").trim();
    if (!title) return;

    const targetRoles = Array.isArray(data.targetRoles)
      ? data.targetRoles.filter(r => typeof r === "string").slice(0, 20)
      : [];

    const safe = {
      ts: typeof data.ts === "string" ? data.ts : new Date().toISOString(),
      type: typeof data.type === "string" ? data.type.slice(0, 24) : "info",
      title: title.slice(0, 160),
      detail: String(data.detail || "").slice(0, 1000),
      message: title.slice(0, 160),
      targetRoles,
      targetPage: typeof data.targetPage === "string" ? data.targetPage.slice(0, 50) : null,
      fromUser: socket.user.name,
      timestamp: Date.now(),
    };
    socket.broadcast.emit("notification:broadcast", safe);
  });

  socket.on("disconnect", () => {
    console.log(`? ${socket.user.name} ayrld`);
    connectedUsers.delete(socket.id); socketRates.delete(socket.id);
    broadcastOnlineUsers();
  });
});

function broadcastOnlineUsers() {
  const online = [], seen = new Set();
  connectedUsers.forEach(v => { if (!seen.has(v.userId)) { seen.add(v.userId); online.push({ userId: v.userId, name: v.name }); } });
  io.emit("users:online", online);
}

// ===========================================
// GRACEFUL SHUTDOWN
// ===========================================
function shutdown(sig) {
  console.log(`\n?? ${sig}  kapatlyor...`);
  if (saveTimer) clearTimeout(saveTimer);
  saveDataSync(); createBackup();
  server.close(() => { try { store.close(); } catch { } console.log("? Sunucu kapatıldı."); process.exit(0); });
  setTimeout(() => process.exit(1), 5000);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// ===========================================
// START
// ===========================================
loadData();
setTimeout(createBackup, 5000);
server.listen(PORT, "0.0.0.0", () => {
  console.log(`
-======================================================
  MHENK retim Takip Sistemi v1.1 (Gvenlik+)      
  Adres:  http://0.0.0.0:${String(PORT).padEnd(33)}
  Veri:   ${DB_FILE.padEnd(43)}
  Ortam:  ${NODE_ENV.padEnd(43)}
  JWT:    ${(process.env.JWT_SECRET ? "env" : fs.existsSync(SECRET_FILE) ? "dosya" : "bellek").padEnd(43)}
  Durum:  ${String(DATA.users.length).padStart(2)} kullanc hazr                         
L======================================================-
  `);
});




