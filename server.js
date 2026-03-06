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


const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : ["http://localhost:3000","http://127.0.0.1:3000"];

// ═══════════════════════════════════════════
// [FIX #4] PERSISTENT JWT SECRET
// ═══════════════════════════════════════════
const DATA_DIR = process.env.DATA_DIR || __dirname;
const SECRET_FILE = path.join(DATA_DIR, ".jwt-secret");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  try { if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE,"utf8").trim(); } catch(e){}
  const secret = crypto.randomBytes(64).toString("hex");
  try { fs.writeFileSync(SECRET_FILE, secret, {mode:0o600}); } catch(e){ console.warn("⚠️ JWT secret dosyası yazılamadı"); }
  return secret;
}
const JWT_SECRET = getJwtSecret();

// ═══════════════════════════════════════════
// [FIX #5] CORS — RESTRICTED
// ═══════════════════════════════════════════
const io = new Server(server, {
  cors: { origin:(origin,cb)=>{ if(!origin||ALLOWED_ORIGINS.includes(origin)||!IS_PROD) return cb(null,true); cb(new Error("CORS denied")); }, credentials:true },
  pingTimeout:60000, pingInterval:25000,
  maxHttpBufferSize: 5e6,
});

// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy:{
    directives:{
      defaultSrc:["'self'"], scriptSrc:["'self'","'unsafe-inline'","'unsafe-eval'","cdnjs.cloudflare.com","fonts.googleapis.com"],
      styleSrc:["'self'","'unsafe-inline'","fonts.googleapis.com"], fontSrc:["'self'","fonts.gstatic.com"],
      connectSrc:["'self'","ws:","wss:"], imgSrc:["'self'","data:","blob:"],
    }
  }
}));
app.use(compression());
app.use(express.json({limit:"5mb"}));
app.use(cookieParser());

// ═══════════════════════════════════════════
// [FIX #12] RATE LIMITING
// ═══════════════════════════════════════════
const rateLimiters = new Map();
function checkRate(ip,type,max,windowMs){
  const now=Date.now(),key=`${type}:${ip}`;
  const r=rateLimiters.get(key)||{count:0,resetAt:now+windowMs};
  if(now>r.resetAt){r.count=0;r.resetAt=now+windowMs;}
  r.count++; rateLimiters.set(key,r);
  return r.count<=max;
}
function checkLoginRate(ip){return checkRate(ip,"login",5,60000);}
function checkApiRate(ip){return checkRate(ip,"api",100,60000);}
setInterval(()=>{const now=Date.now();rateLimiters.forEach((v,k)=>{if(now>v.resetAt)rateLimiters.delete(k);});},300000);

app.use("/api",(req,res,next)=>{
  if(req.path==="/health")return next();
  const ip=req.ip||req.connection.remoteAddress;
  if(!checkApiRate(ip))return res.status(429).json({error:"Çok fazla istek."});
  next();
});

app.use(express.static(path.join(__dirname,"public"),{maxAge:"1h"}));

// ═══════════════════════════════════════════
// PERMISSIONS & ROLES
// ═══════════════════════════════════════════
const PERMISSIONS = {
  orders_view:"Siparişleri Görüntüle",orders_edit:"Sipariş Oluştur/Düzenle",
  orders_price:"Fiyat Bilgisi Görüntüle",workorders_view:"İş Emirlerini Görüntüle",
  workorders_edit:"İş Emri Düzenle",cutting_view:"Kesimi Görüntüle",
  cutting_edit:"Kesim İşlemleri",grinding_view:"Taşlamayı Görüntüle",
  grinding_edit:"Taşlama İşlemleri",planning_view:"Planlamayı Görüntüle",
  planning_edit:"Planlama Düzenle",production_view:"Üretimi Görüntüle",
  production_edit:"Üretim Başlat/Bitir",qc_view:"Kalite Kontrolü Görüntüle",
  qc_edit:"KK Onayı Ver",coating_view:"Kaplamayı Görüntüle",
  coating_edit:"Kaplama İşlemleri",shipping_view:"Sevkiyatı Görüntüle",
  shipping_edit:"Sevkiyat İşlemleri",stock_view:"Stok Görüntüle",
  stock_edit:"Stok Düzenle",purchasing_view:"Satın Almayı Görüntüle",
  purchasing_edit:"Satın Alma İşlemleri",machines_view:"Makinaları Görüntüle",
  operators_view:"Operatörleri Görüntüle",invoices_view:"Faturaları Görüntüle",
  invoices_edit:"Fatura İşlemleri",admin:"Yönetici (Tüm Yetkiler)",
};

const DEFAULT_ROLES = {
  admin:{label:"Yönetici",permissions:Object.keys(PERMISSIONS)},
  manager:{label:"Üretim Müdürü",permissions:["orders_view","orders_edit","orders_price","workorders_view","workorders_edit","cutting_view","cutting_edit","grinding_view","grinding_edit","planning_view","planning_edit","production_view","production_edit","qc_view","qc_edit","coating_view","coating_edit","shipping_view","shipping_edit","invoices_view","invoices_edit","stock_view","stock_edit","purchasing_view","purchasing_edit","machines_view","operators_view"]},
  planner:{label:"Planlama Sorumlusu",permissions:["orders_view","workorders_view","workorders_edit","cutting_view","grinding_view","planning_view","planning_edit","production_view","purchasing_view","machines_view","operators_view"]},
  operator:{label:"Operatör",permissions:["orders_view","workorders_view","workorders_edit","cutting_view","cutting_edit","grinding_view","grinding_edit","production_view","production_edit","qc_view","qc_edit","stock_view","purchasing_view","machines_view"]},
  viewer:{label:"İzleyici",permissions:["orders_view","workorders_view","cutting_view","grinding_view","planning_view","production_view","qc_view","coating_view","shipping_view","stock_view","purchasing_view","machines_view","operators_view"]},
};

// [FIX #1] Socket handler → required permission mapping
const HANDLER_PERMISSIONS = {
  "orders:set":"orders_edit","workOrders:set":"workorders_edit","productionJobs:set":"production_edit",
  "machines:set":"admin","operators:set":"admin","barStock:set":"stock_edit",
  "coatingQueue:set":"coating_edit","grindingQueue:set":"grinding_edit",
  "purchaseRequests:set":"purchasing_edit","invoices:set":"invoices_edit",
};

// ═══════════════════════════════════════════
// [PHASE 2] DELTA HANDLER CONFIG
// ═══════════════════════════════════════════
const DELTA_COLLECTIONS = {
  orders:          { key:"orders",          perm:"orders_edit",      schema:{ required:["id","customerName","items"], types:{id:"string",items:"array"} } },
  workOrders:      { key:"workOrders",      perm:"workorders_edit",  schema:{ required:["id","orderId"],             types:{id:"string"} } },
  productionJobs:  { key:"productionJobs",  perm:"production_edit",  schema:{ required:["id","woId"],                types:{id:"string"} } },
  barStock:        { key:"barStock",        perm:"stock_edit",       schema:{ required:["id"],                       types:{id:"string"} } },
  coatingQueue:    { key:"coatingQueue",    perm:"coating_edit",     schema:{ required:["id"],                       types:{id:"string"} } },
  grindingQueue:   { key:"grindingQueue",   perm:"grinding_edit",    schema:{ required:["id"],                       types:{id:"string"} } },
  purchaseRequests:{ key:"purchaseRequests",perm:"purchasing_edit",  schema:{ required:["id"],                       types:{id:"string"} } },
  invoices:        { key:"invoices",        perm:"invoices_edit",    schema:{ required:["id"],                       types:{id:"string"} } },
  machines:        { key:"machines",        perm:"admin",            schema:{ required:["id","name"],                types:{id:"string"} } },
  operators:       { key:"operators",       perm:"admin",            schema:{ required:["id","name"],                types:{id:"string"} } },
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
      if (t !== "array" && typeof item[f] !== t) return `${f} tipi hatalı (beklenen: ${t})`;
    }
  }
  if (String(item.id || "").length > 200) return "id çok uzun";
  return null;
}

// ═══════════════════════════════════════════
// DEFAULT DATA
// ═══════════════════════════════════════════
function createDefaultData(){
  const salt=bcrypt.genSaltSync(10);
  const pw=bcrypt.hashSync("1234",salt);
  return {
    users:[
      {id:"U1",name:"Taha",username:"taha",passwordHash:pw,role:"admin",avatar:"T",mustChangePassword:true},
      {id:"U2",name:"Ahmet Yılmaz",username:"ahmet",passwordHash:pw,role:"operator",avatar:"A",mustChangePassword:true},
      {id:"U3",name:"Mehmet Kaya",username:"mehmet",passwordHash:pw,role:"operator",avatar:"M",mustChangePassword:true},
      {id:"U4",name:"Fatma Demir",username:"fatma",passwordHash:pw,role:"manager",avatar:"F",mustChangePassword:true},
      {id:"U5",name:"Zeynep Acar",username:"zeynep",passwordHash:pw,role:"planner",avatar:"Z",mustChangePassword:true},
      {id:"U6",name:"Emre Şahin",username:"emre",passwordHash:pw,role:"viewer",avatar:"E",mustChangePassword:true},
    ],
    userPerms:{},orders:[],workOrders:[],productionJobs:[],
    machines:[
      {id:"M1",name:"S20-1",type:"CNC",status:"active"},{id:"M2",name:"S20-2",type:"CNC",status:"active"},
      {id:"M3",name:"S20-3",type:"CNC",status:"active"},{id:"M4",name:"Studer Taşlama",type:"Taşlama",status:"active"},
      {id:"M5",name:"Lazer Markalama",type:"Lazer",status:"active"},{id:"M6",name:"Kesim Tezgahı",type:"Kesim",status:"active"},
      {id:"M8",name:"S22-1",type:"CNC",status:"active"},{id:"M9",name:"S22-2",type:"CNC",status:"active"},
      {id:"M10",name:"Saacke",type:"CNC",status:"active"},
    ],
    operators:[
      {id:"O1",name:"Ahmet Yılmaz",role:"CNC Operatör",shift:"Gündüz"},
      {id:"O2",name:"Mehmet Kaya",role:"CNC Operatör",shift:"Gündüz"},
      {id:"O3",name:"Ali Demir",role:"CNC Operatör",shift:"Gece"},
      {id:"O4",name:"Hasan Çelik",role:"Taşlamacı",shift:"Gündüz"},
      {id:"O5",name:"Veli Acar",role:"Kesimci",shift:"Gündüz"},
      {id:"O6",name:"Emre Şahin",role:"Lazer Operatör",shift:"Gündüz"},
    ],
    barStock:[],coatingQueue:[],grindingQueue:[],purchaseRequests:[],invoices:[],
    _version:1,_createdAt:new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════
// DATA PERSISTENCE — Atomic JSON (Phase 3)
// write-ahead: tmp dosyasına yaz → rename (atomic)
// race condition koruması: yazma kuyruğu
// ═══════════════════════════════════════════
let DATA=null, saveTimer=null, _writing=false, _pendingWrite=false;

const JSON_COLLECTIONS=["orders","workOrders","productionJobs","machines","operators",
  "barStock","coatingQueue","grindingQueue","purchaseRequests","invoices"];

// Atomic write: önce .tmp'ye yaz, sonra rename
async function writeAtomic(filePath, data){
  const tmp=filePath+".tmp";
  await fs.promises.writeFile(tmp, data, "utf8");
  await fs.promises.rename(tmp, filePath);
}

// Write queue — eş zamanlı yazma yarışını önler
async function flushWrite(){
  if(_writing){ _pendingWrite=true; return; }
  _writing=true;
  try{
    DATA._version=(DATA._version||0)+1;
    await writeAtomic(DATA_FILE, JSON.stringify(DATA, null, 2));
  }catch(e){ console.error("Veri kaydetme hatası:", e.message); }
  finally{
    _writing=false;
    if(_pendingWrite){ _pendingWrite=false; flushWrite(); }
  }
}

function saveDataSync(){
  DATA._version=(DATA._version||0)+1;
  try{
    const json=JSON.stringify(DATA, null, 2);
    const tmp=DATA_FILE+".tmp";
    fs.writeFileSync(tmp, json, "utf8");
    fs.renameSync(tmp, DATA_FILE);
  }catch(e){ console.error("Veri kaydetme hatası:", e.message); }
}

function saveData(){
  if(saveTimer) clearTimeout(saveTimer);
  saveTimer=setTimeout(()=>flushWrite(), 300);
}

// Delta helpers — memory güncelle + debounced write
function dbInsert(collection, item){
  // DATA zaten güncellendi (handler'da push yapıldı), sadece save tetikle
  saveData();
}
function dbUpdate(collection, id, changes){
  // DATA zaten güncellendi (handler'da merge yapıldı), sadece save tetikle
  saveData();
}
function dbDelete(collection, id){
  // DATA zaten güncellendi (handler'da filter yapıldı), sadece save tetikle
  saveData();
}
function dbVersionBump(){
  // saveData içinde zaten version bump yapılıyor
}

function loadData(){
  try{
    if(fs.existsSync(DATA_FILE)){
      const raw=fs.readFileSync(DATA_FILE,"utf8");
      DATA=JSON.parse(raw);
      console.log("✓ Veri yüklendi:", DATA_FILE, "— version:", DATA._version);
    } else {
      DATA=createDefaultData();
      saveDataSync();
      console.log("✓ Yeni veri dosyası:", DATA_FILE);
    }
  }catch(e){ console.error("Veri yükleme hatası:", e.message); DATA=createDefaultData(); saveDataSync(); }
}

// ═══════════════════════════════════════════
// AUTO-BACKUP
// ═══════════════════════════════════════════
function createBackup(){
  try{
    if(!fs.existsSync(DATA_FILE)) return;
    if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR,{recursive:true});
    const stamp=new Date().toISOString().replace(/[:.]/g,"-").slice(0,19);
    fs.copyFileSync(DATA_FILE, path.join(BACKUP_DIR,`data-${stamp}.json`));
    const files=fs.readdirSync(BACKUP_DIR).filter(f=>f.startsWith("data-")).sort();
    while(files.length>30){ fs.unlinkSync(path.join(BACKUP_DIR,files.shift())); }
  }catch(e){ console.error("Yedekleme hatası:", e.message); }
}
setInterval(createBackup, 6*60*60*1000);

// ═══════════════════════════════════════════
// AUTH HELPERS
// ═══════════════════════════════════════════
// [FIX #16] Token includes pwAt for revocation on password change
function createToken(user){return jwt.sign({id:user.id,username:user.username,role:user.role,pwAt:user.passwordChangedAt||0},JWT_SECRET,{expiresIn:"7d"});}
function verifyToken(token){try{return jwt.verify(token,JWT_SECRET);}catch{return null;}}

// [FIX #16] Reject tokens issued before password change
function getUser(decoded){
  if(!decoded)return null;
  const user=DATA.users.find(u=>u.id===decoded.id);
  if(!user)return null;
  if(user.passwordChangedAt && decoded.pwAt!==undefined && user.passwordChangedAt>decoded.pwAt) return null;
  return user;
}
function hasPerm(user,perm){
  if(!user)return false;
  const perms=DATA.userPerms[user.id]||DEFAULT_ROLES[user.role]?.permissions||[];
  return perms.includes("admin")||perms.includes(perm);
}
function sanitizeUser(u){const{passwordHash,...safe}=u;return safe;}

// [FIX #15] Role-filtered state
function buildState(user){
  const base={users:DATA.users.map(sanitizeUser),userPerms:DATA.userPerms,machines:DATA.machines,operators:DATA.operators,_version:DATA._version};
  const perms=DATA.userPerms[user?.id]||DEFAULT_ROLES[user?.role]?.permissions||[];
  const can=p=>perms.includes("admin")||perms.includes(p);
  base.orders=can("orders_view")?DATA.orders:[];
  base.workOrders=can("workorders_view")?DATA.workOrders:[];
  base.productionJobs=can("production_view")?DATA.productionJobs:[];
  base.barStock=can("stock_view")?DATA.barStock:[];
  base.coatingQueue=can("coating_view")?DATA.coatingQueue:[];
  base.grindingQueue=can("grinding_view")?DATA.grindingQueue:[];
  base.purchaseRequests=can("purchasing_view")?DATA.purchaseRequests:[];
  base.invoices=can("invoices_view")?(DATA.invoices||[]):[];
  // [FIX #15] Strip prices if no permission
  if(!can("orders_price")&&base.orders.length>0){
    base.orders=base.orders.map(o=>({...o,items:o.items.map(it=>{const{unitPrice,...rest}=it;return rest;})}));
  }
  return base;
}

// [FIX #11] Password complexity
function validatePassword(pw){
  if(!pw||pw.length<8)return "Şifre en az 8 karakter olmalıdır";
  if(!/[A-Za-zÇçĞğİıÖöŞşÜü]/.test(pw))return "Şifre en az bir harf içermelidir";
  if(!/[0-9]/.test(pw))return "Şifre en az bir rakam içermelidir";
  return null;
}

// [FIX #6] Data validation
function validateSocketData(key,data){
  if(!Array.isArray(data))return "Veri bir dizi olmalıdır";
  const size=JSON.stringify(data).length;
  if(size>4*1024*1024)return "Veri boyutu çok büyük (>4MB)";
  const limits={orders:10000,workOrders:10000,productionJobs:50000,machines:100,operators:200,barStock:1000,coatingQueue:10000,grindingQueue:10000,purchaseRequests:10000,invoices:50000};
  if(limits[key]&&data.length>limits[key])return `Çok fazla kayıt (${data.length}>${limits[key]})`;
  return null;
}

// ═══════════════════════════════════════════
// REST API
// ═══════════════════════════════════════════
app.get("/api/health",(req,res)=>res.json({status:"ok",uptime:process.uptime(),connections:connectedUsers.size,version:DATA._version,db:"sqlite"}));

// Manuel backup tetikle (admin only)
app.post("/api/backup",(req,res)=>{
  const token=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(token));
  if(!user||!hasPerm(user,"admin")) return res.status(403).json({error:"Yetkisiz"});
  try{ createBackup(); res.json({ok:true,message:"Yedek alındı"}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// ═══════════════════════════════════════════
// [PHASE 2.4] PDF UPLOAD — Multer tabanlı dosya depolama
// base64 data.json'a gömülmesi yerine disk'e kaydedilir
// ═══════════════════════════════════════════
const multer = require("multer");
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // Güvenli dosya adı: timestamp + uuid + sabit uzantı
    const safeName = crypto.randomBytes(16).toString("hex") + ".pdf";
    cb(null, safeName);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Sadece PDF dosyası kabul edilir"));
    }
    cb(null, true);
  },
});

// POST /api/upload — PDF yükle, path döndür
app.post("/api/upload", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });

  upload.single("pdf")(req, res, (err) => {
    if (err) {
      const msg = err.code === "LIMIT_FILE_SIZE" ? "Dosya 10MB'ı aşamaz" : err.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) return res.status(400).json({ error: "Dosya bulunamadı" });
    console.log(`📎 ${user.name} PDF yükledi: ${req.file.filename} (${Math.round(req.file.size/1024)}KB)`);
    res.json({ path: `/uploads/${req.file.filename}`, name: req.file.originalname, size: req.file.size });
  });
});

// DELETE /api/upload/:filename — PDF sil
app.delete("/api/upload/:filename", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });

  const filename = req.params.filename;
  // Güvenlik: sadece hex.pdf formatına izin ver, path traversal engelle
  if (!/^[a-f0-9]{32}\.pdf$/.test(filename)) return res.status(400).json({ error: "Geçersiz dosya adı" });

  const filepath = path.join(UPLOAD_DIR, filename);
  try {
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
      console.log(`🗑️ ${user.name} PDF sildi: ${filename}`);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Dosya silinemedi" });
  }
});

// Statik dosya servisi — yüklenen PDF'lere erişim
app.use("/uploads", (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");
  const user = getUser(verifyToken(token));
  if (!user) return res.status(401).json({ error: "Yetkisiz" });
  next();
}, express.static(UPLOAD_DIR, { maxAge: "7d" }));

// [FIX #2] Login with mustChangePassword
app.post("/api/login",(req,res)=>{
  const ip=req.ip||req.connection.remoteAddress;
  if(!checkLoginRate(ip))return res.status(429).json({error:"Çok fazla deneme! 1 dakika bekleyin."});
  const{username,password}=req.body;
  if(!username||!password)return res.status(400).json({error:"Kullanıcı adı ve şifre gerekli"});
  const user=DATA.users.find(u=>u.username===username);
  if(!user||!bcrypt.compareSync(password,user.passwordHash))return res.status(401).json({error:"Kullanıcı adı veya şifre hatalı!"});
  const token=createToken(user);
  // [FIX #8] Secure cookie
  res.cookie("token",token,{httpOnly:true,maxAge:7*24*60*60*1000,sameSite:"lax",secure:IS_PROD});
  console.log(`🔑 ${user.name} giriş yaptı (${ip})`);
  res.json({user:sanitizeUser(user),token,mustChangePassword:!!user.mustChangePassword});
});

// [FIX #2] Force password change endpoint
app.post("/api/change-password",(req,res)=>{
  const token=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(token));
  if(!user)return res.status(401).json({error:"Oturum geçersiz"});
  const{currentPassword,newPassword}=req.body;
  if(!currentPassword||!bcrypt.compareSync(currentPassword,user.passwordHash))return res.status(400).json({error:"Mevcut şifre hatalı"});
  const pwErr=validatePassword(newPassword);
  if(pwErr)return res.status(400).json({error:pwErr});
  user.passwordHash=bcrypt.hashSync(newPassword,bcrypt.genSaltSync(10));
  user.mustChangePassword=false;
  user.passwordChangedAt=Date.now();
  saveData();
  const newToken=createToken(user);
  res.cookie("token",newToken,{httpOnly:true,maxAge:7*24*60*60*1000,sameSite:"lax",secure:IS_PROD});
  res.json({ok:true,token:newToken,user:sanitizeUser(user)});
});

app.post("/api/logout",(req,res)=>{res.clearCookie("token");res.json({ok:true});});

app.get("/api/me",(req,res)=>{
  const token=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(token));
  if(!user)return res.status(401).json({error:"Oturum geçersiz"});
  res.json({user:sanitizeUser(user)});
});

// [FIX #15] Role-filtered state
app.get("/api/state",(req,res)=>{
  const token=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(token));
  if(!user)return res.status(401).json({error:"Yetkisiz"});
  res.json(buildState(user));
});

// ═══════════════════════════════════════════
// [FIX #9] PARAŞÜT API PROXY — VALIDATED
// ═══════════════════════════════════════════
const https=require("https");
const PARASUT_ALLOWED=["sales_invoices","contacts","accounts","products","item_categories","tags","e_invoices","e_archives"];

function parasutProxy(method,apiPath,body,token){
  return new Promise((resolve,reject)=>{
    const opts={hostname:"api.parasut.com",path:apiPath,method,headers:{"Content-Type":"application/json"}};
    if(token)opts.headers["Authorization"]="Bearer "+token;
    const req=https.request(opts,(resp)=>{let d="";resp.on("data",c=>d+=c);resp.on("end",()=>{try{resolve({status:resp.statusCode,data:JSON.parse(d)});}catch(e){resolve({status:resp.statusCode,data:d});}});});
    req.on("error",e=>reject(e));
    if(body)req.write(JSON.stringify(body));
    req.end();
  });
}

app.post("/api/parasut/token",async(req,res)=>{
  const authToken=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(authToken));
  if(!user||!hasPerm(user,"invoices_edit"))return res.status(403).json({error:"Yetkisiz"});
  try{
    const{client_id,client_secret}=req.body;
    if(!client_id||!client_secret)return res.status(400).json({error:"Client ID ve Secret gerekli"});
    const result=await parasutProxy("POST","/oauth/token",{grant_type:"client_credentials",client_id,client_secret,redirect_uri:"urn:ietf:wg:oauth:2.0:oob"},null);
    res.json(result.data);
  }catch(e){res.status(500).json({error:IS_PROD?"Paraşüt bağlantı hatası":e.message});}
});

// [FIX #9] Path validation + companyId numeric check
app.all("/api/parasut/v4/:companyId/*",async(req,res)=>{
  const authToken=req.cookies.token||req.headers.authorization?.replace("Bearer ","");
  const user=getUser(verifyToken(authToken));
  if(!user||!hasPerm(user,"invoices_edit"))return res.status(403).json({error:"Yetkisiz"});
  try{
    const cid=req.params.companyId;
    if(!/^\d+$/.test(cid))return res.status(400).json({error:"Geçersiz şirket ID"});
    const resourcePath=req.params[0];
    if(/\.\./.test(resourcePath))return res.status(400).json({error:"Geçersiz path"});
    const resource=resourcePath.split("/")[0];
    if(!PARASUT_ALLOWED.includes(resource))return res.status(403).json({error:"İzin verilmeyen kaynak: "+resource});
    const parasutToken=req.headers["x-parasut-token"];
    if(!parasutToken)return res.status(400).json({error:"Paraşüt token gerekli"});
    const apiPath="/v4/"+cid+"/"+req.params[0];
    const query=require("url").parse(req.url).search||"";
    const result=await parasutProxy(req.method,apiPath+query,["POST","PUT","PATCH"].includes(req.method)?req.body:null,parasutToken);
    res.status(result.status).json(result.data);
  }catch(e){res.status(500).json({error:IS_PROD?"Paraşüt API hatası":e.message});}
});

// ═══════════════════════════════════════════
// SOCKET.IO — SECURED
// ═══════════════════════════════════════════
const connectedUsers=new Map();
const socketRates=new Map();
function checkSocketRate(sid,max=120){const now=Date.now();const r=socketRates.get(sid)||{count:0,resetAt:now+60000};if(now>r.resetAt){r.count=0;r.resetAt=now+60000;}r.count++;socketRates.set(sid,r);return r.count<=max;}

io.use((socket,next)=>{
  const token=socket.handshake.auth?.token||socket.handshake.headers?.cookie?.split("token=")[1]?.split(";")[0];
  const user=getUser(verifyToken(token));
  if(!user)return next(new Error("Yetkisiz"));
  socket.user=sanitizeUser(user);
  next();
});

io.on("connection",(socket)=>{
  console.log(`⚡ ${socket.user.name} bağlandı (${socket.id})`);
  connectedUsers.set(socket.id,{userId:socket.user.id,username:socket.user.username,name:socket.user.name});
  broadcastOnlineUsers();

  // [FIX #15] Role-filtered state
  socket.on("state:request",()=>{
    const user=DATA.users.find(u=>u.id===socket.user.id);
    socket.emit("state:init",buildState(user));
  });

  // ═══════════════════════════════════════════
  // [FIX #1] DATA HANDLERS WITH PERMISSIONS
  // ═══════════════════════════════════════════
  const handlers={"orders:set":"orders","workOrders:set":"workOrders","productionJobs:set":"productionJobs","machines:set":"machines","operators:set":"operators","barStock:set":"barStock","coatingQueue:set":"coatingQueue","grindingQueue:set":"grindingQueue","purchaseRequests:set":"purchaseRequests","invoices:set":"invoices"};

  Object.entries(handlers).forEach(([ev,key])=>{
    socket.on(ev,(data)=>{
      if(!checkSocketRate(socket.id))return socket.emit("error",{message:"Çok fazla istek"});
      // [FIX #1] Permission check
      const perm=HANDLER_PERMISSIONS[ev];
      const user=getUser({id:socket.user.id});
      if(!user||!hasPerm(user,perm)){
        console.warn(`🚫 YETKİSİZ: ${socket.user.name} → ${ev}`);
        return socket.emit("error",{message:`${ev} için yetkiniz yok`});
      }
      // [FIX #6] Validation
      const err=validateSocketData(key,data);
      if(err){console.warn(`🚫 GEÇERSİZ VERİ: ${socket.user.name} → ${ev}: ${err}`);return socket.emit("error",{message:err});}
      DATA[key]=data; saveData(); socket.broadcast.emit(key+":updated",data);
    });
  });

  // ═══════════════════════════════════════════
  // [PHASE 2] GENERIC DELTA HANDLERS
  // create / update / delete — sadece değişen kayıt gönderilir
  // Eski :set handler'larla paralel çalışır (geriye uyumlu)
  // ═══════════════════════════════════════════
  Object.entries(DELTA_COLLECTIONS).forEach(([collection, cfg]) => {
    // ── CREATE ──
    socket.on(`${collection}:create`, (item) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`🚫 YETKİSİZ: ${socket.user.name} → ${collection}:create`);
        return socket.emit("error", { message: `${collection}:create için yetkiniz yok` });
      }
      const err = validateItem(item, cfg.schema);
      if (err) return socket.emit("error", { message: err });
      // Aynı id varsa reject et
      if (DATA[cfg.key].find(x => x.id === item.id)) {
        return socket.emit("error", { message: `Kayıt zaten mevcut: ${item.id}` });
      }
      DATA[cfg.key].push(item);
      dbInsert(cfg.key, item);
      dbVersionBump();
      io.emit(`${collection}:created`, item);
      console.log(`✓ ${socket.user.name} → ${collection}:create [${item.id}]`);
    });

    // ── UPDATE (patch — sadece gelen alanlar güncellenir) ──
    socket.on(`${collection}:update`, ({ id, changes }) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`🚫 YETKİSİZ: ${socket.user.name} → ${collection}:update`);
        return socket.emit("error", { message: `${collection}:update için yetkiniz yok` });
      }
      if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
      if (!changes || typeof changes !== "object" || Array.isArray(changes)) return socket.emit("error", { message: "changes nesne olmalıdır" });
      // id değiştirilemez
      delete changes.id;
      const idx = DATA[cfg.key].findIndex(x => x.id === id);
      if (idx === -1) return socket.emit("error", { message: `Kayıt bulunamadı: ${id}` });
      DATA[cfg.key][idx] = { ...DATA[cfg.key][idx], ...changes };
      dbUpdate(cfg.key, id, changes);
      dbVersionBump();
      io.emit(`${collection}:patched`, { id, changes });
      console.log(`✓ ${socket.user.name} → ${collection}:update [${id}]`);
    });

    // ── DELETE ──
    socket.on(`${collection}:delete`, (id) => {
      if (!checkSocketRate(socket.id)) return socket.emit("error", { message: "Çok fazla istek" });
      const user = getUser({ id: socket.user.id });
      if (!user || !hasPerm(user, cfg.perm)) {
        console.warn(`🚫 YETKİSİZ: ${socket.user.name} → ${collection}:delete`);
        return socket.emit("error", { message: `${collection}:delete için yetkiniz yok` });
      }
      if (!id || typeof id !== "string") return socket.emit("error", { message: "Geçersiz id" });
      const before = DATA[cfg.key].length;
      DATA[cfg.key] = DATA[cfg.key].filter(x => x.id !== id);
      if (DATA[cfg.key].length === before) return socket.emit("error", { message: `Kayıt bulunamadı: ${id}` });
      dbDelete(cfg.key, id);
      dbVersionBump();
      io.emit(`${collection}:deleted`, id);
      console.log(`✓ ${socket.user.name} → ${collection}:delete [${id}]`);
    });
  });
  socket.on("users:set",usersData=>{
    if(!hasPerm(getUser({id:socket.user.id}),"admin"))return;
    if(!Array.isArray(usersData))return;
    DATA.users=usersData.map(u=>{
      const ex=DATA.users.find(e=>e.id===u.id);
      if(ex)return{...ex,name:u.name,username:u.username,role:u.role,avatar:u.avatar};
      return{...u,passwordHash:bcrypt.hashSync(u.password||"Miheng2026!",bcrypt.genSaltSync(10)),mustChangePassword:true};
    });
    saveData(); io.emit("users:updated",DATA.users.map(sanitizeUser));
  });

  // [FIX #11] Password change with complexity
  socket.on("users:changePassword",({userId,newPassword})=>{
    const reqUser=getUser({id:socket.user.id});
    if(!hasPerm(reqUser,"admin")&&reqUser?.id!==userId)return;
    const user=DATA.users.find(u=>u.id===userId);
    if(!user)return;
    const pwErr=validatePassword(newPassword);
    if(pwErr)return socket.emit("password:changed",{ok:false,error:pwErr});
    user.passwordHash=bcrypt.hashSync(newPassword,bcrypt.genSaltSync(10));
    user.mustChangePassword=false;
    user.passwordChangedAt=Date.now(); // [FIX #16]
    saveData(); socket.emit("password:changed",{ok:true});
    console.log(`🔑 ${user.name} şifre değiştirildi`);
  });

  // [FIX] Server-side log ekleme — client log manipülasyonunu önler
  socket.on("woLog:add", ({woId, action, detail}) => {
    if(!woId || !action || typeof action !== "string") return;
    const user = getUser({id: socket.user.id});
    if(!user) return;
    const wo = DATA.workOrders.find(w => w.id === woId);
    if(!wo) return;
    const entry = { ts: new Date().toISOString(), user: user.name, action: String(action).slice(0,200), detail: String(detail||"").slice(0,500) };
    wo.log = [...(wo.log || []), entry];
    dbUpdate("workOrders", woId, { log: wo.log });
    dbVersionBump();
    // Sadece değişen WO'nun log alanını yayınla — tüm diziyi göndermek race condition yaratır
    io.emit("workOrders:patched", { id: woId, changes: { log: wo.log } });
  });

  socket.on("userPerms:set",perms=>{
    if(!hasPerm(getUser({id:socket.user.id}),"admin"))return;
    if(!perms||typeof perms!=="object"||Array.isArray(perms))return;
    DATA.userPerms=perms; saveData(); io.emit("userPerms:updated",perms);
  });

  // [FIX #10] Notification broadcast — requires edit permission
  socket.on("notification:broadcast",(data)=>{
    const user=getUser({id:socket.user.id});
    if(!user)return;
    const perms=DATA.userPerms[user.id]||DEFAULT_ROLES[user.role]?.permissions||[];
    const canBroadcast=perms.includes("admin")||perms.some(p=>p.endsWith("_edit"));
    if(!canBroadcast)return socket.emit("error",{message:"Bildirim gönderme yetkiniz yok"});
    if(typeof data!=="object"||!data.message)return;
    const safe={message:String(data.message).slice(0,500),type:data.type||"info",from:socket.user.name,timestamp:Date.now()};
    socket.broadcast.emit("notification:broadcast",safe);
  });

  socket.on("disconnect",()=>{
    console.log(`⚡ ${socket.user.name} ayrıldı`);
    connectedUsers.delete(socket.id); socketRates.delete(socket.id);
    broadcastOnlineUsers();
  });
});

function broadcastOnlineUsers(){
  const online=[],seen=new Set();
  connectedUsers.forEach(v=>{if(!seen.has(v.userId)){seen.add(v.userId);online.push({userId:v.userId,name:v.name});}});
  io.emit("users:online",online);
}

// ═══════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════
function shutdown(sig){
  console.log(`\n🛑 ${sig} — kapatılıyor...`);
  if(saveTimer)clearTimeout(saveTimer);
  saveDataSync();createBackup();
  server.close(()=>{console.log("✓ Sunucu kapatıldı.");process.exit(0);});
  setTimeout(()=>process.exit(1),5000);
}
process.on("SIGTERM",()=>shutdown("SIGTERM"));
process.on("SIGINT",()=>shutdown("SIGINT"));

// ═══════════════════════════════════════════
// START
// ═══════════════════════════════════════════
loadData();
setTimeout(createBackup,5000);
server.listen(PORT,"0.0.0.0",()=>{
  console.log(`
╔══════════════════════════════════════════════════════╗
║  MİHENK Üretim Takip Sistemi v1.1 (Güvenlik+)      ║
║  Adres:  http://0.0.0.0:${String(PORT).padEnd(33)}║
║  Veri:   ${DATA_FILE.padEnd(43)}║
║  Ortam:  ${NODE_ENV.padEnd(43)}║
║  JWT:    ${(process.env.JWT_SECRET?"env":fs.existsSync(SECRET_FILE)?"dosya":"bellek").padEnd(43)}║
║  Durum:  ${String(DATA.users.length).padStart(2)} kullanıcı hazır                         ║
╚══════════════════════════════════════════════════════╝
  `);
});
