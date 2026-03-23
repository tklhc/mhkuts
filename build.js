const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// File order matters — this is the concatenation order
const SOURCE_FILES = [
  'src/constants.js',
  'src/seed-data.js',
  'src/components.jsx',
  'src/scheduler.js',
  'src/app-core.jsx',
  'src/pages/login.jsx',
  'src/pages/notifications.jsx',
  'src/pages/nav.jsx',
  'src/pages/dashboard.jsx',
  'src/pages/orders.jsx',
  'src/pages/workorders.jsx',
  'src/pages/planning.jsx',
  'src/pages/production.jsx',
  'src/pages/qc.jsx',
  'src/pages/coating.jsx',
  'src/pages/shipping.jsx',
  'src/pages/invoices.jsx',
  'src/pages/cutting.jsx',
  'src/pages/grinding.jsx',
  'src/pages/purchasing.jsx',
  'src/pages/stock.jsx',
  'src/pages/arge.jsx',
  'src/pages/admin.jsx',
  'src/app-render.jsx',
];

console.log('🔨 MİHENK Build System\n');

// 1) Read template
const template = fs.readFileSync('public/template.html', 'utf8');

// 2) Concatenate all source files
let scriptContent = '';
let totalLines = 0;
SOURCE_FILES.forEach(file => {
  if (!fs.existsSync(file)) { console.error(`❌ Missing: ${file}`); process.exit(1); }
  let content = fs.readFileSync(file, 'utf8');
  content = content.replace(/^\/\/ ═+\n\/\/ .*\n\/\/ ═+\n/, '');
  totalLines += content.split('\n').length;
  scriptContent += content + '\n';
});

// 3) Validate delimiters
let b = 0, p = 0, k = 0;
for (const c of scriptContent) {
  if (c === '{') b++; if (c === '}') b--;
  if (c === '(') p++; if (c === ')') p--;
  if (c === '[') k++; if (c === ']') k--;
}
if (b !== 0 || p !== 0 || k !== 0) {
  console.error(`❌ DELIMITER HATA! {${b}} (${p}) [${k}]`);
  SOURCE_FILES.forEach(file => {
    let fb = 0, fp = 0, fk = 0;
    for (const c of fs.readFileSync(file, 'utf8')) {
      if (c === '{') fb++; if (c === '}') fb--; if (c === '(') fp++; if (c === ')') fp--; if (c === '[') fk++; if (c === ']') fk--;
    }
    if (fb !== 0 || fp !== 0 || fk !== 0) console.error(`  ⚠️  ${file}: {${fb}} (${fp}) [${fk}]`);
  });
  process.exit(1);
}

// 3b) Validate JSX tag balance
const tagChecks = ['Card', 'Modal', 'Badge'];
let tagOk = true;
tagChecks.forEach(tag => {
  const opens = (scriptContent.match(new RegExp(`<${tag}[\\s>]`, 'g')) || []).length;
  const closes = (scriptContent.match(new RegExp(`</${tag}>`, 'g')) || []).length;
  if (opens !== closes) {
    console.error(`❌ JSX TAG HATA! <${tag}> opens:${opens} closes:${closes}`);
    SOURCE_FILES.forEach(file => {
      const c = fs.readFileSync(file, 'utf8');
      const fo = (c.match(new RegExp(`<${tag}[\\s>]`, 'g')) || []).length;
      const fc = (c.match(new RegExp(`</${tag}>`, 'g')) || []).length;
      if (fo !== fc) console.error(`  ⚠️  ${file}: <${tag}> opens:${fo} closes:${fc}`);
    });
    tagOk = false;
  }
});
if (!tagOk) process.exit(1);

// 4) Try build-time Babel transform (Phase 3.1)
let finalScript = scriptContent.trim();
let babelUsed = false;

try {
  const babel = require('@babel/core');
  const result = babel.transformSync(scriptContent, {
    presets: [
      ['@babel/preset-react', { runtime: 'classic' }],
      ['@babel/preset-env', { targets: { chrome: '90', firefox: '90', safari: '14' }, modules: false }],
    ],
    filename: 'app.jsx',
    sourceMaps: false,
    compact: true,
    comments: false,
  });
  finalScript = result.code;
  babelUsed = true;
  const origKB = (Buffer.byteLength(scriptContent) / 1024).toFixed(0);
  const outKB = (Buffer.byteLength(finalScript) / 1024).toFixed(0);
  console.log(`⚡ Babel build-time transform: ${origKB}KB → ${outKB}KB`);
} catch (e) {
  if (e.code === 'MODULE_NOT_FOUND') {
    console.log('ℹ️  @babel/core bulunamadı — runtime Babel kullanılıyor (npm install --save-dev @babel/core @babel/preset-react @babel/preset-env)');
  } else {
    console.error('❌ Babel transform hatası:', e.message);
    process.exit(1);
  }
}

// 5) Build index.html — babel varsa pre-transpiled script kullan
let output;
const cacheBuster = Date.now().toString(36);
const scriptTagRegex = /<script type="text\/babel" data-presets="react">[\s\S]*?{{SCRIPT_CONTENT}}[\s\S]*?<\/script>/;

if (babelUsed) {
  // Extract to external JS
  fs.writeFileSync('public/app.js', finalScript);

  // Babel CDN'e gerek yok, React production build kullan
  const prodTemplate = template
    .replace('react.development.js', 'react.production.min.js')
    .replace('react-dom.development.js', 'react-dom.production.min.js')
    .replace(/<script src="https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/babel-standalone[^"]*"><\/script>\n?/, '')
    .replace(scriptTagRegex, `<script src="/app.js?v=${cacheBuster}"></script>`);

  output = prodTemplate;
  console.log(`🚀 Production build: JS mantığı public/app.js'e taşındı (${(Buffer.byteLength(finalScript) / 1024).toFixed(0)}KB)`);
} else {
  // Extract to external JSX for dev runtime
  fs.writeFileSync('public/app.jsx', finalScript);
  output = template.replace(scriptTagRegex, `<script type="text/babel" data-presets="react" src="/app.jsx?v=${cacheBuster}"></script>`);
}

fs.writeFileSync('public/index.html', output);
const sizeKB = (Buffer.byteLength(output) / 1024).toFixed(0);
console.log(`✅ public/index.html (${sizeKB}KB, ${totalLines} satır, ${SOURCE_FILES.length} dosya)`);
console.log(`📐 Delimiter: {${b}} (${p}) [${k}] ✓`);
console.log('\n🎉 Build tamamlandı!');
