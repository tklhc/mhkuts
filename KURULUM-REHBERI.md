# MİHENK — Tam Güvenlikli İnternete Açma Rehberi

---

## Mimari Genel Bakış

```
Kullanıcılar (telefon/PC)
       │
       ▼
 [Cloudflare]  ── DDoS koruması, WAF, SSL, bot engelleme
       │            IP gizleme (sunucu IP'si dışarıdan görünmez)
       │
       ▼
 [Nginx :443]  ── Rate limiting, güvenlik başlıkları
       │            Sadece Cloudflare IP'lerinden trafik kabul eder
       ▼
 [Node.js :3000]  ── MİHENK server.js
       │               JWT (httpOnly cookie), rol bazlı yetki
       ▼
 [data.json]     ── Şifreli disk üzerinde
 [backups/]      ── 6 saatte bir otomatik yedek
       
       ┌──────────────────────┐
       │  Opsiyonel: VPN      │
       │  WireGuard :51820    │
       │  Sadece yetkili      │
       │  cihazlar erişir     │
       └──────────────────────┘
```

**Güvenlik katmanları:** Cloudflare (DDoS/WAF) → Nginx (rate limit) → Node.js (JWT/yetki) → VPN (opsiyonel ek katman)

---

## Adım 1: Sunucu Seçimi

### KVKK Değerlendirmesi

MİHENK sistemi üretim verileri, müşteri bilgileri ve fiyatlandırma içerir. KVKK (6698 sayılı Kişisel Verilerin Korunması Kanunu) kapsamında dikkat edilmesi gerekenler:

**Yurt dışı sunucu kullanılabilir mi?**
- Açık rıza veya yeterli koruma şartıyla evet. AB sunucuları (Almanya, Finlandiya) GDPR kapsamında "yeterli koruma" sağlar.
- Ancak **en güvenli yol** Türkiye'de veri tutmaktır — hukuki risk sıfıra iner.

### Öneriler (Güvenlik Öncelikli)

| Sağlayıcı | Lokasyon | Plan | Fiyat | KVKK | Not |
|-----------|----------|------|-------|------|-----|
| **Turhost VDS** | 🇹🇷 İstanbul | VDS-2 (2C/4GB) | ~250₺/ay | ✅ Tam uyumlu | TL ödeme, TR destek |
| **Natro VDS** | 🇹🇷 İstanbul | VDS Start | ~200₺/ay | ✅ Tam uyumlu | TL ödeme |
| **Hetzner** | 🇩🇪 Almanya | CX22 (2C/4GB) | ~4.49€/ay | ⚠️ AB/GDPR | Fiyat/performans en iyi |
| **DigitalOcean** | 🇩🇪 Frankfurt | Basic (2C/2GB) | $12/ay | ⚠️ AB/GDPR | Kolay arayüz |

**Tavsiye:** Müşteri kişisel verisi (ad, telefon, adres) varsa → **Turhost/Natro (TR)**. Sadece üretim takibi, kişisel veri yoksa → **Hetzner (DE)** fiyat avantajı.

### Sunucu Kurulum Adımları

1. Seçtiğiniz sağlayıcıdan **Ubuntu 24.04** sunucu alın
2. **En az:** 2 vCPU, 2GB RAM, 40GB SSD
3. IP adresini not alın (örn: `185.XX.XX.XX`)

---

## Adım 2: Cloudflare Kurulumu (Ücretsiz)

Cloudflare ücretsiz planı bile DDoS koruması, WAF ve SSL sağlar. Sunucunuzun gerçek IP'si gizlenir.

### 2a. Cloudflare Hesabı

1. https://dash.cloudflare.com → Hesap oluştur (ücretsiz)
2. "Add a Site" → alan adınızı girin (örn: `firmaniz.com`)
3. **Free plan** seç
4. Cloudflare'in verdiği nameserver'ları alan adı sağlayıcınızda güncelleyin

### 2b. DNS Kaydı

Cloudflare DNS panelinde:

```
Tür:    A
İsim:   mihenk
Değer:  185.XX.XX.XX  (sunucu IP)
Proxy:  ✅ AÇIK (turuncu bulut)  ← ÖNEMLİ
TTL:    Auto
```

**Turuncu bulut (Proxy ON)** = Trafik Cloudflare üzerinden geçer, IP gizlenir.

### 2c. SSL Ayarı

Cloudflare Dashboard → **SSL/TLS**:
- Encryption mode: **Full (Strict)**
- Edge Certificates → Always Use HTTPS: **ON**
- Minimum TLS Version: **1.2**

### 2d. Güvenlik Kuralları

**Security → WAF:**
- Managed Rules: **ON** (ücretsiz planda da var)
- Security Level: **Medium**

**Security → Bots:**
- Bot Fight Mode: **ON**

**Security → Settings:**
- Browser Integrity Check: **ON**
- Challenge Passage: **30 minutes**

**Rules → Page Rules** (3 adet ücretsiz):
```
1. *firmaniz.com/api/login*  → Security Level: I'm Under Attack
2. *mihenk.firmaniz.com/*    → Browser Cache TTL: 1 hour
```

---

## Adım 3: Sunucuya Bağlanma

### İlk Bağlantı
```bash
ssh root@185.XX.XX.XX
```

### SSH Key Oluşturma (Bilgisayarınızda)

Henüz SSH key'iniz yoksa:

```bash
# Bilgisayarınızda (sunucuda değil!)
ssh-keygen -t ed25519 -C "taha@miheng"
# Enter'a basın (varsayılan konum)
# Şifre belirleyin (opsiyonel ama önerilen)

# Key'i sunucuya kopyala
ssh-copy-id root@185.XX.XX.XX
```

---

## Adım 4: Dosyaları Yükle ve Kur

### Bilgisayarınızdan:
```bash
scp miheng-platform.zip root@185.XX.XX.XX:/root/
```

### Sunucuda:
```bash
cd /root
apt install -y unzip
unzip miheng-platform.zip
cd miheng-platform
sudo bash setup.sh mihenk.firmaniz.com
```

### Kurulum Ne Yapar?

| Adım | Ne Yapıyor | Güvenlik Etkisi |
|------|-----------|-----------------|
| Deploy kullanıcısı | Root yerine `deploy` ile SSH | Root ele geçirilmesini önler |
| SSH sertleştirme | Key-only auth, root login kapalı | Brute-force imkansız |
| UFW güvenlik duvarı | Sadece 22, 80, 443 açık | Saldırı yüzeyi minimal |
| Fail2ban | 3 başarısız giriş → 1 saat ban | Brute-force koruması |
| Node.js + MİHENK | Uygulama kurulumu | — |
| .env güvenliği | 600 izin, güçlü JWT secret | Secret sızma önlenir |
| Systemd sandbox | ProtectSystem, PrivateTmp | İzole çalışma ortamı |
| Nginx + Cloudflare | CF IP whitelist, rate limit | DDoS koruması |
| Sağlık izleme | 5 dk'da bir kontrol | Çökme anında otomatik restart |
| Denetim logları | Başarısız giriş takibi | Sızma denemesi tespiti |
| Auto-update | Güvenlik yamaları otomatik | Bilinen açıklar kapanır |

### SSL Sertifikası (Kurulumdan sonra)

Cloudflare Full (Strict) kullanıyorsan:
1. Cloudflare → SSL/TLS → Origin Server → **Create Certificate**
2. Sunucuda:
```bash
sudo bash /usr/local/bin/install-cf-cert.sh
```
3. Sertifika ve key'i yapıştırın

---

## Adım 5: VPN Kurulumu (WireGuard)

Ekstra güvenlik katmanı. VPN açık olmadan sisteme erişilemez.

```bash
sudo bash vpn-setup.sh 5    # 5 kullanıcı için config oluştur
```

### Kullanıcılara Config Dağıtma

**Telefon için (QR kod):**
```bash
sudo qrencode -t ansiutf8 < /etc/wireguard/clients/Taha.conf
```
Kullanıcı WireGuard uygulamasını açar → QR kodu tarar → VPN açılır.

**Bilgisayar için (dosya):**
```bash
# Sunucudan bilgisayarınıza kopyalayın
scp root@185.XX.XX.XX:/etc/wireguard/clients/Taha.conf .
```

### VPN Client Kurulumu

| Platform | İndirme | Kurulum |
|----------|---------|---------|
| **iPhone** | App Store → "WireGuard" | QR kod tara |
| **Android** | Play Store → "WireGuard" | QR kod tara |
| **Windows** | wireguard.com/install | .conf dosyasını içe aktar |
| **Mac** | App Store → "WireGuard" | .conf dosyasını içe aktar |

### Tam VPN Kilidi (Opsiyonel)

MİHENK'i **sadece** VPN üzerinden erişilebilir yapmak için:

```bash
# Public erişimi kapat
sudo ufw delete allow 80/tcp
sudo ufw delete allow 443/tcp

# MİHENK'i sadece VPN interface'inde dinlet
# /opt/miheng/.env dosyasına ekle:
#   BIND_HOST=10.66.66.1
```

Bu modda: VPN açık değilse → site açılmaz. Maksimum güvenlik.

---

## Adım 6: İlk Giriş ve Kullanıcı Yönetimi

1. `https://mihenk.firmaniz.com` aç
2. `taha` / `1234` ile giriş
3. **Şifre değiştirme ekranı** → en az 8 karakter + 1 rakam
4. Yönetim → diğer kullanıcıların şifrelerini ayarla
5. Her kullanıcı ilk girişte kendi şifresini belirleyecek

---

## Günlük İşlemler

### Durum Kontrolü
```bash
sudo systemctl status miheng          # Uygulama
sudo wg show                          # VPN (kuruluysa)
sudo fail2ban-client status           # Ban durumu
cat /var/log/miheng-health.log        # Sağlık logları
cat /var/log/miheng-audit.log         # Denetim logları
```

### Güncelleme
```bash
scp yeni-dosyalar.zip deploy@SUNUCU:/tmp/
ssh deploy@SUNUCU

sudo systemctl stop miheng
sudo cp /tmp/yeni-server.js /opt/miheng/server.js
sudo cp -r /tmp/yeni-public/ /opt/miheng/public/
sudo chown -R miheng:miheng /opt/miheng
sudo systemctl start miheng
```

### Yedek
```bash
ls -la /opt/miheng/backups/                    # Yedekleri listele
sudo systemctl stop miheng
sudo cp /opt/miheng/backups/data-XXXX.json /opt/miheng/data.json
sudo chown miheng:miheng /opt/miheng/data.json
sudo systemctl start miheng
```

### Yeni VPN Kullanıcısı Ekleme
```bash
cd /etc/wireguard
wg genkey | tee clients/YeniKisi_private.key | wg pubkey > clients/YeniKisi_public.key

# wg0.conf'a ekle:
# [Peer]
# PublicKey = <YeniKisi public key>
# AllowedIPs = 10.66.66.X/32

# Config dosyası oluştur ve QR ile paylaş
sudo systemctl restart wg-quick@wg0
```

---

## Güvenlik Kontrol Listesi

Kurulumdan sonra tek tek kontrol edin:

### Ağ Güvenliği
- [ ] Cloudflare proxy aktif (turuncu bulut)
- [ ] SSL: Full (Strict) modu
- [ ] WAF kuralları aktif
- [ ] Bot koruması açık
- [ ] `sudo ufw status` → sadece gerekli portlar açık
- [ ] Sunucu IP'si dışarıdan doğrudan erişilemiyor

### Sunucu Güvenliği
- [ ] SSH key-only authentication
- [ ] Root SSH kapalı: `grep PermitRootLogin /etc/ssh/sshd_config.d/*`
- [ ] Fail2ban aktif: `sudo fail2ban-client status sshd`
- [ ] Otomatik güvenlik güncellemeleri: `dpkg -l | grep unattended`
- [ ] .env dosya izinleri: `ls -la /opt/miheng/.env` → `-rw-------`

### Uygulama Güvenliği
- [ ] Tüm varsayılan şifreler değiştirildi
- [ ] Admin dışında kimse kullanıcı yönetemiyor
- [ ] JWT secret güçlü (.env'de 128 hex karakter)
- [ ] Cookie: httpOnly + secure + sameSite

### Veri Güvenliği
- [ ] Yedekler çalışıyor: `ls /opt/miheng/backups/`
- [ ] Sağlık kontrolü: `cat /var/log/miheng-health.log`
- [ ] Denetim logları: `cat /var/log/miheng-audit.log`

### VPN (kuruluysa)
- [ ] WireGuard aktif: `sudo wg show`
- [ ] Config dosyaları güvenli: `ls -la /etc/wireguard/clients/`
- [ ] Her kullanıcının kendi config'i var

---

## Sorun Giderme

### Site açılmıyor
```bash
sudo systemctl status miheng           # 1. Servis çalışıyor mu?
curl -s http://127.0.0.1:3000/api/health   # 2. Localhost erişim
sudo nginx -t                          # 3. Nginx config doğru mu?
sudo ufw status                        # 4. Port açık mı?
dig mihenk.firmaniz.com                # 5. DNS doğru mu?
```

### "520 Error" (Cloudflare)
Sunucu yanıt vermiyor demek:
```bash
sudo systemctl restart miheng
sudo journalctl -u miheng -n 30
```

### VPN bağlanmıyor
```bash
sudo wg show                           # Sunucu tarafı
sudo ufw status | grep 51820           # Port açık mı?
sudo journalctl -u wg-quick@wg0       # WireGuard logları
```

### Çok fazla başarısız giriş
```bash
sudo fail2ban-client status sshd       # Banlı IP'ler
sudo fail2ban-client set sshd unbanip IP_ADRESI   # Ban kaldır
cat /var/log/miheng-audit.log          # Uygulama girişleri
```

### Disk doldu
```bash
df -h
# Eski yedekleri temizle (son 10'u tut)
ls -t /opt/miheng/backups/ | tail -n +11 | xargs -I {} rm /opt/miheng/backups/{}
sudo journalctl --vacuum-time=7d       # Eski logları sil
```

---

## Maliyet Özeti

| Kalem | Aylık | Not |
|-------|-------|-----|
| VPS (Hetzner CX22) | ~4.49€ (~175₺) | veya TR: ~250₺ |
| Cloudflare | 0₺ | Free plan yeterli |
| Alan adı | ~12₺ | Yıllık ~150₺ / 12 |
| SSL | 0₺ | Cloudflare veya Let's Encrypt |
| **Toplam** | **~190-260₺/ay** | |

---

## Phase 3.1 — Build-Time Babel (Production Optimizasyonu)

Babel'i build sırasında çalıştırarak runtime Babel CDN yükünü (244KB) kaldırabilirsiniz.

### Kurulum

```bash
# Sadece bir kez — devDependencies kur
npm install

# Production build yap
node build.js
```

### Ne Değişir?

| | Runtime Babel | Build-Time Babel |
|---|---|---|
| İlk yüklenme | ~2-3sn (Babel parse) | ~0.3sn |
| Toplam JS | ~1.6MB | ~350KB |
| CDN bağımlılığı | Babel + React dev | Sadece React prod |
| Ağ hatası riski | Yüksek | Düşük |

### Nasıl Çalışır?

`build.js` önce `@babel/core` kurup kurmadığını kontrol eder:
- **Kuruluysa:** JSX → JS dönüşümü build sırasında yapılır, `react.production.min.js` kullanılır, Babel CDN kaldırılır
- **Kurulu değilse:** Eski davranış, runtime Babel çalışır (geriye uyumlu)

### Not

`npm install` sırasında native modül derleme hatası alırsanız (Windows + Node 24):
```bash
# Sadece devDependencies için — pure JS, derleme gerektirmez
npm install --ignore-scripts
```
