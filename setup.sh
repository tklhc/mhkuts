#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# MİHENK Üretim Takip Sistemi v1.1 — Tam Güvenlikli VPS Kurulum
# Ubuntu 22.04/24.04
# Kullanım: sudo bash setup.sh mihenk.firmaniz.com
# ═══════════════════════════════════════════════════════════════

set -e

DOMAIN=$1
APP_DIR="/opt/miheng"
APP_USER="miheng"
DEPLOY_USER="deploy"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  MİHENK v1.1 — Tam Güvenlikli Kurulum                ║"
echo "║  Cloudflare + SSH Hardening + Fail2ban + Monitoring  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then echo -e "${RED}HATA: sudo bash setup.sh alan-adi.com${NC}"; exit 1; fi
if [ -z "$DOMAIN" ]; then
  echo -e "${YELLOW}Kullanım: sudo bash setup.sh alan-adi.com${NC}"
  echo "  Örnek: sudo bash setup.sh mihenk.firmaniz.com"
  echo "  Not: Cloudflare'den geçirilen alan adı olmalıdır."
  exit 1
fi

# ═══════════════════════════════════════════
# [1/12] SİSTEM GÜNCELLEMESİ
# ═══════════════════════════════════════════
echo -e "${GREEN}[1/12]${NC} Sistem güncelleniyor..."
apt update -qq && apt upgrade -y -qq

# ═══════════════════════════════════════════
# [2/12] DEPLOY KULLANICISI (root'tan kaçış)
# ═══════════════════════════════════════════
echo -e "${GREEN}[2/12]${NC} Deploy kullanıcısı oluşturuluyor..."
if ! id "$DEPLOY_USER" &>/dev/null; then
  adduser --disabled-password --gecos "" $DEPLOY_USER
  usermod -aG sudo $DEPLOY_USER
  # Root'un SSH anahtarını deploy kullanıcısına kopyala
  if [ -d /root/.ssh ]; then
    mkdir -p /home/$DEPLOY_USER/.ssh
    cp /root/.ssh/authorized_keys /home/$DEPLOY_USER/.ssh/ 2>/dev/null || true
    chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh
    chmod 700 /home/$DEPLOY_USER/.ssh
    chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys 2>/dev/null || true
  fi
  # sudo şifresiz (opsiyonel ama pratik)
  echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$DEPLOY_USER
  echo -e "  ${GREEN}✓${NC} '$DEPLOY_USER' kullanıcısı oluşturuldu"
else
  echo -e "  ${YELLOW}⏩${NC} '$DEPLOY_USER' zaten mevcut"
fi

# ═══════════════════════════════════════════
# [3/12] SSH SERTLEŞTIRME
# ═══════════════════════════════════════════
echo -e "${GREEN}[3/12]${NC} SSH sertleştiriliyor..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp $SSHD_CONFIG ${SSHD_CONFIG}.backup.$(date +%s)

# SSH hardening ayarları
cat > /etc/ssh/sshd_config.d/99-miheng-hardening.conf << 'SSHEOF'
# MİHENK SSH Sertleştirme
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF

# SSH key yoksa, şifreyi hemen kapatmayalım — uyaralım
if [ ! -f /home/$DEPLOY_USER/.ssh/authorized_keys ] || [ ! -s /home/$DEPLOY_USER/.ssh/authorized_keys ]; then
  echo -e "  ${RED}⚠ SSH key bulunamadı!${NC}"
  echo -e "  ${YELLOW}Şifre girişi açık bırakılıyor — SSH key ekledikten sonra kapatın.${NC}"
  echo -e "  ${YELLOW}Komut: sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-miheng-hardening.conf && sudo systemctl restart sshd${NC}"
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/99-miheng-hardening.conf
  sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config.d/99-miheng-hardening.conf
else
  echo -e "  ${GREEN}✓${NC} SSH key mevcut, şifre girişi kapatıldı"
fi

# SSH port değiştir (opsiyonel ama etkili)
SSH_PORT=22
# Uncomment ve değiştir: SSH_PORT=2222
# echo "Port $SSH_PORT" >> /etc/ssh/sshd_config.d/99-miheng-hardening.conf

systemctl restart sshd

# ═══════════════════════════════════════════
# [4/12] GÜVENLİK DUVARI (UFW)
# ═══════════════════════════════════════════
echo -e "${GREEN}[4/12]${NC} Güvenlik duvarı ayarlanıyor..."
apt install -y -qq ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp comment "SSH"
ufw allow 80/tcp comment "HTTP"
ufw allow 443/tcp comment "HTTPS"
ufw --force enable
echo -e "  ${GREEN}✓${NC} Sadece SSH($SSH_PORT), HTTP(80), HTTPS(443) açık"

# ═══════════════════════════════════════════
# [5/12] FAIL2BAN (Brute-force Koruması)
# ═══════════════════════════════════════════
echo -e "${GREEN}[5/12]${NC} Fail2ban kuruluyor..."
apt install -y -qq fail2ban

cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 600
F2BEOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "  ${GREEN}✓${NC} SSH: 3 başarısız → 1 saat ban | Nginx: 5 flood → 10 dk ban"

# ═══════════════════════════════════════════
# [6/12] NODE.JS
# ═══════════════════════════════════════════
echo -e "${GREEN}[6/12]${NC} Node.js kuruluyor..."
if ! command -v node &> /dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt install -y -qq nodejs
fi
echo -e "  Node.js $(node -v)"

# ═══════════════════════════════════════════
# [7/12] UYGULAMA KURULUMU
# ═══════════════════════════════════════════
echo -e "${GREEN}[7/12]${NC} MİHENK kuruluyor..."
if ! id "$APP_USER" &>/dev/null; then
  useradd -r -s /bin/false -d $APP_DIR $APP_USER
fi

mkdir -p $APP_DIR/backups

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/server.js" "$APP_DIR/"
cp "$SCRIPT_DIR/storage.js" "$APP_DIR/"
cp "$SCRIPT_DIR/workflow-utils.js" "$APP_DIR/"
cp "$SCRIPT_DIR/package.json" "$APP_DIR/"
cp -r "$SCRIPT_DIR/public" "$APP_DIR/"

# Güçlü JWT secret
JWT_SECRET=$(openssl rand -hex 64)

cat > $APP_DIR/.env << EOF
PORT=3000
NODE_ENV=production
JWT_SECRET=$JWT_SECRET
ALLOWED_ORIGINS=https://$DOMAIN
DATA_DIR=$APP_DIR
EOF

chmod 600 $APP_DIR/.env
chmod 700 $APP_DIR/backups

cd $APP_DIR
npm install --production 2>&1 | tail -1
chown -R $APP_USER:$APP_USER $APP_DIR

# ═══════════════════════════════════════════
# [8/12] SYSTEMD SERVİSİ
# ═══════════════════════════════════════════
echo -e "${GREEN}[8/12]${NC} Systemd servisi oluşturuluyor..."
cat > /etc/systemd/system/miheng.service << EOF
[Unit]
Description=MİHENK Üretim Takip Sistemi
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Güvenlik sertleştirme
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable miheng
systemctl start miheng
sleep 2

if systemctl is-active --quiet miheng; then
  echo -e "  ${GREEN}✓${NC} MİHENK servisi çalışıyor"
else
  echo -e "  ${RED}✗${NC} Servis başlatılamadı! journalctl -u miheng -n 20"
fi

# ═══════════════════════════════════════════
# [9/12] NGINX + CLOUDFLARE
# ═══════════════════════════════════════════
echo -e "${GREEN}[9/12]${NC} Nginx + Cloudflare yapılandırılıyor..."
apt install -y -qq nginx

# Cloudflare IP listesini indir (sadece CF'den gelen trafik kabul et)
mkdir -p /etc/nginx/snippets

cat > /etc/nginx/snippets/cloudflare-ips.conf << 'CFEOF'
# Cloudflare IPv4 — https://www.cloudflare.com/ips-v4
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
# Cloudflare IPv6
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
CFEOF

# Cloudflare IP güncelleme script'i
cat > /usr/local/bin/update-cloudflare-ips.sh << 'UPDATEEOF'
#!/bin/bash
# Cloudflare IP listelerini güncelle
CF_FILE="/etc/nginx/snippets/cloudflare-ips.conf"
echo "# Cloudflare IPs — updated $(date)" > $CF_FILE
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
  echo "set_real_ip_from $ip;" >> $CF_FILE
done
for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
  echo "set_real_ip_from $ip;" >> $CF_FILE
done
echo "real_ip_header CF-Connecting-IP;" >> $CF_FILE
nginx -t && systemctl reload nginx
UPDATEEOF
chmod +x /usr/local/bin/update-cloudflare-ips.sh

# Rate limiting
cat > /etc/nginx/sites-available/miheng << NGINXEOF
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=30r/s;

server {
    listen 80;
    server_name $DOMAIN;

    # Cloudflare gerçek IP
    include /etc/nginx/snippets/cloudflare-ips.conf;

    # Güvenlik başlıkları
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Sunucu bilgisini gizle
    server_tokens off;

    # Login endpoint — sıkı rate limit
    location /api/login {
        limit_req zone=login_limit burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # API — orta rate limit
    location /api/ {
        limit_req zone=api_limit burst=50 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        client_max_body_size 5M;
    }

    # Socket.IO — WebSocket desteği
    location /socket.io/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    # Statik dosyalar
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_valid 200 1h;
    }

    # Hassas dosyaları engelle
    location ~ /\. { deny all; }
    location ~ \.(env|json|bak|log)$ { deny all; }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/miheng /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ═══════════════════════════════════════════
# [10/12] SSL (Cloudflare Modu)
# ═══════════════════════════════════════════
echo -e "${GREEN}[10/12]${NC} SSL yapılandırılıyor..."
echo ""
echo -e "  ${YELLOW}SSL için iki seçenek var:${NC}"
echo ""
echo -e "  ${BLUE}A) Cloudflare Full (Strict) — ÖNERİLEN${NC}"
echo "     Cloudflare Dashboard → SSL/TLS → Full (Strict)"
echo "     Origin Certificate oluşturup sunucuya yükle"
echo ""
echo -e "  ${BLUE}B) Let's Encrypt — Cloudflare kullanmıyorsan${NC}"
echo "     sudo certbot --nginx -d $DOMAIN"
echo ""

# Let's Encrypt'i yükle (her iki durumda da hazır olsun)
apt install -y -qq certbot python3-certbot-nginx

# Cloudflare Origin Certificate dizini
mkdir -p /etc/ssl/cloudflare

echo -e "  ${YELLOW}Cloudflare Origin Certificate kurulumu için:${NC}"
echo "  sudo bash /usr/local/bin/install-cf-cert.sh"

# Cloudflare cert kurulum yardımcısı
cat > /usr/local/bin/install-cf-cert.sh << 'CERTEOF'
#!/bin/bash
echo "Cloudflare Origin Certificate Kurulumu"
echo "======================================="
echo "1. Cloudflare Dashboard → SSL/TLS → Origin Server → Create Certificate"
echo "2. PEM key ve certificate'ı kopyalayın"
echo ""
read -p "Certificate dosyasını yapıştırmak için hazır mısınız? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Certificate'ı yapıştırın (bitince Ctrl+D):"
  cat > /etc/ssl/cloudflare/cert.pem
  echo "Private Key'i yapıştırın (bitince Ctrl+D):"
  cat > /etc/ssl/cloudflare/key.pem
  chmod 600 /etc/ssl/cloudflare/key.pem
  
  # Nginx config güncelle
  DOMAIN=$(grep server_name /etc/nginx/sites-available/miheng | head -1 | awk '{print $2}' | tr -d ';')
  sed -i "s/listen 80;/listen 443 ssl;\n    listen 80;\n    ssl_certificate \/etc\/ssl\/cloudflare\/cert.pem;\n    ssl_certificate_key \/etc\/ssl\/cloudflare\/key.pem;/" /etc/nginx/sites-available/miheng
  nginx -t && systemctl reload nginx
  echo "✓ SSL kuruldu!"
fi
CERTEOF
chmod +x /usr/local/bin/install-cf-cert.sh

# ═══════════════════════════════════════════
# [11/12] İZLEME VE UYARILAR
# ═══════════════════════════════════════════
echo -e "${GREEN}[11/12]${NC} İzleme ve uyarı sistemi kuruluyor..."

# Health check script
cat > /usr/local/bin/miheng-health.sh << 'HEALTHEOF'
#!/bin/bash
# MİHENK Sağlık Kontrolü
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/api/health 2>/dev/null)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ "$STATUS" != "200" ]; then
  echo "[$TIMESTAMP] UYARI: MİHENK yanıt vermiyor (HTTP $STATUS)" >> /var/log/miheng-health.log
  systemctl restart miheng
  echo "[$TIMESTAMP] MİHENK yeniden başlatıldı" >> /var/log/miheng-health.log
  # Opsiyonel: Telegram/e-posta bildirimi buraya eklenebilir
fi

# Disk kullanımı kontrolü
DISK_USAGE=$(df /opt/miheng | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "[$TIMESTAMP] UYARI: Disk kullanımı %$DISK_USAGE" >> /var/log/miheng-health.log
fi

# Bellek kontrolü
MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -gt 90 ]; then
  echo "[$TIMESTAMP] UYARI: RAM kullanımı %$MEM_USAGE" >> /var/log/miheng-health.log
fi
HEALTHEOF
chmod +x /usr/local/bin/miheng-health.sh

# Login izleme script'i — şüpheli girişleri logla
cat > /usr/local/bin/miheng-audit.sh << 'AUDITEOF'
#!/bin/bash
# Son 1 saatteki giriş denemelerini kontrol et
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
FAILED=$(journalctl -u miheng --since "1 hour ago" --no-pager 2>/dev/null | grep -c "şifre hatalı" || echo "0")
SUCCESS=$(journalctl -u miheng --since "1 hour ago" --no-pager 2>/dev/null | grep -c "giriş yaptı" || echo "0")
BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")

if [ "$FAILED" -gt 10 ]; then
  echo "[$TIMESTAMP] UYARI: Son 1 saatte $FAILED başarısız giriş denemesi!" >> /var/log/miheng-audit.log
fi
if [ "$BANNED" -gt 0 ]; then
  echo "[$TIMESTAMP] Fail2ban: $BANNED IP banlı" >> /var/log/miheng-audit.log
fi
AUDITEOF
chmod +x /usr/local/bin/miheng-audit.sh

# Cron jobs
(crontab -l 2>/dev/null; cat << 'CRONEOF'
# MİHENK Otomatik Görevler
*/5 * * * * /usr/local/bin/miheng-health.sh
0 * * * * /usr/local/bin/miheng-audit.sh
0 */6 * * * cp /opt/miheng/data.json /opt/miheng/backups/data-$(date +\%Y\%m\%d-\%H\%M).json 2>/dev/null
0 3 * * 0 /usr/local/bin/update-cloudflare-ips.sh 2>/dev/null
CRONEOF
) | sort -u | crontab -

# Logrotate
cat > /etc/logrotate.d/miheng << 'LREOF'
/var/log/miheng-*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root root
}
LREOF

echo -e "  ${GREEN}✓${NC} Sağlık kontrolü: 5 dk'da bir | Denetim: saatte bir | Yedek: 6 saatte bir"

# ═══════════════════════════════════════════
# [12/12] OTOMATİK GÜNCELLEMELer
# ═══════════════════════════════════════════
echo -e "${GREEN}[12/12]${NC} Otomatik güvenlik güncellemeleri ayarlanıyor..."
apt install -y -qq unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true

# ═══════════════════════════════════════════
# ÖZET
# ═══════════════════════════════════════════
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "?.?.?.?")
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ TAM GÜVENLİKLİ KURULUM TAMAMLANDI!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Domain:     ${BLUE}$DOMAIN${NC}"
echo -e "  🖥  Sunucu IP:  ${BLUE}$PUBLIC_IP${NC}"
echo -e "  📁 Uygulama:   $APP_DIR"
echo -e "  🔒 Ortam:      production"
echo ""
echo -e "  ${YELLOW}── Giriş Bilgileri ──${NC}"
echo -e "  Kullanıcı: taha  |  Şifre: 1234"
echo -e "  ${RED}⚠ İlk girişte yeni şifre belirlemeniz istenecektir!${NC}"
echo ""
echo -e "  ${YELLOW}── Kalan Adımlar ──${NC}"
echo -e "  1. ${BLUE}Cloudflare'de DNS ekle:${NC}"
echo -e "     A kaydı: $DOMAIN → $PUBLIC_IP (Proxy: ON / turuncu bulut)"
echo ""
echo -e "  2. ${BLUE}Cloudflare SSL ayarla:${NC}"
echo -e "     SSL/TLS → Full (Strict)"
echo -e "     Origin Server → Create Certificate → sunucuya yükle:"
echo -e "     sudo bash /usr/local/bin/install-cf-cert.sh"
echo ""
echo -e "  3. ${BLUE}Cloudflare güvenlik kuralları:${NC}"
echo -e "     Security → WAF → Enable"
echo -e "     Security → Bots → Block (AI bots, scrapers)"
echo ""
echo -e "  4. ${BLUE}(Opsiyonel) VPN ekle — iç ağ güvenliği:${NC}"
echo -e "     sudo bash vpn-setup.sh"
echo ""
echo -e "  ${YELLOW}── Faydalı Komutlar ──${NC}"
echo -e "  sudo systemctl status miheng        # Uygulama durumu"
echo -e "  sudo journalctl -u miheng -f        # Canlı loglar"
echo -e "  sudo fail2ban-client status         # Ban durumu"
echo -e "  cat /var/log/miheng-health.log      # Sağlık logları"
echo -e "  cat /var/log/miheng-audit.log       # Denetim logları"
echo ""
echo -e "  ${YELLOW}── SSH Bağlantısı ──${NC}"
echo -e "  ssh deploy@$PUBLIC_IP"
echo -e "  ${RED}⚠ SSH key yoksa: önce key ekleyin, sonra şifre girişini kapatın${NC}"
echo ""
