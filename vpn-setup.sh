#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# MİHENK — WireGuard VPN Kurulumu
# Sadece yetkili cihazlar erişebilsin
# Kullanım: sudo bash vpn-setup.sh [kullanıcı_sayısı]
# ═══════════════════════════════════════════════════════════════

set -e

CLIENT_COUNT=${1:-5}
VPN_PORT=51820
VPN_SUBNET="10.66.66"
VPN_SERVER_IP="${VPN_SUBNET}.1"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  MİHENK — WireGuard VPN Kurulumu                 ║"
echo "║  $CLIENT_COUNT kullanıcı için config oluşturulacak          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then echo -e "${RED}HATA: sudo bash vpn-setup.sh${NC}"; exit 1; fi

# ═══════════════════════════════════════════
# [1/4] WIREGUARD KUR
# ═══════════════════════════════════════════
echo -e "${GREEN}[1/4]${NC} WireGuard kuruluyor..."
apt install -y -qq wireguard qrencode

# ═══════════════════════════════════════════
# [2/4] SUNUCU ANAHTARLARI
# ═══════════════════════════════════════════
echo -e "${GREEN}[2/4]${NC} Anahtarlar oluşturuluyor..."
mkdir -p /etc/wireguard/clients
cd /etc/wireguard

# Sunucu anahtarları
wg genkey | tee server_private.key | wg pubkey > server_public.key
chmod 600 server_private.key

SERVER_PRIVATE=$(cat server_private.key)
SERVER_PUBLIC=$(cat server_public.key)
PUBLIC_IP=$(curl -s ifconfig.me)
INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

# ═══════════════════════════════════════════
# [3/4] SUNUCU CONFIG
# ═══════════════════════════════════════════
echo -e "${GREEN}[3/4]${NC} VPN yapılandırılıyor..."

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${VPN_SERVER_IP}/24
ListenPort = ${VPN_PORT}
PrivateKey = ${SERVER_PRIVATE}

# NAT — VPN üzerinden internete çıkış (opsiyonel)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${INTERFACE} -j MASQUERADE
EOF

# ═══════════════════════════════════════════
# [4/4] KULlANICI CONFIGLERİ
# ═══════════════════════════════════════════
echo -e "${GREEN}[4/4]${NC} Kullanıcı config'leri oluşturuluyor..."

USERS=("Taha" "Ahmet" "Fatma" "Zeynep" "Emre" "Yedek1" "Yedek2" "Yedek3" "Yedek4" "Yedek5")

for i in $(seq 1 $CLIENT_COUNT); do
  CLIENT_NAME="${USERS[$((i-1))]:-Kullanici$i}"
  CLIENT_IP="${VPN_SUBNET}.$((i+1))"
  
  # İstemci anahtarları
  wg genkey | tee "clients/${CLIENT_NAME}_private.key" | wg pubkey > "clients/${CLIENT_NAME}_public.key"
  CLIENT_PRIVATE=$(cat "clients/${CLIENT_NAME}_private.key")
  CLIENT_PUBLIC=$(cat "clients/${CLIENT_NAME}_public.key")
  
  # Sunucu config'e ekle
  cat >> /etc/wireguard/wg0.conf << EOF

# ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUBLIC}
AllowedIPs = ${CLIENT_IP}/32
EOF

  # İstemci config dosyası
  cat > "clients/${CLIENT_NAME}.conf" << EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE}
Address = ${CLIENT_IP}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC}
Endpoint = ${PUBLIC_IP}:${VPN_PORT}
AllowedIPs = ${VPN_SUBNET}.0/24
PersistentKeepalive = 25
EOF

  echo -e "  ${GREEN}✓${NC} ${CLIENT_NAME}: ${CLIENT_IP}"
done

chmod 600 /etc/wireguard/clients/*

# UFW port aç
ufw allow ${VPN_PORT}/udp comment "WireGuard VPN"

# IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p > /dev/null

# WireGuard başlat
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# QR kodları oluştur (telefon için)
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ VPN KURULUMU TAMAMLANDI!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}VPN Sunucu: ${PUBLIC_IP}:${VPN_PORT}${NC}"
echo -e "  ${BLUE}VPN Subnet: ${VPN_SUBNET}.0/24${NC}"
echo ""
echo -e "  ${YELLOW}── Config Dosyaları ──${NC}"
echo -e "  /etc/wireguard/clients/"
ls -1 /etc/wireguard/clients/*.conf 2>/dev/null | while read f; do
  echo -e "    $(basename $f)"
done

echo ""
echo -e "  ${YELLOW}── Kullanıcıya Config Gönderme ──${NC}"
echo -e "  ${BLUE}Dosya olarak:${NC} scp root@${PUBLIC_IP}:/etc/wireguard/clients/Taha.conf ."
echo -e "  ${BLUE}QR kod:${NC}       sudo qrencode -t ansiutf8 < /etc/wireguard/clients/Taha.conf"
echo ""
echo -e "  ${YELLOW}── Kullanıcı Cihaz Kurulumu ──${NC}"
echo -e "  1. WireGuard uygulamasını indir (iOS/Android/Windows/Mac)"
echo -e "  2. Config dosyasını içe aktar veya QR kodu tara"
echo -e "  3. VPN'i aç → MİHENK'e http://${VPN_SERVER_IP}:3000 ile eriş"
echo ""
echo -e "  ${YELLOW}── Sadece VPN Erişimi İçin (Opsiyonel) ──${NC}"
echo -e "  MİHENK'i sadece VPN'den erişilebilir yapmak için:"
echo -e "  1. /opt/miheng/.env dosyasında ALLOWED_ORIGINS değiştir"
echo -e "  2. Nginx config'den public erişimi kaldır"
echo -e "  3. UFW'den 80 ve 443 portlarını kapat:"
echo -e "     sudo ufw delete allow 80/tcp"
echo -e "     sudo ufw delete allow 443/tcp"
echo ""
echo -e "  ${YELLOW}── VPN Yönetim Komutları ──${NC}"
echo -e "  sudo wg show                     # VPN durumu"
echo -e "  sudo systemctl restart wg-quick@wg0  # Yeniden başlat"
echo ""
