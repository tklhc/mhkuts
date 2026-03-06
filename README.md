# MİHENK Üretim Takip Sistemi

Çok kullanıcılı, gerçek zamanlı üretim takip platformu.

## Özellikler

- 🔐 **Kullanıcı Girişi** — Her kullanıcı kendi adı ve şifresiyle giriş yapar
- 🔄 **Gerçek Zamanlı** — Yapılan değişiklikler anında tüm kullanıcılara yansır
- 💾 **Kalıcı Veri** — Tüm veriler sunucuda `data.json` dosyasında saklanır
- 👥 **Çevrimiçi Kullanıcılar** — Kim bağlı görülebilir
- 🛡️ **Yetkilendirme** — Rol bazlı erişim kontrolü

## Kurulum

### 1. Gereksinimler
- Node.js 18+ (https://nodejs.org)

### 2. Bağımlılıkları Yükle
```bash
cd miheng-platform
npm install
```

### 3. Sunucuyu Başlat
```bash
npm start
```

Sunucu http://localhost:3000 adresinde çalışır.

### 4. Ağdaki Diğer Bilgisayarlardan Erişim

Aynı ağdaki diğer bilgisayarlar, sunucunun IP adresini kullanarak erişebilir:
```
http://192.168.1.XX:3000
```

IP adresini öğrenmek için:
- Windows: `ipconfig`
- macOS/Linux: `ifconfig` veya `ip addr`

## Varsayılan Kullanıcılar

| Kullanıcı Adı | Şifre | Rol |
|---|---|---|
| taha | 1234 | Yönetici |
| ahmet | 1234 | Operatör |
| mehmet | 1234 | Operatör |
| fatma | 1234 | Üretim Müdürü |
| zeynep | 1234 | Planlama Sorumlusu |
| emre | 1234 | İzleyici |

> ⚠️ İlk girişten sonra şifreleri değiştirin!

## Dosya Yapısı

```
miheng-platform/
├── server.js          # Ana sunucu (Express + Socket.io)
├── package.json       # Bağımlılıklar
├── data.json          # Veri dosyası (otomatik oluşur)
├── public/
│   └── index.html     # React arayüz
└── README.md          # Bu dosya
```

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| PORT | 3000 | Sunucu portu |
| JWT_SECRET | miheng-secret-key... | JWT şifreleme anahtarı |

Üretim ortamında JWT_SECRET'ı mutlaka değiştirin:
```bash
JWT_SECRET=guclu-bir-sifre-koyun PORT=3000 npm start
```

## Yedekleme

Tüm veriler `data.json` dosyasında saklanır. Bu dosyayı düzenli olarak yedekleyin:
```bash
cp data.json data-backup-$(date +%Y%m%d).json
```

## Sorun Giderme

- **Bağlantı hatası**: Güvenlik duvarının 3000 portuna izin verdiğinden emin olun
- **Oturum geçersiz**: Tarayıcı çerezlerini temizleyin ve tekrar giriş yapın
- **Veri sıfırlama**: `data.json` dosyasını silin, sunucu yeniden başlayınca varsayılan verilerle oluşturur
