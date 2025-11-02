# 🕵️‍♂️ Process Network Sniffer GUI (CustomTkinter + Treeview)

⚡ **Windows / Linux için hafif, donmayan süreç-tabanlı ağ dinleyici (sniffer)**  
Psutil ile PID/Process eşleme, Scapy ile TCP/UDP dinleme; QUIC/HTTP3 ve DNS etiketleri, filtre, CSV dışa aktarım, panoya kopyalama ve performans odaklı GUI güncellemeleri içerir.

---

## 🚀 Özellikler
- 🧊 **Donma fixleri**
  - Reverse DNS varsayılan **kapalı** ✅
  - Reverse DNS: LRU cache, **özel IP’ler** ve **DNS paketlerinde çözümleme yok**
  - GUI tick başına **en fazla 200 paket** işleme
  - **Maks 5000 satır**; aşınca eskileri otomatik temizler
  - `psutil.net_connections` güncelleme aralığı **5 sn**
- 💻 **Çekirdek**
  - TCP/UDP sniff, PID/Process/Path eşleme
  - QUIC/HTTP3 ve DNS **etiketleri**
  - Filtre: PID veya process adı, protokol (all/tcp/udp)
  - **CSV dışa aktar**, seçili / tümünü **panoya kopyala**
- ⌨️ **Kısayollar**
  - `Ctrl + C` → seçili satır(lar)ı kopyala
  - `Ctrl + S` → CSV olarak kaydet

---

## 🧭 Ekran Alanları
🕒 Time | ⚙️ PID | 🧩 Process | 📂 Path | 🔌 Proto | 🌍 Source | 🎯 Destination | 📦 Len | 🧾 Payload (önizleme)

---

## 🔧 Kurulum

### 🪟 Windows
1️⃣ **Npcap** kurun → https://npcap.com  
2️⃣ Python 3.10+ önerilir  
3️⃣ Terminalde:
```bash
pip install -r requirements.txt
```
4️⃣ Yönetici olarak çalıştırmanız gerekebilir

### 🐧 Linux
- `sudo` ile çalıştırın (raw socket için)
- Python 3.10+ ve libpcap mevcut olmalı
```bash
pip install -r requirements.txt
```

---

## ▶️ Çalıştırma
```bash
python process_sniffer_gui.py
```

- **Start** → Dinlemeyi başlat  
- **Stop** → Durdur  
- 🔍 **Reverse DNS** kutusunu isterseniz açın (yavaşlatabilir)
- 🔎 **Filtre** kutusuna:
  - PID (sayı) → sadece o PID’i gösterir  
  - Process adı parçası → adı içerenleri gösterir  
- Protokol menüsünden `all/tcp/udp` seçebilirsiniz

---

## ⚙️ Performans İpuçları
💡 Reverse DNS’i yalnızca gerektiğinde açın  
🚀 Filtre kullanmak GUI’yi hızlandırır  
🧾 CSV kaydı binlerce satırda birkaç saniye sürebilir

---

## 🧠 Bilinen Notlar
- 🪟 Windows’ta **Npcap** gereklidir  
- 🔐 Process path için bazen ek izin gerekebilir  
- 🌐 UDP/443 trafiği **QUIC/HTTP3** etiketiyle gösterilir

---

## 🔒 Güvenlik
Bu araç yalnızca **yerel makinenizdeki trafiği analiz eder.**  
Ağ politikalarınızı ve yerel mevzuatı ihlal etmeyecek şekilde kullanın ⚖️

---

## 📜 Lisans
MIT — ayrıntı için `LICENSE` dosyasına bakın.

---

## ❤️ Teşekkürler
- 🐍 [Scapy](https://scapy.net/)
- ⚙️ [psutil](https://github.com/giampaolo/psutil)
- 🎨 [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
