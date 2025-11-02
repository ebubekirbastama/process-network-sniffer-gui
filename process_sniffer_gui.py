"""
Process Network Sniffer GUI (CustomTkinter + Treeview)
- Donma fix:
  * Reverse DNS varsayılan KAPALI + checkbox
  * Reverse DNS: LRU cache, özel IP’leri ve DNS paketi çözme YOK
  * Her turda en fazla 200 paket işleme
  * Maks 5000 satır
  * net_connections güncelleme aralığı 5sn
- Özellikler:
  * TCP/UDP sniff, PID/Process/Path eşleme
  * QUIC/HTTP3 ve DNS etiketleri
  * Filtre: PID veya process adı, protokol
  * CSV dışa aktar, seçili / tümünü panoya kopyala
"""

import threading
import queue
import time
import os
import socket
import psutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, raw
import re
import tkinter as tk
from tkinter import ttk
from functools import lru_cache

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except Exception:
    CTK_AVAILABLE = False

# ------------------- AYARLAR -------------------
PACKET_QUEUE_MAX = 2000
UPDATE_CONNECTIONS_INTERVAL = 5.0  # daha seyrek
PAYLOAD_PREVIEW_LEN = 200
GUI_MAX_ROWS = 5000
GUI_BATCH_PER_TICK = 200  # her 200ms'de en fazla 200 paket
# ------------------------------------------------

packet_q = queue.Queue(maxsize=PACKET_QUEUE_MAX)
stop_sniffer = threading.Event()
conn_map = {}
conn_map_lock = threading.Lock()

# ----------- Yardımcılar: ağ & eşleme -----------

def get_local_ips():
    ips = set()
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ips.add(addr.address)
    ips.add("127.0.0.1")
    return ips

def is_private_or_local(ip):
    try:
        a = ip.split(".")
        a = [int(x) for x in a]
        if a[0] == 10: return True
        if a[0] == 127: return True
        if a[0] == 192 and a[1] == 168: return True
        if a[0] == 172 and 16 <= a[1] <= 31: return True
    except Exception:
        pass
    return False

def build_conn_map():
    global conn_map
    new_map = {}
    for c in psutil.net_connections(kind='inet'):
        if not c.laddr:
            continue
        proto = 'tcp' if c.type == socket.SOCK_STREAM else 'udp'
        laddr_ip = c.laddr.ip
        laddr_port = c.laddr.port
        pid = c.pid
        pname = None
        try:
            if pid:
                pname = psutil.Process(pid).name()
        except Exception:
            pass
        new_map[(proto, laddr_ip, laddr_port)] = (pid, pname)
    with conn_map_lock:
        conn_map = new_map

def conn_map_updater():
    while not stop_sniffer.is_set():
        build_conn_map()
        time.sleep(UPDATE_CONNECTIONS_INTERVAL)

def map_packet_to_process(pkt, local_ips):
    if IP not in pkt:
        return (None, None, None)
    ip = pkt[IP]
    proto = 'tcp' if TCP in pkt else ('udp' if UDP in pkt else None)
    if not proto:
        return (None, None, None)

    src, dst = ip.src, ip.dst
    sport = pkt.sport if hasattr(pkt, 'sport') else None
    dport = pkt.dport if hasattr(pkt, 'dport') else None

    if src in local_ips:
        laddr_ip, lport = src, sport
    elif dst in local_ips:
        laddr_ip, lport = dst, dport
    else:
        return (None, None, None)

    with conn_map_lock:
        key = (proto, laddr_ip, lport)
        if key in conn_map:
            return (*conn_map[key], key)
        # farklı arayüz IP eşleşmesi için port wildcard
        for (p_proto, p_ip, p_port), (pid, pname) in conn_map.items():
            if p_proto == proto and p_port == lport:
                return (pid, pname, (p_proto, p_ip, p_port))
    return (None, None, None)

def pkt_summary(pkt):
    if IP not in pkt:
        return {}
    ip = pkt[IP]
    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    sport = pkt.sport if hasattr(pkt, 'sport') else None
    dport = pkt.dport if hasattr(pkt, 'dport') else None
    payload = b""
    try:
        if TCP in pkt:
            payload = raw(pkt[TCP].payload)
        elif UDP in pkt:
            payload = raw(pkt[UDP].payload)
    except Exception:
        pass
    preview = payload[:PAYLOAD_PREVIEW_LEN].decode('utf-8', errors='replace') if payload else ""
    return {
        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'proto': proto,
        'src': ip.src,
        'dst': ip.dst,
        'sport': sport,
        'dport': dport,
        'payload_preview': preview,
        'payload_len': len(payload)
    }

def scapy_packet_callback(pkt):
    try:
        packet_q.put(pkt, timeout=0.05)
    except queue.Full:
        # drop oldest
        try:
            packet_q.get_nowait()
            packet_q.put(pkt, timeout=0.01)
        except Exception:
            pass

def sniffer_thread():
    sniff(prn=scapy_packet_callback, filter="tcp or udp", store=False, stop_filter=lambda x: stop_sniffer.is_set())

# ------------------------- GUI -------------------------

class NetSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.local_ips = get_local_ips()
        self.running = False
        self.conn_thread = None
        self.sniff_thread = None

        self.setup_ui()
        # Kısayollar
        self.root.bind("<Control-c>", lambda e: self.copy_selected())
        self.root.bind("<Control-s>", lambda e: self.save_log())
        self.root.after(200, self.update_gui)

    def setup_ui(self):
        if CTK_AVAILABLE:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("green")
            self.root.title("Process Network Sniffer (Tablo)")
            self.root.geometry("1300x750")
        else:
            self.root.title("Process Network Sniffer")
            self.root.geometry("1300x750")

        # Üst çubuk
        top = ctk.CTkFrame(self.root) if CTK_AVAILABLE else ttk.Frame(self.root)
        top.pack(fill="x", pady=5)
        btn_style = {"padx": 5, "pady": 3}

        if CTK_AVAILABLE:
            self.start_btn = ctk.CTkButton(top, text="Start", command=self.toggle_sniffer)
            self.stop_btn = ctk.CTkButton(top, text="Stop", command=self.toggle_sniffer, state="disabled")
            self.clear_btn = ctk.CTkButton(top, text="Clear", command=self.clear_table)
            self.copy_btn = ctk.CTkButton(top, text="Copy Seçilen", command=self.copy_selected)
            self.copy_all_btn = ctk.CTkButton(top, text="Copy Tümü", command=self.copy_all)
            self.save_btn = ctk.CTkButton(top, text="Save Log (CSV)", command=self.save_log)
        else:
            self.start_btn = ttk.Button(top, text="Start", command=self.toggle_sniffer)
            self.stop_btn = ttk.Button(top, text="Stop", command=self.toggle_sniffer, state="disabled")
            self.clear_btn = ttk.Button(top, text="Clear", command=self.clear_table)
            self.copy_btn = ttk.Button(top, text="Copy Seçilen", command=self.copy_selected)
            self.copy_all_btn = ttk.Button(top, text="Copy Tümü", command=self.copy_all)
            self.save_btn = ttk.Button(top, text="Save Log (CSV)", command=self.save_log)

        for b in [self.start_btn, self.stop_btn, self.clear_btn, self.copy_btn, self.copy_all_btn, self.save_btn]:
            b.pack(side="left", **btn_style)

        # Filtre ve protokol
        self.filter_entry = ttk.Entry(top)
        self.filter_entry.pack(side="left", padx=5, fill="x", expand=True)

        self.proto_var = ctk.StringVar(value="all") if CTK_AVAILABLE else tk.StringVar(value="all")
        self.proto_menu = ttk.Combobox(top, values=["all", "tcp", "udp"], textvariable=self.proto_var, width=6)
        self.proto_menu.pack(side="right", padx=5)

        # Reverse DNS toggle (varsayılan kapalı)
        self.rdns_var = ctk.BooleanVar(value=False) if CTK_AVAILABLE else tk.BooleanVar(value=False)
        rdns_text = "Reverse DNS (dikkat: yavaşlatır)" 
        self.rdns_chk = ctk.CTkCheckBox(top, text=rdns_text, variable=self.rdns_var) if CTK_AVAILABLE else ttk.Checkbutton(top, text=rdns_text, variable=self.rdns_var)
        self.rdns_chk.pack(side="right", padx=10)

        # Tablo
        columns = ("Time", "PID", "Process", "Path", "Proto", "Source", "Destination", "Len", "Payload")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            self.tree.heading(col, text=col)
            if col in ["Path", "Payload"]:
                self.tree.column(col, width=320, anchor="w")
            elif col in ["Source", "Destination"]:
                self.tree.column(col, width=220, anchor="w")
            else:
                self.tree.column(col, width=120, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbars
        y_scroll = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(self.tree, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        y_scroll.pack(side="right", fill="y")
        x_scroll.pack(side="bottom", fill="x")

    def toggle_sniffer(self):
        if not self.running:
            self.running = True
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            stop_sniffer.clear()
            self.conn_thread = threading.Thread(target=conn_map_updater, daemon=True)
            self.conn_thread.start()
            self.sniff_thread = threading.Thread(target=sniffer_thread, daemon=True)
            self.sniff_thread.start()
            self.add_row(["INFO", "-", "Sniffer Started", "", "", "", "", "", ""])
        else:
            stop_sniffer.set()
            self.running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.add_row(["INFO", "-", "Sniffer Stopped", "", "", "", "", "", ""])

    def add_row(self, values):
        # satır limiti
        if len(self.tree.get_children()) >= GUI_MAX_ROWS:
            # en eski 500'ü sil
            for iid in self.tree.get_children()[:500]:
                self.tree.delete(iid)
        self.tree.insert("", "end", values=values)
        self.tree.yview_moveto(1)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def save_log(self):
        fn = f"sniffer_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        headers = ["Time", "PID", "Process", "Path", "Proto", "Source", "Destination", "Len", "Payload"]
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(",".join(headers) + "\n")
                for item in self.tree.get_children():
                    row = [str(v) for v in self.tree.item(item)["values"]]
                    row = [v if "," not in v else f"\"{v}\"" for v in row]
                    f.write(",".join(row) + "\n")
            self.add_row(["INFO", "-", "Log Saved", fn, "", "", "", "", ""])
        except Exception as e:
            self.add_row(["ERROR", "-", f"CSV hata: {e}", "", "", "", "", "", ""])

    def copy_selected(self):
        try:
            selected = self.tree.selection()
            if not selected:
                return
            rows = []
            for item in selected:
                row = [str(v) for v in self.tree.item(item)["values"]]
                row = [v if "," not in v else f"\"{v}\"" for v in row]
                rows.append(",".join(row))
            data = "\n".join(rows)
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            self.add_row(["INFO", "-", "Seçilen satır(lar) panoya kopyalandı", "", "", "", "", "", ""])
        except Exception as e:
            self.add_row(["ERROR", "-", f"Kopyalama hatası: {e}", "", "", "", "", "", ""])

    def copy_all(self):
        try:
            rows = []
            headers = ["Time", "PID", "Process", "Path", "Proto", "Source", "Destination", "Len", "Payload"]
            rows.append(",".join(headers))
            for item in self.tree.get_children():
                row = [str(v) for v in self.tree.item(item)["values"]]
                row = [v if "," not in v else f"\"{v}\"" for v in row]
                rows.append(",".join(row))
            data = "\n".join(rows)
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            self.add_row(["INFO", "-", "Tablonun tamamı panoya kopyalandı", "", "", "", "", "", ""])
        except Exception as e:
            self.add_row(["ERROR", "-", f"Kopyalama hatası: {e}", "", "", "", "", "", ""])

    def update_gui(self):
        # Her tick’te en fazla GUI_BATCH_PER_TICK paket işle
        processed = 0
        try:
            while processed < GUI_BATCH_PER_TICK:
                pkt = packet_q.get_nowait()
                self.handle_packet(pkt)
                processed += 1
        except queue.Empty:
            pass
        self.root.after(200, self.update_gui)

    # ----------- DNS çözümleme: güvenli & cache'li -----------
    @lru_cache(maxsize=1000)
    def safe_rdns(self, ip):
        # Özel IP veya loopback → çözme
        if is_private_or_local(ip):
            return ip
        try:
            # 100ms gecikmeleri engellemek için timeout (global yok; gethostbyaddr bloklar)
            # Bloklamayı azaltmak için sadece RDNS açıkken ve nadiren kullanacağız.
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def handle_packet(self, pkt):
        def get_proc_exe_path(pid):
            try:
                return psutil.Process(pid).exe()
            except Exception:
                return "-"

        def clean_payload(data):
            if not data:
                return ""
            text = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in data)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()

        try:
            local_ips = get_local_ips()
            pid, pname, key = map_packet_to_process(pkt, local_ips)
            s = pkt_summary(pkt)
            proto = s.get("proto", "").lower()
            if self.proto_var.get() != "all" and self.proto_var.get() != proto:
                return

            userfilter = self.filter_entry.get().strip()
            if userfilter:
                if userfilter.isdigit():
                    if not pid or str(pid) != userfilter:
                        return
                else:
                    if not pname or userfilter.lower() not in pname.lower():
                        return

            # Etiketler
            label = ""
            if proto == "udp" and (str(s["sport"]) == "443" or str(s["dport"]) == "443"):
                label = "QUIC/HTTP3"
            elif proto == "udp" and (str(s["sport"]) == "53" or str(s["dport"]) == "53"):
                label = "DNS"

            # Reverse DNS sadece checkbox açıksa, DNS paketlerinde ASLA yapma
            use_rdns = bool(self.rdns_var.get())
            if use_rdns and label != "DNS":
                src_disp = self.safe_rdns(s["src"])
                dst_disp = self.safe_rdns(s["dst"])
            else:
                src_disp = s["src"]
                dst_disp = s["dst"]

            proc_path = get_proc_exe_path(pid)
            payload = clean_payload(s["payload_preview"])
            proto_disp = f"{proto.upper()} ({label})" if label else proto.upper()

            row = [
                s["time"],
                pid or "-",
                pname or "-",
                proc_path,
                proto_disp,
                f"{src_disp}:{s['sport']}",
                f"{dst_disp}:{s['dport']}",
                s["payload_len"],
                payload[:200]
            ]
            self.add_row(row)
        except Exception as e:
            self.add_row(["ERROR", "-", str(e), "", "", "", "", "", ""])

# ------------------------ main ------------------------

if __name__ == "__main__":
    root = ctk.CTk() if CTK_AVAILABLE else tk.Tk()
    app = NetSnifferGUI(root)
    root.mainloop()
    stop_sniffer.set()
