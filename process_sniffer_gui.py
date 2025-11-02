"""
Eklemeler:
- AsyncSniffer (CPU yükü az)
- Thread-safe QueueHandler logging (GUI freeze fix)
- Arayüz seçimi (iface ComboBox)
"""

import threading
import queue
import time
import os
import socket
import psutil
import logging
from datetime import datetime
from scapy.all import AsyncSniffer, IP, TCP, UDP, raw, get_if_list
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
UPDATE_CONNECTIONS_INTERVAL = 5.0
PAYLOAD_PREVIEW_LEN = 200
GUI_MAX_ROWS = 5000
GUI_BATCH_PER_TICK = 200
# ------------------------------------------------

packet_q = queue.Queue(maxsize=PACKET_QUEUE_MAX)
stop_sniffer = threading.Event()
conn_map = {}
conn_map_lock = threading.Lock()

# -------- Thread-safe Logging -----------
log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    """Thread-safe handler that sends logs to a queue."""
    def __init__(self, log_q):
        super().__init__()
        self.log_q = log_q
    def emit(self, record):
        self.log_q.put(self.format(record))

logger = logging.getLogger("sniffer")
logger.setLevel(logging.INFO)
handler = QueueHandler(log_queue)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# -------- Yardımcılar: ağ & eşleme --------
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
        a = [int(x) for x in ip.split(".")]
        if a[0] == 10 or a[0] == 127: return True
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

# ------------------------- GUI -------------------------
class NetSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.local_ips = get_local_ips()
        self.running = False
        self.conn_thread = None
        self.sniff_thread = None
        self.sniffer = None
        self.selected_iface = None

        self.setup_ui()
        self.root.after(200, self.update_gui)
        self.root.after(300, self.process_log_queue)

    def setup_ui(self):
        if CTK_AVAILABLE:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("green")
        self.root.title("Process Network Sniffer (AsyncSniffer + QueueLog)")
        self.root.geometry("1300x750")

        top = ctk.CTkFrame(self.root) if CTK_AVAILABLE else ttk.Frame(self.root)
        top.pack(fill="x", pady=5)

        # Butonlar
        self.start_btn = ctk.CTkButton(top, text="Start", command=self.toggle_sniffer) if CTK_AVAILABLE else ttk.Button(top, text="Start", command=self.toggle_sniffer)
        self.stop_btn = ctk.CTkButton(top, text="Stop", command=self.toggle_sniffer, state="disabled") if CTK_AVAILABLE else ttk.Button(top, text="Stop", command=self.toggle_sniffer, state="disabled")
        self.clear_btn = ctk.CTkButton(top, text="Clear", command=self.clear_table) if CTK_AVAILABLE else ttk.Button(top, text="Clear", command=self.clear_table)
        for b in [self.start_btn, self.stop_btn, self.clear_btn]:
            b.pack(side="left", padx=5)

        # Arayüz seçimi
        ttk.Label(top, text="Interface:").pack(side="left", padx=5)
        self.iface_var = tk.StringVar()
        iface_list = get_if_list()
        self.iface_box = ttk.Combobox(top, values=iface_list, textvariable=self.iface_var, width=20)
        if iface_list:
            self.iface_box.set(iface_list[0])
        self.iface_box.pack(side="left", padx=5)

        # Tablo
        columns = ("Time", "PID", "Process", "Proto", "Source", "Destination", "Len", "Payload")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=160, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        y_scroll = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y_scroll.set)
        y_scroll.pack(side="right", fill="y")

    def toggle_sniffer(self):
        if not self.running:
            self.running = True
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            stop_sniffer.clear()
            self.selected_iface = self.iface_var.get()
            logger.info(f"Sniffer started on interface: {self.selected_iface}")

            # Conn map thread
            self.conn_thread = threading.Thread(target=conn_map_updater, daemon=True)
            self.conn_thread.start()

            # AsyncSniffer
            self.sniffer = AsyncSniffer(
                iface=self.selected_iface,
                prn=lambda pkt: packet_q.put(pkt) if not packet_q.full() else None,
                filter="tcp or udp",
                store=False
            )
            self.sniffer.start()
        else:
            stop_sniffer.set()
            if self.sniffer:
                self.sniffer.stop()
            self.running = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            logger.info("Sniffer stopped")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def update_gui(self):
        processed = 0
        try:
            while processed < GUI_BATCH_PER_TICK:
                pkt = packet_q.get_nowait()
                self.handle_packet(pkt)
                processed += 1
        except queue.Empty:
            pass
        self.root.after(200, self.update_gui)

    def process_log_queue(self):
        """Thread-safe log kuyruğundaki mesajları GUI’ye ekle."""
        try:
            while True:
                msg = log_queue.get_nowait()
                self.add_row(["INFO", "-", msg, "-", "-", "-", "-", "-"])
        except queue.Empty:
            pass
        self.root.after(500, self.process_log_queue)

    def add_row(self, values):
        if len(self.tree.get_children()) >= GUI_MAX_ROWS:
            for iid in self.tree.get_children()[:500]:
                self.tree.delete(iid)
        self.tree.insert("", "end", values=values)
        self.tree.yview_moveto(1)

    def handle_packet(self, pkt):
        try:
            local_ips = get_local_ips()
            pid, pname, key = map_packet_to_process(pkt, local_ips)
            s = pkt_summary(pkt)
            row = [
                s["time"],
                pid or "-",
                pname or "-",
                s["proto"],
                f"{s['src']}:{s['sport']}",
                f"{s['dst']}:{s['dport']}",
                s["payload_len"],
                s["payload_preview"][:120]
            ]
            self.add_row(row)
        except Exception as e:
            logger.error(f"Packet parse error: {e}")

# ------------------------ main ------------------------
if __name__ == "__main__":
    root = ctk.CTk() if CTK_AVAILABLE else tk.Tk()
    app = NetSnifferGUI(root)
    root.mainloop()
    stop_sniffer.set()
