import tkinter as tk
from scapy.all import sniff, DNS, DNSQR
from collections import Counter
from datetime import datetime
import threading, os, csv

TRACKERS = ["doubleclick", "facebook", "criteo", "taboola", "bing", "google-analytics", "googletagmanager", "pinimg", "pinterest", "snap", "linkedin", "msn", "srtb"]

counter = Counter()
running = False
last_site = ""
desktop = os.path.join(os.path.expanduser("~"), "Desktop")

def show_packet(packet):
    global last_site
    if not running: return
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            site = packet[DNSQR].qname.decode().strip('.')
            if len(site) < 4: return
            if "windows" in site or "microsoft.com" in site: return
            if site == last_site: return
            last_site = site
            counter[site] += 1

            is_tracker = any(t in site for t in TRACKERS)
            tag = " [TRACKER!!]" if is_tracker else ""
            time = datetime.now().strftime("%H:%M:%S")

            listbox.insert(0, f"[{time}] {site}{tag}")
            if is_tracker:
                listbox.itemconfig(0, {'fg':'red'})

            track_count = sum(1 for s in counter if any(t in s for t in TRACKERS))
            label_count.config(text=f"المواقع: {len(counter)} | تتبع: {track_count}")
        except: pass

def start_sniff():
    global running
    if running: return
    running = True
    btn_start.config(state="disabled", text="شغال...")
    btn_stop.config(state="normal")
    listbox.insert(0, "--- بدأ الصيد 🐋 ---")
    threading.Thread(target=lambda: sniff(prn=show_packet, filter="port 53", store=0), daemon=True).start()

def stop_sniff():
    global running
    running = False
    btn_start.config(state="normal", text="Start")
    btn_stop.config(state="disabled")
    listbox.insert(0, "--- وقف ---")

def save_report():
    path = os.path.join(desktop, f"report_{datetime.now().strftime('%H-%M-%S')}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Count", "Is_Tracker"])
        for site, count in counter.most_common():
            is_t = "YES" if any(t in site for t in TRACKERS) else "NO"
            writer.writerow([site, count, is_t])
    listbox.insert(0, f"تم الحفظ: {path}")
    label_status.config(text=f"اتحفظ: {os.path.basename(path)}")

root = tk.Tk()
root.title("Whale Analyzer - Final + Tracker")
root.geometry("600x450")
label_count = tk.Label(root, text="المواقع: 0 | تتبع: 0", font=("Arial", 12, "bold"))
label_count.pack(pady=5)
frame = tk.Frame(root)
frame.pack(pady=5)
btn_start = tk.Button(frame, text="Start", bg="#22c55e", fg="white", width=10, command=start_sniff)
btn_start.pack(side="left", padx=5)
btn_stop = tk.Button(frame, text="Stop", bg="#ef4444", fg="white", width=10, state="disabled", command=stop_sniff)
btn_stop.pack(side="left", padx=5)
btn_save = tk.Button(frame, text="Save Report", bg="#3b82f6", fg="white", width=12, command=save_report)
btn_save.pack(side="left", padx=5)
listbox = tk.Listbox(root, width=80, height=20)
listbox.pack(pady=10)
label_status = tk.Label(root, text="جاهز - دوس Start", fg="gray")
label_status.pack()
root.mainloop()