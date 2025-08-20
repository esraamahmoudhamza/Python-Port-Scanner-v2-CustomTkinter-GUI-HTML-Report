import customtkinter as ctk
import tkinter as tk
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import messagebox
import webbrowser

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "No banner"
    except:
        return "No banner"

def scan_port(target, port, protocol):
    try:
        if protocol == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                return (port, "OPEN")
            elif result == socket.errno.ECONNREFUSED:
                return (port, "CLOSED")
            else:
                return (port, "FILTERED")
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            try:
                s.sendto(b"", (target, port))
                data, _ = s.recvfrom(1024)
                s.close()
                return (port, "OPEN")
            except socket.timeout:
                s.close()
                return (port, "FILTERED")
            except Exception:
                s.close()
                return (port, "CLOSED")
    except Exception:
        return (port, "ERROR")

def scan_ports():
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    target = entry_ip.get().strip()
    protocol = protocol_var.get()
    try:
        start_port = int(entry_start.get())
        end_port = int(entry_end.get())
        if start_port > end_port:
            messagebox.showerror("Input Error", "Start Port must be less than or equal to End Port!")
            result_text.config(state=tk.DISABLED)
            return
    except ValueError:
        messagebox.showerror("Input Error", "Please enter valid port numbers!")
        result_text.config(state=tk.DISABLED)
        return

    progress_bar.set(0)
    total_ports = end_port - start_port + 1

    def run_scan():
        scanned_ports = 0
        results = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, target, port, protocol): port for port in range(start_port, end_port + 1)}
            for future in as_completed(futures):
                port, status = future.result()
                results.append((port, status))
                scanned_ports += 1
                progress_bar.set(scanned_ports / total_ports)

        results.sort(key=lambda x: x[0])  

        html_lines = []

        for port, status in results:
            banner = grab_banner(target, port) if status == "OPEN" and protocol == "TCP" else "N/A"
            text_line = f"Port {port} ({protocol}): {status} - {banner}\n"
            result_text.insert(tk.END, text_line, status)
            html_lines.append(f"<tr><td>{port}</td><td>{protocol}</td><td>{status}</td><td>{banner}</td></tr>")

        result_text.config(state=tk.DISABLED)

        # Generate HTML Report
        html_report = f"""
        <html>
        <head><title>Port Scan Report</title></head>
        <body style="background-color:#1e1e1e; color:#fff; font-family:monospace;">
        <h2>Scan Report for {target}</h2>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse; color:#fff;">
        <tr style="background-color:#333;"><th>Port</th><th>Protocol</th><th>Status</th><th>Banner</th></tr>
        {''.join(html_lines)}
        </table>
        <p>Scan completed successfully.</p>
        </body>
        </html>
        """
        with open("scan_report.html", "w", encoding="utf-8") as f:
            f.write(html_report)

        webbrowser.open("scan_report.html")

        messagebox.showinfo("Done", "Port scanning completed!")

    threading.Thread(target=run_scan).start()

root = ctk.CTk()
root.title("Colored Port Scanner")
root.geometry("550x600")
root.resizable(False, False)

label_ip = ctk.CTkLabel(root, text="Target IP or Domain:", font=("Helvetica", 14))
label_ip.pack(pady=(20, 5))

entry_ip = ctk.CTkEntry(root, width=400, font=("Helvetica", 14))
entry_ip.pack()

protocol_var = ctk.StringVar(value="TCP")
frame_protocol = ctk.CTkFrame(root)
frame_protocol.pack(pady=15)

label_protocol = ctk.CTkLabel(frame_protocol, text="Select Protocol to Scan:", font=("Helvetica", 14))
label_protocol.pack(side="left", padx=10)

radio_tcp = ctk.CTkRadioButton(frame_protocol, text="TCP", variable=protocol_var, value="TCP")
radio_tcp.pack(side="left", padx=10)

radio_udp = ctk.CTkRadioButton(frame_protocol, text="UDP", variable=protocol_var, value="UDP")
radio_udp.pack(side="left", padx=10)

note_label = ctk.CTkLabel(root, text="Note: Scanning TCP or UDP ports as selected.", font=("Helvetica", 10, "italic"), text_color="#AAAAAA")
note_label.pack()

label_start = ctk.CTkLabel(root, text="Start Port:", font=("Helvetica", 14))
label_start.pack(pady=(15, 5))

entry_start = ctk.CTkEntry(root, width=150, font=("Helvetica", 14))
entry_start.pack()

label_end = ctk.CTkLabel(root, text="End Port:", font=("Helvetica", 14))
label_end.pack(pady=(15, 5))

entry_end = ctk.CTkEntry(root, width=150, font=("Helvetica", 14))
entry_end.pack()

scan_button = ctk.CTkButton(root, text="Start Scan", font=("Helvetica", 16, "bold"), command=scan_ports)
scan_button.pack(pady=25, ipadx=10, ipady=5)

progress_bar = ctk.CTkProgressBar(root, width=480)
progress_bar.set(0)
progress_bar.pack(pady=10)

result_text = tk.Text(root, width=65, height=15, font=("Courier", 12), bg="#222222", fg="white", insertbackground="white")
result_text.pack(padx=20, pady=10)

result_text.tag_configure("OPEN", foreground="red")
result_text.tag_configure("CLOSED", foreground="green")
result_text.tag_configure("FILTERED", foreground="white")
result_text.tag_configure("ERROR", foreground="orange")

root.mainloop()
