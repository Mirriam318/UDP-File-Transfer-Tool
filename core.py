import os
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk

# Constants
RECEIVER_IP = "0.0.0.0"
CHUNK_SIZE = 6000
DEFAULT_RECEIVED_DIR = os.path.join(os.path.expanduser("~"), "Documents", "UDP_Received")
os.makedirs(DEFAULT_RECEIVED_DIR, exist_ok=True)

# Main GUI Application class
class UDPFileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 UDP File Transfer Tool")
        self.root.geometry("850x600")
        self.root.configure(bg="#f0f0f0")

        # Configure UI style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", font=("Segoe UI", 11))
        style.configure("TButton", font=("Segoe UI", 10, "bold"))
        style.configure("TLabelframe", font=("Segoe UI", 12, "bold"))
        style.configure("TLabelframe.Label", font=("Segoe UI", 12, "bold"))

        self.create_sender_frame()
        self.create_receiver_frame()
        self.create_log_area()

    def create_sender_frame(self):
        sender_frame = ttk.LabelFrame(self.root, text="📤 Sender", padding=15)
        sender_frame.pack(padx=20, pady=10, fill="x")

        ttk.Label(sender_frame, text="File:").grid(row=0, column=0, sticky="e", pady=5)
        self.file_path_var = tk.StringVar()
        ttk.Entry(sender_frame, textvariable=self.file_path_var, width=60).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(sender_frame, text="📁 Browse", command=self.browse_file).grid(row=0, column=2, padx=5)

        ttk.Label(sender_frame, text="Receiver IP:").grid(row=1, column=0, sticky="e")
        self.receiver_ip_var = tk.StringVar()
        ttk.Entry(sender_frame, textvariable=self.receiver_ip_var, width=30).grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(sender_frame, text="Port:").grid(row=1, column=2, sticky="e")
        self.receiver_port_var = tk.StringVar()
        ttk.Entry(sender_frame, textvariable=self.receiver_port_var, width=10).grid(row=1, column=3, padx=5)

        ttk.Button(sender_frame, text="📤 Send File", command=self.send_file).grid(row=2, column=1, pady=10)

    def create_receiver_frame(self):
        receiver_frame = ttk.LabelFrame(self.root, text="📥 Receiver", padding=15)
        receiver_frame.pack(padx=20, pady=10, fill="x")

        ttk.Label(receiver_frame, text="Listen Port:").grid(row=0, column=0, padx=5)
        self.listen_port_var = tk.StringVar()
        ttk.Entry(receiver_frame, textvariable=self.listen_port_var, width=10).grid(row=0, column=1)

        ttk.Button(receiver_frame, text="🟢 Start Listening", command=self.start_receiving_default).grid(row=0, column=2, padx=10)
        ttk.Button(receiver_frame, text="📥 Receive File Now", command=self.start_receiving_manual).grid(row=0, column=3, padx=10)

    def create_log_area(self):
        log_frame = ttk.LabelFrame(self.root, text="📝 NOTIFICATION UPDATES", padding=10)
        log_frame.pack(padx=20, pady=10, fill="both", expand=True)

        self.log = scrolledtext.ScrolledText(log_frame, height=15, font=("Consolas", 11), bg="#ffffff", fg="#000000")
        self.log.pack(fill="both", expand=True)

    def log_message(self, msg):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime())
        self.log.insert(tk.END, f"{timestamp} {msg}\n")
        self.log.see(tk.END)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file to send")
        if file_path:
            self.file_path_var.set(file_path)

    def send_file(self):
        try:
            file_path = self.file_path_var.get()
            receiver_ip = self.receiver_ip_var.get()
            port_str = self.receiver_port_var.get()

            if not os.path.exists(file_path):
                raise FileNotFoundError("Selected file does not exist.")
            if not port_str.isdigit():
                raise ValueError("Please enter a valid port number.")
            receiver_port = int(port_str)

            ip_resolved = socket.gethostbyname(receiver_ip)
            self.log_message(f"[INFO] Resolved IP Address: {ip_resolved}")

            file_name = os.path.basename(file_path)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.sendto(f"FILENAME:{file_name}".encode(), (ip_resolved, receiver_port))
            time.sleep(1)

            with open(file_path, "rb") as f:
                packet_id = 0
                while chunk := f.read(CHUNK_SIZE):
                    header = f"ID:{packet_id}:".encode()
                    sock.sendto(header + chunk, (ip_resolved, receiver_port))
                    packet_id += 1
                    time.sleep(0.5)

            sock.sendto(b"__END__", (ip_resolved, receiver_port))
            self.log_message(f"[SUCCESS] File '{file_name}' sent successfully with {packet_id} packets.")

        except Exception as e:
            self.log_message(f"[ERROR] Send failed: {str(e)}")

    def receive_file(self, port, dest_folder):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((RECEIVER_IP, port))
            sock.settimeout(20)
            self.log_message(f"[INFO] Listening on port {port}...")

            file_name = None
            received_packets = {}

            while True:
                try:
                    data, addr = sock.recvfrom(CHUNK_SIZE + 100)
                except socket.timeout:
                    raise TimeoutError("Receiving timed out. No data received.")

                if data == b"__END__":
                    break
                elif data.startswith(b"FILENAME:"):
                    file_name = data.decode().split("FILENAME:")[1]
                    self.log_message(f"[INFO] Receiving file: {file_name} from {addr}")
                elif data.startswith(b"ID:"):
                    try:
                        header_end = data.index(b":", 3)
                        packet_id = int(data[3:header_end].decode())
                        chunk_data = data[header_end+1:]
                        received_packets[packet_id] = chunk_data
                    except Exception as parse_err:
                        self.log_message(f"[WARNING] Skipped malformed packet: {parse_err}")
                else:
                    self.log_message("[WARNING] Unknown data format received.")

            if not file_name:
                raise Exception("File name not received.")

            os.makedirs(dest_folder, exist_ok=True)
            full_path = os.path.join(dest_folder, f"received_{file_name}")
            with open(full_path, "wb") as f:
                for packet_id in sorted(received_packets):
                    f.write(received_packets[packet_id])

            self.log_message(f"[SUCCESS] File saved to '{full_path}'.")

        except Exception as e:
            self.log_message(f"[ERROR] File receive failed: {str(e)}")

    def start_receiving_default(self):
        try:
            port_str = self.listen_port_var.get()
            if not port_str.isdigit():
                raise ValueError("Please enter a valid port number.")
            port = int(port_str)
            threading.Thread(target=self.receive_file, args=(port, DEFAULT_RECEIVED_DIR), daemon=True).start()
        except Exception as e:
            self.log_message(f"[ERROR] {str(e)}")

    def start_receiving_manual(self):
        try:
            port_str = self.listen_port_var.get()
            if not port_str.isdigit():
                raise ValueError("Please enter a valid port number.")
            port = int(port_str)
            dest_folder = filedialog.askdirectory(title="Select folder to save received file")
            if dest_folder:
                threading.Thread(target=self.receive_file, args=(port, dest_folder), daemon=True).start()
            else:
                self.log_message("[INFO] No folder selected. Operation cancelled.")
        except Exception as e:
            self.log_message(f"[ERROR] {str(e)}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = UDPFileTransferApp(root)
    root.mainloop()
#end of code