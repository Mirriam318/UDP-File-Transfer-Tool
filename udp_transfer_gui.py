import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
from pathlib import Path
from udp_transfer import UDPTransfer

class UDPFileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP File Transfer Tool")
        self.transfer = UDPTransfer()
        self.setup_ui()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.send_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.send_frame, text="Send File")
        self.setup_send_tab()

        self.receive_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.receive_frame, text="Receive File")
        self.setup_receive_tab()

    def setup_send_tab(self):
        ttk.Label(self.send_frame, text="File to send:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.file_path = tk.StringVar()
        ttk.Entry(self.send_frame, textvariable=self.file_path, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(self.send_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)

        ttk.Label(self.send_frame, text="Receiver IP:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.receiver_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(self.send_frame, textvariable=self.receiver_ip).grid(row=1, column=1, padx=5)

        ttk.Label(self.send_frame, text="Port:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.receiver_port = tk.IntVar(value=5005)
        ttk.Entry(self.send_frame, textvariable=self.receiver_port).grid(row=2, column=1, padx=5)

        self.send_progress = ttk.Progressbar(self.send_frame, length=300)
        self.send_progress.grid(row=3, column=0, columnspan=3, pady=10)

        self.send_status = ttk.Label(self.send_frame, text="Ready to send")
        self.send_status.grid(row=4, column=0, columnspan=3)

        ttk.Button(self.send_frame, text="Send File", command=self.start_send_thread).grid(row=5, column=1, pady=10)

    def setup_receive_tab(self):
        ttk.Label(self.receive_frame, text="Save directory:").grid(row=0, column=0, padx=5, pady=5, sticky="w")

        default_docs = Path.home() / "Documents"
        self.save_path = tk.StringVar(value=str(default_docs))

        ttk.Entry(self.receive_frame, textvariable=self.save_path, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(self.receive_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2, padx=5)

        ttk.Label(self.receive_frame, text="Listen Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.listen_port = tk.IntVar(value=5005)
        ttk.Entry(self.receive_frame, textvariable=self.listen_port).grid(row=1, column=1, padx=5)

        self.receive_progress = ttk.Progressbar(self.receive_frame, length=300)
        self.receive_progress.grid(row=2, column=0, columnspan=3, pady=10)

        self.receive_status = ttk.Label(self.receive_frame, text="Ready to receive")
        self.receive_status.grid(row=3, column=0, columnspan=3)

        ttk.Button(self.receive_frame, text="Receive File", command=self.start_receive_thread).grid(row=4, column=1, pady=10)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.save_path.set(directory)

    def start_send_thread(self):
        if not self.file_path.get():
            messagebox.showerror("Missing file", "Please select a file to send.")
            return
        threading.Thread(target=self.send_file, daemon=True).start()

    def send_file(self):
        self.send_status.config(text="Sending...")
        self.send_progress["value"] = 0

        def update_progress(sent, total):
            percent = sent / total * 100
            self.send_progress["value"] = percent
            self.send_status.config(text=f"Sent {sent}/{total} bytes ({percent:.1f}%)")
            self.root.update_idletasks()

        success, msg = self.transfer.send_file(
            self.file_path.get(),
            self.receiver_ip.get(),
            self.receiver_port.get(),
            update_progress
        )
        self.send_progress["value"] = 0
        self.send_status.config(text=msg)
        (messagebox.showinfo if success else messagebox.showerror)("Send Result", msg)

    def start_receive_thread(self):
        if not self.save_path.get():
            messagebox.showerror("Missing directory", "Please choose where to save received files.")
            return
        threading.Thread(target=self.receive_file, daemon=True).start()

    def receive_file(self):
        self.receive_status.config(text="Receiving...")
        self.receive_progress["value"] = 0

        def update_progress(received, total):
            percent = received / total * 100
            self.receive_progress["value"] = percent
            self.receive_status.config(text=f"Received {received} bytes ({percent:.1f}%)")
            self.root.update_idletasks()

        success, msg = self.transfer.receive_file(
            self.save_path.get(),
            self.listen_port.get(),
            update_progress
        )
        self.receive_progress["value"] = 0
        self.receive_status.config(text=msg)
        (messagebox.showinfo if success else messagebox.showerror)("Receive Result", msg)

    def on_closing(self):
        self.transfer.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = UDPFileTransferApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
