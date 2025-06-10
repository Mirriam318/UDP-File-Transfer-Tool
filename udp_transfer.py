import socket
import os
import time

class UDPTransfer:
    def __init__(self, buffer_size=4096):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.buffer_size = buffer_size

    def send_file(self, file_path, ip, port, progress_callback=None):
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)

            # Send file name
            self.sock.sendto(f"FILENAME:{filename}".encode(), (ip, port))
            time.sleep(0.1)

            # Send file size
            self.sock.sendto(f"FILESIZE:{file_size}".encode(), (ip, port))
            time.sleep(0.1)

            with open(file_path, "rb") as f:
                sent = 0
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    self.sock.sendto(chunk, (ip, port))
                    sent += len(chunk)
                    if progress_callback:
                        progress_callback(sent, file_size)

            return True, "File sent successfully."
        except Exception as e:
            return False, f"Send error: {str(e)}"

    def receive_file(self, save_dir, listen_port, progress_callback=None):
        try:
            self.sock.bind(("", listen_port))

            # Receive file name
            data, addr = self.sock.recvfrom(1024)
            if not data.startswith(b"FILENAME:"):
                return False, "Did not receive filename."
            filename = data[len("FILENAME:"):].decode()

            # Receive file size
            data, addr = self.sock.recvfrom(1024)
            if not data.startswith(b"FILESIZE:"):
                return False, "Did not receive file size."
            file_size = int(data[len("FILESIZE:"):].decode())

            save_path = os.path.join(save_dir, filename)
            with open(save_path, "wb") as f:
                received = 0
                while received < file_size:
                    chunk, _ = self.sock.recvfrom(self.buffer_size)
                    f.write(chunk)
                    received += len(chunk)
                    if progress_callback:
                        progress_callback(received, file_size)

            return True, f"File received and saved as: {filename}"
        except Exception as e:
            return False, f"Receive error: {str(e)}"

    def close(self):
        self.sock.close()
