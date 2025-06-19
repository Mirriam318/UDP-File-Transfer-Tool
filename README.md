 UDP File Transfer Documentation
1. Overview
This project implements a simple file transfer system using the User Datagram Protocol (UDP). Unlike TCP, UDP is connectionless and unreliable, meaning that packet delivery, order, and integrity are not guaranteed. Therefore, additional logic is added to handle potential errors, such as packet loss, corruption, and out-of-order delivery.
2. Components
The system has two main components:
•	Sender (Client): Reads and sends the file in chunks over UDP.
•	Receiver (Server): Listens for incoming packets and reconstructs the file.
3. Workflow
Sender Side:
 Step-by-Step Process:
1.	Open the File:
o	Opens the file in binary mode (rb) to read its contents.
2.	Split the File:
o	Reads the file in fixed-size chunks (e.g., 1024 bytes).
3.	Add Packet Header:
o	For each chunk, the sender adds a header that includes:
	Sequence number (to track order)
	EOF flag (to indicate the last packet)
	Chunk size
4.	Send the Packet:
o	Sends each packet over UDP to the receiver's IP and port.
5.	(Optional) Wait for ACK:
o	If reliability is added, the sender waits for an acknowledgment (ACK) for each packet.
o	If no ACK is received within a timeout, it retransmits the packet.
6.	Repeat:
o	Continues until all chunks are sent and acknowledged.
7.	Close Socket:
o	After sending all packets (and receiving final ACK), the sender closes the socket.
import socket
import os
import time

CHUNK_SIZE = 1024
ACK_TIMEOUT = 2  # seconds
MAX_RETRIES = 5

def send_file(filename, receiver_ip, receiver_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(ACK_TIMEOUT)

    file_size = os.path.getsize(filename)
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    with open(filename, "rb") as f:
        for seq in range(total_chunks):
            chunk = f.read(CHUNK_SIZE)
            eof_flag = 1 if seq == total_chunks - 1 else 0
            header = f"{seq}|{eof_flag}|".encode()
            packet = header + chunk

            retries = 0
            while retries < MAX_RETRIES:
                sock.sendto(packet, (receiver_ip, receiver_port))
                try:
                    ack_data, _ = sock.recvfrom(1024)
                    ack_seq = int(ack_data.decode())
                    if ack_seq == seq:
                        print(f"ACK received for packet {seq}")
                        break
                except socket.timeout:
                    print(f"Timeout for packet {seq}, retrying...")
                    retries += 1
            else:
                print(f"Failed to send packet {seq} after retries. Aborting.")
                sock.close()
                return

    print("File sent successfully.")
    sock.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python sender.py <receiver_ip> <receiver_port> <filename>")
    else:
        send_file(sys.argv[3], sys.argv[1], int(sys.argv[2]))

Receiver Side:
 Step-by-Step Process:
1.	Bind to UDP Port:
o	Opens a UDP socket and listens on a specific port for incoming packets.
2.	Wait for Packets:
o	Receives UDP packets as they arrive.
3.	Read Header:
o	Extracts:
	Sequence number
	EOF flag
	Chunk size
4.	Store the Data:
o	Keeps received data in a dictionary or buffer, using the sequence number as the key.
5.	Send ACK (Optional):
o	Sends an ACK back to the sender for each packet received.
6.	Check for Completion:
o	If the EOF flag is detected and all previous sequence numbers are received:
	Assembles the file in correct order.
	Writes the file to disk.
7.	Handle Errors:
o	Ignores duplicate packets (already received SEQ_NO).
o	Reorders out-of-order packets using SEQ_NO.
o	Waits or requests retransmission if a packet is missing (if ACK system is used).
8.	Close and Save:
o	Closes the socket and writes the final file to disk

import socket

def receive_file(listen_port, output_filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', listen_port))
    print(f"Listening on port {listen_port}...")

    received_data = {}
    expected_packets = None

    while True:
        packet, addr = sock.recvfrom(2048)
        try:
            header_end = packet.index(b'|', packet.index(b'|') + 1)
            header = packet[:header_end].decode()
            seq_str, eof_str = header.split('|')
            seq = int(seq_str)
            eof = int(eof_str)
            data = packet[header_end + 1:]

            if seq not in received_data:
                received_data[seq] = data
                print(f"Received packet {seq}")

            # Send ACK
            ack = f"{seq}".encode()
            sock.sendto(ack, addr)

            if eof == 1:
                print("Last packet received. Writing file...")
                break

        except Exception as e:
            print("Error processing packet:", e)

    # Write the file in correct order
    with open(output_filename, "wb") as f:
        for i in range(len(received_data)):
            f.write(received_data[i])

    print("File received and saved successfully.")
    sock.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python receiver.py <listen_port> <output_filename>")
    else:
        receive_file(int(sys.argv[1]), sys.argv[2])

4. Packet Structure
[SEQ_NO][EOF][CHUNK_SIZE][DATA]
- SEQ_NO: Sequence number (integer)
- EOF: 1 if it's the last packet, 0 otherwise
- CHUNK_SIZE: Number of bytes in the data
- DATA: Actual bytes from the file

5. Error Handling
UDP does not guarantee delivery or order, so we handle errors manually.
 Implemented Error Handling Techniques:
Error Type	Description	Handling Method
Packet Loss	Some packets may never arrive	Use timeouts + ACKs and retransmissions
Out-of-Order Packets	Packets may arrive in any order	Use sequence numbers to reorder
Duplicate Packets	Packets may be resent accidentally	Track received SEQ_NO to ignore duplicates
Corruption	Data could be corrupted in transit	Add checksum/CRC (optional) and discard bad packets
Missing Final Packet	Last packet might be lost	Receiver expects EOF flag, re-requests if not received
Optional Enhancements:
•	Checksum/CRC for data integrity.
•	Sliding Window Protocol for better performance and flow control.
•	Selective Repeat ARQ for efficient retransmission.

6. Configuration Parameters
•	CHUNK_SIZE: Size of each packet’s data payload (e.g., 1024 bytes).
•	TIMEOUT: Duration (in seconds) before resending a packet if no ACK is received.
•	MAX_RETRIES: Number of retries before aborting transmission.
•	PORT: UDP port number used for communication.
•	ACK_REQUIRED: Boolean flag to enable/disable ACK-based reliability.

7. Usage
Sender
python sender.py <receiver_ip> <receiver_port> <filename>
Receiver
python receiver.py <listen_port>
8. Limitations
•	UDP is not suitable for very large files or unreliable networks unless enhanced.
•	The current implementation may not scale well without threading or async I/O.
•	No encryption or authentication is provided.

9. Future Improvements
•	Use reliable UDP techniques (like RUDP).
•	Add GUI interface using Tkinter or PyQt.
•	Implement multi-threading to handle concurrent transfers.
•	Support resume interrupted transfers.

# UDP-File-Transfer-Tool
An application to send and recieve files 
