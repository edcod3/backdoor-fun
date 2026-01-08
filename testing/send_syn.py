from scapy.all import IP, TCP, sr1, send, RandShort, conf
import sys

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
# ===================

if SRC_IP:
    ip = IP(dst=DST_IP, src=SRC_IP)
else:
    ip = IP(dst=DST_IP)

tcp = TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=SEQ, ack=SEQ_ACK,
          options=[('MSS', 1460), ('SAckOK',''), ('Timestamp',(0,0))])

pkt = ip / tcp

pkt.urgptr = 0x4269

print(f"Sending SYN -> {DST_IP}:{DST_PORT} (sport {int(SRC_PORT)})")
resp = sr1(pkt, timeout=TIMEOUT)   # send and wait for single reply

if resp is None:
    print("No response (timeout).")
    sys.exit(0)

if resp.haslayer(TCP):
    rflags = resp[TCP].flags
    # check for SYN-ACK (S=0x02, A=0x10 so SYN+ACK = 0x12)
    if int(rflags) & 0x12 == 0x12:
        print("Received SYN-ACK from target.")
        # Optionally send the ACK to complete handshake from our side (for legitimate testing)
        ack = IP(dst=DST_IP)/TCP(sport=SRC_PORT, dport=DST_PORT,
                                 flags="A",
                                 seq=SEQ+1,
                                 ack=resp[TCP].seq + 1)
        send(ack)
        print("Sent ACK (handshake completed from our side).")
    elif int(rflags) & 0x04:   # RST
        print("Received RST (connection refused).")
    else:
        print(f"Received TCP with flags: {rflags}")
else:
    print("Received non-TCP response:", resp.summary())
