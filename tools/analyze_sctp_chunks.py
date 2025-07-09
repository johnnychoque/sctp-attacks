"""
===============================================================================
Script Name: analyze_sctp_chunks.py
Description : This script demonstrates how to extract SCTP chunks directly from captured network packets
              using Scapy, without relying on higher-level Scapy or Python functions that may not 
              always work reliably for SCTP. The main goal is to show a robust method for iterating
              over and analyzing all SCTP chunks present in each packet, regardless of their type.
Author      : Grupo de Ingeniería Telemática. Universidad de Cantabria
===============================================================================

Notes:
- Ensure you have Scapy installed and run this script with appropriate permissions.
- As an example, the script prints details for SACK chunks, but the approach is generic
  and can be used to inspect any SCTP chunk type.
- This script is for educational purposes only. Use responsibly and ethically.
===============================================================================
"""

from scapy.all import *

def analyze_sctp_chunks(pkt):
    if SCTP not in pkt:
        print("[INFO] The packet does not contain SCTP.")
        return

    sctp = pkt[SCTP]
    all_payloads = list(sctp.iterpayloads())

    # Exclude SCTP base layer if it appears as a chunk
    real_chunks = [c for c in all_payloads if type(c).__name__.startswith("SCTPChunk")]

    print("="*50)
    print(f"[ANALYSIS] SCTP packet: {pkt.summary()}")
    print(f"Total in iterpayloads(): {len(all_payloads)}")
    print(f"Types found: {[type(c).__name__ for c in all_payloads]}")
    print(f"Valid chunks: {len(real_chunks)}")
    for i, chunk in enumerate(real_chunks):
        print(f"  Chunk {i}: {type(chunk).__name__}")
    print("="*50 + "\n")

    # Optional extra: if it is a single chunk SACK
    if len(real_chunks) == 1 and type(real_chunks[0]).__name__ == "SCTPChunkSACK":
        try:
            tsn = real_chunks[0].cumul_tsn_ack
            print(f"[INFO] It is a SACK with a single chunk. Cumulative TSN ACK: {tsn}")
        except Exception as e:
            print(f"[ERROR] Could not read cumul_tsn_ack: {e}")

print("Listening for SCTP traffic...")
sniff(
    filter="sctp",
    prn=analyze_sctp_chunks
)
