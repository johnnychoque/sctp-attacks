from scapy.all import *

def analyze_sctp_chunks(pkt):
    if SCTP not in pkt:
        print("[INFO] El paquete no contiene SCTP.")
        return

    sctp = pkt[SCTP]
    all_payloads = list(sctp.iterpayloads())

    # Excluir la capa base SCTP si aparece como chunk
    real_chunks = [c for c in all_payloads if type(c).__name__.startswith("SCTPChunk")]

    print("="*50)
    print(f"[ANÁLISIS] Paquete SCTP: {pkt.summary()}")
    print(f"Total en iterpayloads(): {len(all_payloads)}")
    print(f"Tipos encontrados: {[type(c).__name__ for c in all_payloads]}")
    print(f"Chunks válidos: {len(real_chunks)}")
    for i, chunk in enumerate(real_chunks):
        print(f"  Chunk {i}: {type(chunk).__name__}")
    print("="*50 + "\n")

    # Extra opcional: si es SACK de un solo chunk
    if len(real_chunks) == 1 and type(real_chunks[0]).__name__ == "SCTPChunkSACK":
        try:
            tsn = real_chunks[0].cumul_tsn_ack
            print(f"[INFO] Es un SACK con un solo chunk. Cumulative TSN ACK: {tsn}")
        except Exception as e:
            print(f"[ERROR] No se pudo leer cumul_tsn_ack: {e}")

print("Escuchando tráfico SCTP...")
sniff(
    filter="sctp",
    prn=analyze_sctp_chunks
)
