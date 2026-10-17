"""Analizador de logs SSH para detectar posibles ataques de fuerza bruta.

Lee un archivo de log, cuenta los intentos fallidos por direccion IP y
marca como sospechosas las que superan un umbral. Tambien avisa si una IP
fallo varias veces y despues logro entrar (posible cuenta comprometida).

Uso:
    python analizador_logs.py auth_ejemplo.log --umbral 5
"""
import argparse
import re
from collections import defaultdict

PATRON_FALLO = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
PATRON_EXITO = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analizar(ruta):
    fallos = defaultdict(int)          # IP -> numero de fallos
    usuarios = defaultdict(set)        # IP -> usuarios probados
    exitos = defaultdict(int)          # IP -> accesos correctos
    entro_tras_fallar = set()          # IPs que fallaron y luego entraron

    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            m = PATRON_FALLO.search(linea)
            if m:
                usuario, ip = m.groups()
                fallos[ip] += 1
                usuarios[ip].add(usuario)
                continue
            m = PATRON_EXITO.search(linea)
            if m:
                _, ip = m.groups()
                exitos[ip] += 1
                if fallos[ip] >= 3:
                    entro_tras_fallar.add(ip)
    return fallos, usuarios, exitos, entro_tras_fallar


def generar_reporte(fallos, usuarios, entro_tras_fallar, umbral):
    lineas = ["REPORTE DE ACCESOS SOSPECHOSOS", "=" * 40]
    sospechosas = {ip: n for ip, n in fallos.items() if n >= umbral}

    if not sospechosas:
        lineas.append("No se encontraron IPs por encima del umbral.")
    for ip, n in sorted(sospechosas.items(), key=lambda x: -x[1]):
        lineas.append(f"[ALERTA] {ip}: {n} intentos fallidos, "
                      f"{len(usuarios[ip])} usuarios probados ({', '.join(sorted(usuarios[ip]))})")

    for ip in sorted(entro_tras_fallar):
        lineas.append(f"[CRITICO] {ip} fallo varias veces y luego inicio sesion: revisar la cuenta")

    lineas.append("-" * 40)
    lineas.append(f"IPs analizadas: {len(fallos)} | IPs sospechosas: {len(sospechosas)}")
    return "\n".join(lineas)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detecta posible fuerza bruta en logs SSH")
    parser.add_argument("archivo", help="ruta del archivo de log")
    parser.add_argument("--umbral", type=int, default=5, help="fallos minimos para alertar (default 5)")
    args = parser.parse_args()

    fallos, usuarios, exitos, comprometidas = analizar(args.archivo)
    reporte = generar_reporte(fallos, usuarios, comprometidas, args.umbral)
    print(reporte)
    with open("reporte.txt", "w", encoding="utf-8") as out:
        out.write(reporte)
    print("\nReporte guardado en reporte.txt")
