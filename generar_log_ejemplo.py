"""Genera un archivo de log de ejemplo (formato similar a auth.log de Linux)
para poder probar el analizador sin datos reales."""
import random
from datetime import datetime, timedelta

random.seed(7)  # para que el resultado sea siempre el mismo
inicio = datetime(2026, 10, 15, 8, 0, 0)
usuarios = ["root", "admin", "juan", "test", "ubuntu"]
atacantes = ["203.0.113.45", "198.51.100.23"]   # IPs de documentacion, no reales
normales = ["192.0.2.10", "192.0.2.11", "192.0.2.12"]

lineas = []
t = inicio

# Trafico normal: algunos accesos correctos y algun error aislado
for _ in range(25):
    t += timedelta(minutes=random.randint(1, 12))
    ip = random.choice(normales)
    if random.random() < 0.85:
        msg = f"Accepted password for juan from {ip} port {random.randint(40000, 60000)} ssh2"
    else:
        msg = f"Failed password for juan from {ip} port {random.randint(40000, 60000)} ssh2"
    lineas.append((t, msg))

# Ataque de fuerza bruta desde dos IPs
for ip, n in [(atacantes[0], 18), (atacantes[1], 7)]:
    t2 = inicio + timedelta(hours=random.randint(1, 5))
    for _ in range(n):
        t2 += timedelta(seconds=random.randint(2, 20))
        usr = random.choice(usuarios)
        lineas.append((t2, f"Failed password for {usr} from {ip} port {random.randint(40000, 60000)} ssh2"))

# Una IP que falla varias veces y luego entra (posible cuenta comprometida)
t3 = inicio + timedelta(hours=6)
for _ in range(6):
    t3 += timedelta(seconds=random.randint(3, 15))
    lineas.append((t3, "Failed password for admin from 198.51.100.77 port 51234 ssh2"))
t3 += timedelta(seconds=10)
lineas.append((t3, "Accepted password for admin from 198.51.100.77 port 51240 ssh2"))

lineas.sort(key=lambda x: x[0])
with open("auth_ejemplo.log", "w") as f:
    for ts, msg in lineas:
        f.write(f"{ts.strftime('%b %d %H:%M:%S')} servidor sshd[{random.randint(1000, 9999)}]: {msg}\n")
print("Archivo auth_ejemplo.log generado con", len(lineas), "lineas")
