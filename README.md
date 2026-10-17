# Analizador de logs SSH

Script en Python que revisa un log de autenticacion SSH y detecta posibles ataques de fuerza bruta.

## Que hace
- Cuenta los intentos fallidos de inicio de sesion por direccion IP.
- Marca como sospechosas las IPs que superan un umbral configurable.
- Avisa si una IP fallo varias veces y despues logro entrar (posible cuenta comprometida).
- Guarda un reporte en `reporte.txt`.

## Como usarlo
```
python generar_log_ejemplo.py
python analizador_logs.py auth_ejemplo.log --umbral 5
```

## Tecnologias
Python 3 (re, argparse, collections). No necesita librerias externas.

## Nota
El log de ejemplo es simulado y usa IPs de documentacion, no datos reales.
