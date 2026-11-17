| Hora | Fecha | Alerta |
|---|---|---|
| 16:30:02 | 2026-11-17 | Multiple Failed Logon Attempts |

### Revise la alerta y me tope con la siguiente salida
| source_ip |	host | failed_attempts | targeted_accounts | targeted_users | source_workstations|
|---|---|---|---|---|---|
| 192.168.1.103 | DESKTOP-1BDISO6 | 52 | 1 | SOC_Lab | KALI| 

### Analisis y evidencia
| Hora inicial de los intentos de login | Hora final del ultimo intento de login | Tiempo concurrido | 
|---|---|---|
| 2026-11-17 16:26:56.722 | 2026-11-17 16:27:45.775 | 49.053 segundos |

Intervalo demasiado corto para que un humano inserte 52 contraseñas
Los intentos de inicio de sesion provienen de un ip externo 192.168.1.103 
host afectado:  DESKTOP-1BDISO6 
usuario afectado: SOC_Lab
Al revisar se puede verificar que los intentos de inicio de sesion provienen de un kali sistema comunmente usado para atacar

El atacante logro hacer un inicio de sesion 
Evidencia: 2026-11-17 16:27:45.780 SOC_Lab 192.168.1.103 DESKTOP-1BDISO6 SOC_Lab KALI
### Veredicto
Confirmo que es un fuerza bruta,  true positive
Es necesario escalar esta alerta ya que el atacante esta dentro del sistema


