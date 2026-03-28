# Dolly Sensor

Colector sFlow minimalista en Go para perfilado de tráfico entrante y alertas DDoS.

## Características

- Escucha datagramas sFlow v5 en `127.0.0.1:6343`.
- Decodifica encabezados de paquetes desde registros raw.
- Mantiene **perfiles globales por cada IP de destino propia**.
- Rastrea estadísticas en tiempo real:
  - Mbps actuales, promedio y desviación.
  - PPS actuales, promedio y desviación.
  - Top de protocolos por IP de destino.
  - Top de IPs de origen y puertos por cada destino.
  - Conteo de flags TCP para detección de anomalías.
- Emite alertas de anomalías con lógica híbrida (Z-Score + Threat Scoring).
- Notificaciones ricas en **Discord** vía Webhooks.
- Dashboard web en tiempo real en `127.0.0.1:8080`.
- Almacenamiento eficiente mediante **Ring Buffer circular**.

## Ejecución

```bash
go run .
```

## Compilación

```bash
go build -o dolly-sensor main.go
```

## Configuración

Edita el archivo `config.json`:

- `sflow.sampling`: El factor de muestreo sFlow (ej. 400). **DEBE** coincidir con la configuración de tu agente (ej. `/etc/hsflowd.conf`) para que los cálculos de PPS/Mbps sean exactos.
- `sflow.collector.ip`: IP donde el colector escuchará.
- `sflow.collector.udpport`: Puerto UDP para sFlow (por defecto 6343).
- `http.listen`: Dirección para el dashboard web (ej. `127.0.0.1:8080`).
- `store.max_recent_packets`: Cantidad máxima de paquetes en memoria (se recomiendan 200,000 para 8GB de RAM).
- `local.owned_cidrs`: Lista de redes CIDR que se consideran tráfico "entrante".
- `alert.discord_webhook_url`: URL del Webhook de Discord para notificaciones.

## Ajustes de Detección

El sensor utiliza un sistema de **Puntuación de Amenaza (Threat Scoring)** combinado con estadísticas **Z-Score** para identificar ataques con alta especificidad. Puedes ajustarlo con dos parámetros simples:

### Tipo de Red (`network_type`)
Ajusta el volumen de tráfico base antes de que el sensor empiece a sospechar:
- **`home`**: Comienza a vigilar a partir de **5,000 PPS**. Ideal para routers domésticos y laptops.
- **`office`**: Comienza a partir de **25,000 PPS**. Para redes de pequeñas y medianas empresas.
- **`datacenter`**: Comienza a partir de **100,000 PPS**. Diseñado para entornos de servidores de alto rendimiento.

### Sensibilidad (`sensitivity`)
Ajusta cuánta evidencia y tiempo necesita el sensor para confirmar un ataque:
- **`relaxed`**: Alta tolerancia. Requiere **15 segundos** de anomalía sostenida. Ideal para evitar cualquier falso positivo.
- **`balanced`**: El valor por defecto. Requiere **8 segundos** de anomalía sostenida.
- **`aggressive`**: Reacción rápida. Alerta tras **5 segundos** de anomalía detectada.
- **`ultra`**: Respuesta instantánea. Alerta tras **3 segundos** de anomalía detectada.
- **`instant`**: Máxima agresividad. Alerta tras **1 segundo** de anomalía detectada.

## Mejoras Recientes

- **Handshake Tracking**: Lógica completa para rastrear los 3 pasos de TCP (SYN, SYN/ACK, ACK) y marcar conexiones completadas, permitiendo visibilidad de sesiones legítimas frente a escaneos.
- **Buffer Circular Optimizado**: Implementación de un Ring Buffer para el almacenamiento de paquetes, eliminando copias costosas en memoria y mejorando el rendimiento bajo alta carga.
- **Dashboard Avanzado**: Nuevas tablas de conexiones activas, filtros de búsqueda por IP de origen/destino y visualización detallada de flags IP/TCP y MTU.
- **Limpieza de CI**: Eliminación de dependencias innecesarias de GitHub Actions para un flujo de desarrollo más ligero.
