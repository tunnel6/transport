# Estructura del Código de Transport

> Este documento es la traducción al español de [TRANSPORT_CODE_STRUCTURE.zh.md](./TRANSPORT_CODE_STRUCTURE.zh.md). Actualmente, la versión en inglés (TRANSPORT_CODE_STRUCTURE.md) es el idioma predeterminado.

Este documento describe la estructura actual del código de `tunnel/transport`, las cadenas de llamada clave y las restricciones de mantenimiento, para facilitar futuras refactorizaciones y la limpieza de código muerto.

## 1. Capas de Alto Nivel

- `src/lib.rs`
  - Capa de exportación NAPI (`#[napi]`).
  - Responsable de la conversión de datos, el puente de callbacks y la gestión del ciclo de vida entre JS/Node y el núcleo Rust.
- `src/client/`
  - Lógica del cliente Edge para el plano de control y el plano de datos (mTLS, envío/recepción de mensajes, control de túneles, suscripciones, reenvío HTTP/TCP/UDP).
- `src/ice/`
  - Negociación y reenvío P2P/ICE/QUIC (sondeo, hole punching, conexiones QUIC, forwarder P2P).
- `src/protocol/`
  - Codificación/decodificación de protocolos y definiciones de tipos de mensaje (`generated.rs` + `message.rs`).
- `src/error.rs`
  - Tipo de error unificado (`TransportError`) y sus conversiones.
- `src/debug.rs`
  - Utilidades de depuración.

## 1.1 Árbol de Código (actual)

```text
modules/tunnel/transport/
└── src/
    ├── lib.rs                         # Entrada de exportación NAPI, capa puente Node <-> Rust
    ├── debug.rs                       # Utilidades de depuración
    ├── error.rs                       # Definición y conversión de errores unificados
    ├── client/                        # Lógica principal del cliente Edge (plano de control + plano de datos)
    │   ├── mod.rs                     # Entrada agregada del módulo client
    │   ├── cert.rs                    # Generación de CSR/claves y estructuras de solicitud de certificado
    │   ├── cert_verifier.rs           # Verificación de certificados
    │   ├── connection.rs              # Establecimiento de conexiones TLS/mTLS
    │   ├── connection.rs.bak          # Respaldo histórico (fuera de la cadena de llamada formal)
    │   ├── edge_client.rs             # Cuerpo principal de EdgeClient y estado compartido
    │   ├── framing.rs                 # Lectura/escritura de tramas del protocolo
    │   ├── utils.rs                   # Funciones utilitarias (parseo HTTP, normalización de link type, etc.)
    │   └── edge_client/               # Submódulos de EdgeClient divididos por responsabilidad
    │       ├── data_packet.rs         # Procesamiento y entrega de tramas DATA
    │       ├── edge_ops.rs            # Operaciones del plano de control de Edge (online/offline/status)
    │       ├── http.rs                # Push HTTP + reenvío HTTP
    │       ├── ice.rs                 # Procesamiento de tramas del protocolo ICE
    │       ├── read_loop.rs           # Bucle de lectura y despacho por msg_type
    │       ├── subscriptions.rs       # Suscripciones de eventos y registro de callbacks
    │       ├── tcp_bridge.rs          # Puente TCP local y ciclo de vida de conexiones
    │       ├── tunnel_ops.rs          # Operaciones del plano de control de túneles (sync/start/stop, etc.)
    │       └── udp_assoc.rs           # Gestión y envío/recepción de asociaciones UDP
    ├── ice/                           # Negociación y reenvío P2P/ICE/QUIC
    │   ├── mod.rs                     # Entrada de exportación del módulo ice
    │   ├── agent.rs                   # Flujo principal de la máquina de estados IceAgent
    │   ├── dataplane.rs               # Envoltura de sesiones del plano de datos QUIC
    │   ├── forwarder.rs               # Forwarder P2P (publisher/consumer)
    │   └── probe.rs                   # Construcción y validación de paquetes de sondeo
    └── protocol/                      # Codificación/decodificación de protocolos y definiciones de mensajes
        ├── mod.rs                     # Entrada de exportación del módulo protocol
        ├── generated.rs               # Código generado por FlatBuffers
        └── message.rs                 # Envolturas de construcción/análisis de mensajes de negocio
```

- `connection.rs.bak` es un archivo de respaldo histórico y no forma parte de la cadena de llamada formal de los módulos actuales.

## 2. Estructura del Directorio client

### 2.1 Puntos de Entrada

- `src/client/mod.rs`
  - Exportación y agregación de los submódulos de client.
- `src/client/edge_client.rs`
  - Cuerpo principal de `EdgeClient`: gestión de conexiones, correlación petición-respuesta, almacenamiento de estado compartido, métodos utilitarios básicos.

### 2.2 Submódulos edge_client (divididos por responsabilidad)

- `src/client/edge_client/read_loop.rs`
  - Entrada del bucle de lectura; despacha a cada lógica de procesamiento según `msg_type`.
  - Conserva la determinación del tipo de mensaje y el manejo de excepciones/alternativas.
- `src/client/edge_client/http.rs`
  - Procesamiento de peticiones HTTP Push + reenvío directo HTTP.
  - Gestiona de forma unificada el parseo, reenvío y escritura de respuestas HTTP.
- `src/client/edge_client/data_packet.rs`
  - Procesamiento de paquetes DATA (desempaquetado y entrega de tramas de datos de conexión).
- `src/client/edge_client/tcp_bridge.rs`
  - Puente entre TCP local y tramas del protocolo, y ciclo de vida de conexiones.
- `src/client/edge_client/udp_assoc.rs`
  - Gestión de asociaciones UDP, envío/recepción y recuperación por timeout.
- `src/client/edge_client/ice.rs`
  - Procesamiento de tramas del protocolo ICE (`ICE_START` / `ICE_PUNCH` / `ICE_QUIC_START` / `ICE_STATE_CHANGE`).
- `src/client/edge_client/edge_ops.rs`
  - Operaciones del plano de control a nivel de Edge (online/offline/status).
- `src/client/edge_client/tunnel_ops.rs`
  - Operaciones del plano de control a nivel de túnel (status/sync/upsert/delete/start/stop).
- `src/client/edge_client/subscriptions.rs`
  - Suscripciones de eventos y registro de callbacks (tunnel/channel/ice/log).

### 2.3 Otros Componentes de client

- `src/client/connection.rs`
  - Establecimiento de conexiones TLS/mTLS y carga de certificados.
- `src/client/cert.rs`
  - Generación de CSR/claves y estructuras de datos de solicitud de certificado.
- `src/client/cert_verifier.rs`
  - Lógica de verificación de certificados.
- `src/client/framing.rs`
  - Utilidades de lectura/escritura de tramas.
- `src/client/utils.rs`
  - Funciones auxiliares (parseo HTTP, normalización e inferencia de link type, etc.).

## 3. Estructura del Directorio ICE

- `src/ice/agent.rs`
  - Flujo principal de la máquina de estados `IceAgent` (gather/probe/punch/quic/fallback/close).
- `src/ice/probe.rs`
  - Construcción, validación y análisis de resultados de mensajes de sondeo.
- `src/ice/dataplane.rs`
  - Envoltura de sesiones del plano de datos QUIC (metadatos de conexión y flujo de cierre).
- `src/ice/forwarder.rs`
  - Forwarder P2P (dos roles: publisher/consumer) y puente stream/tcp.

## 4. Cadena de Exportación a Node (debe protegerse al limpiar código muerto)

### 4.1 Cadena Principal

1. `src/lib.rs` expone interfaces `#[napi]` (por ejemplo, `edge_online`, `request_tunnel_sync`, `start_tunnel`, `subscribe_ice_events`).
2. Los métodos NAPI invocan los métodos homónimos o similares de `client::EdgeClient`.
3. `EdgeClient` ejecuta luego el procesamiento real del protocolo a través de `read_loop` + los trait/impl de cada submódulo.
4. Los callbacks de eventos regresan al lado de Node mediante `ThreadsafeFunction`.

### 4.2 Restricciones de Limpieza

- Mientras una función esté en la cadena de llamada `#[napi] -> EdgeClient -> submódulo`, no debe eliminarse como código muerto aunque tenga pocas referencias locales en Rust.
- Algunos `allow(dead_code)` en `protocol/generated.rs` y `protocol/message.rs` provienen de la superficie de compatibilidad del protocolo y no deben eliminarse a la ligera.

## 5. Limpieza Estructural Completada Hasta Ahora

- Se dividió la lógica de `edge_client` por responsabilidad en el directorio `src/client/edge_client/`.
- Se unificó la lógica de despacho de lectura en `read_loop.rs`, evitando mantenimiento disperso.
- Se unificó la lógica de procesamiento HTTP en `http.rs`.
- Se eliminó del módulo ICE un conjunto de interfaces del plano de datos nunca invocadas, conservando solo la capacidad mínima necesaria en ejecución.
- Se eliminó el campo no leído en `forwarder.rs` (`ChannelRoute.channel_id`).

## 6. Recomendaciones de Mantenimiento Futuro

- Las nuevas funciones deben colocarse primero en submódulos con responsabilidades claras; evitar que el código vuelva al archivo grande `edge_client.rs`.
- Confirmar primero si el código está en la cadena de exportación `#[napi]` antes de eliminarlo como código muerto.
- Tras cada refactorización, ejecutar al menos:
  - `cd modules/tunnel/transport && cargo test`
  - Actualizar la documentación de cadenas de llamada cuando sea necesario, manteniendo sincronizado "diagrama de estructura + código".

## 7. Diagrama de Interfaces P2P y Cambios en la Máquina de Estados (línea base pendiente de implementación)

> Nota: esta sección documenta la dirección de refactorización confirmada el 2026-05-14, destinada a corregir el problema "tras el éxito de ICE, el tráfico de negocio no se conmuta a P2P".
> Actualmente es una línea base de diseño y no implica que el código esté totalmente implementado.

### 7.1 Principios Clave

1. `ICE_QUIC_START.role` se usa únicamente para el rol de establecimiento de la conexión QUIC (server/client).
2. Los roles de reenvío de negocio (publisher/consumer) se deciden por canal, no se infieren de `ICE_QUIC_START.role`.
3. El cableado del plano de datos P2P se dispara en dos momentos (doble disparo, para resolver condiciones de carrera de temporización):
   - `IceEvent::QuicConnected`
   - Después de que `start_tunnel` regresa con éxito

### 7.2 Diagrama de Cambios en las Interfaces (Rust / NAPI)

```text
Before (estado actual, ruta problemática)
ICE_QUIC_START.role
    └── IceAgent::handle_ice_quic_start()
          └── ForwarderRole vinculado directamente (server=>publisher, client=>consumer)
                └── El rol del tráfico de negocio queda sobrescrito por el rol de la sesión
                      └── Resultado común: QUIC conectado, pero el canal no registrado/escuchado correctamente

After (objetivo, ruta desacoplada)
ICE_QUIC_START.role
    └── Decide únicamente la rama del handshake QUIC (accept/connect)

Metadatos del canal / runtime de start_tunnel
    └── Decide la dirección de negocio de cada canal (publisher/consumer)
          └── Cableado automático wire_p2p_forwarding()
                ├── publisher: register_channel(channel_id, local_addr)
                └── consumer : start_consumer_listener(bind=local_addr)
```

### 7.3 Diagrama de Cambios en la Máquina de Estados (lado Transport)

```text
Before
[ICE Connected]
    └── forwarder creado (nivel de sesión)
          └── A la espera de llamadas manuales desde JS:
                - p2p_register_channel(...)
                - p2p_start_consumer_listener(...)
                      └── Si no se llama o la temporización es incorrecta => el tráfico sigue por relay / sin tráfico

After
[ICE Connected]
    └── Dispara el cableado automático (según la lista de canales)
          ├── Si canal=publisher: registra la ruta
          └── Si canal=consumer : inicia el listener local (prioriza vincular el local_addr original)

[start_tunnel success]
    └── Vuelve a disparar el cableado automático (idempotente)
          └── Cubre ambas secuencias: "túnel primero, ICE después" o "ICE primero, túnel después"
```

### 7.4 Mapeo de Cambios por Módulo (planificado)

1. `src/lib.rs`
   - Añadir/extender el punto de coordinación del cableado automático (por ejemplo, `wire_p2p_forwarding`).
   - Disparar el cableado en la rama `QuicConnected` de `subscribe_ice_events`.
   - Disparar el cableado tras el éxito de `start_tunnel`.
2. `src/client/edge_client.rs`
   - Exponer la instantánea de vinculación de canales P2P (solo `link_type=p2p`).
   - Permitir actualizar el `local_addr` del canal después de establecer el listener del consumer.
3. `src/ice/forwarder.rs`
   - El listener del consumer soporta el modo "dirección de vinculación especificada" (prioriza el puerto esperado por el negocio).
   - Conservar la capacidad actual de puerto aleatorio como fallback.

### 7.5 Límites del Alcance Actual

1. Esta ronda prioriza la corrección de la conmutación de tráfico TCP/HTTP sobre canales P2P.
2. UDP y la política de certificados HTTPS quedan fuera del alcance de esta ronda (HTTPS se diseñará por separado).

## 8. Lista de Verificación de Pruebas Conjuntas P2P (versión ejecutable)

> Objetivo: verificar rápidamente que "tras el éxito de ICE, TCP/HTTP se conmutó automáticamente a P2P" y localizar el punto de falla en caso contrario.

### 8.1 Precondiciones

1. Ambos extremos han ejecutado `subscribe_ice_events`.
2. El `link_type` del canal del túnel es `p2p` (al menos un canal TCP/HTTP).
3. Mantener visibles los logs Rust de `transport` (`stderr` / log de ejecución).

### 8.2 Secuencia de Disparo Central

1. Disparar `start_tunnel` (o restaurar un túnel existente).
2. Esperar a que la negociación ICE alcance `quic_connected`.
3. Observar si aparecen dos logs de disparo de cableado automático:
   - `source=start_tunnel`
   - `source=ice_quic_connected`

### 8.3 Logs Imprescindibles (ruta de éxito)

1. Resumen del cableado automático:
   - `p2p auto-wire from <source>: channels=<n> forwarder[publisher=..., consumer=...]`
2. Registro de rutas del publisher:
   - `p2p auto-wire register channel=...`
3. Establecimiento del listener del consumer:
   - `p2p consumer listener ready channel=... addr=...`
4. Datos entrando al reenvío P2P:
   - `P2pForwarder] publisher stream route lookup channel=...`

### 8.4 Ramas de Falla Comunes y su Causa

1. `skip p2p auto-wire ... no p2p channels`
   - Causa: el canal no está marcado como `link_type=p2p` o `local_addr` está vacío.
2. `skip p2p auto-wire for udp channel=...`
   - Causa: la política actual omite UDP explícitamente (fuera del alcance de esta ronda).
3. `p2p consumer listener failed channel=... bind=...`
   - Causa: puerto local ocupado / sin permisos de vinculación; verificar la disponibilidad de `local_addr`.
4. `publisher stream error: no route for channel ...`
   - Causa: el registro del publisher falló, o hay inconsistencia entre channel_id/canonical_id.

### 8.5 Criterios de Aceptación (esta ronda)

1. Al menos un canal TCP/HTTP muestra logs `register` o `listener ready` tras `quic_connected`.
2. Al triggerarse el tráfico de negocio aparece `publisher stream route lookup` sin `no route for channel`.
3. En una misma sesión, cualquiera de los órdenes entre `start_tunnel` e `ice_quic_connected` termina en cableado exitoso.
