# Análisis y Mejoras Sugeridas - VANT-SIEM

## Arquitectura Actual

VANT-SIEM es un servidor Django monolitico con 5 aplicaciones internas
que pueden ejecutarse como microservicios independientes:

- VANT_SIEM: Portal web principal
- INVENTORY: Gestión de agentes y assets
- AEGIS: DLP/Seguridad
- OPENSEARCH_LOGS: Ingesta de logs
- EVENT_M: Gestión de incidentes y topologia de red

## Fortalezas

1. **Multi-base de datos**: 6 bases PostgreSQL separadas
2. **Comunicación agente-servidor**: REST/JSON con HMAC-SHA256
3. **Plugins de parseo**: Sistema extensible de parsers
4. **DLP en agente**: Escaneo local con reglas configurables

## Problemas Identificados

### 1. Duplicación de código agente
El código del agente esta DUPLICADO dentro del repositorio VANT-SIEM
(agent-deb/vant-siem-agent/) y en el repositorio VANT-Agent. Esto
genera inconsistencias.

### 2. Dependencia de Internet para builds
requirements.txt asume `pip install` con conexión a internet.
Clientes offline no pueden compilar.

### 3. Hardcoding de configuraciones
- Shared secret hardcodeado: "VANT-SIEM-AGENT-BOOTSTRAP-2026"
- URLs de servicios hardcodeadas en agent_tools.py
- Version de agente hardcodeada "v1.01"

### 4. Seis bases de datos, un solo punto de fallo
Cada servicio depende de su propia base PostgreSQL. Si alguna
cae, ese servicio muere. No hay failover clustering.

### 5. Monolito con microservicios simulados
Los management commands (run_*_service.py) spawn procesos
independientes pero comparten el mismo codebase. Si un servicio
tiene un bug, potencialmente afecta a todos.

### 6. Sin cola de reintentos para ingesta de logs
Si OpenSearch/Postgres de logs esta caido, los eventos se pierden.
No hay buffer local ni cola de reintentos.

### 7. Autenticación debil
- Modo "none" permite enrollment sin autenticar
- Shared secret global (no por agente)
- Token Bearer sin refresh/expiración

### 8. Sin rate limiting en endpoints críticos
Los endpoints de ingesta de logs (/logs/api/ingest/bulk/) no tienen
protección contra abuso.

## Mejoras Sugeridas

### Alta Prioridad
1. [ ] Extraer agente a repositorio independiente (VANT-Agent)
2. [ ] Implementar buffer local de eventos en agente (SQLite)
3. [ ] Agregar refresh tokens con expiración
4. [ ] Rate limiting por agente en endpoints de logs

### Media Prioridad
5. [ ] Health checks entre microservicios
6. [ ] Circuit breaker en comunicacion agente-servidor
7. [ ] Cache Redis para configuraciones frecuentes
8. [ ] Logging estructurado (JSON) en todos los servicios

### Baja Prioridad
9. [ ] Dashboard de monitoreo de agentes en tiempo real
10. [ ] Actualización remota de agentes (OTA)
11. [ ] Soporte para agentes detras de NAT/proxy
