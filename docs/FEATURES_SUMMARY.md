# VANT-SIEM Agent - Nuevas Caracteristicas Implementadas

Este documento resume las nuevas funcionalidades implementadas en el VANT-SIEM Agent para mejorar su capacidades de detección, respuesta y cumplimiento.

## 1. Motor de Reglas Sigma

### Descripcion
Implementación completa de un motor de reglas compatible con el formato Sigma para detección de amenazas en tiempo real.

### Caracteristicas
- Carga dinámica de reglas desde directorio de archivos YAML
- Hot-reloading automático de reglas cada 5 minutos (configurable)
- Soporte completo para modificadores Sigma: contains, startswith, endswith, regex
- Mapeo inteligente de campos entre eventos y reglas Sigma
- Integración completa en el pipeline de procesamiento de eventos
- Generación automática de alertas cuando se coinciden reglas

### Archivos Implementados
- `vant/modules/rules/base.py` - Clase base y implementación de SigmaRule
- `vant/modules/rules/manager.py` - Gestor de reglas (carga, almacenamiento, matching)
- `vant/modules/rules/examples/` - Reglas de ejemplo para amenazas comunes

### Reglas de ejemplo incluidas
1. **PowerShell Sospechoso** - Detecta comandos PowerShell codificados (EventID 4104 con [Convert]::ToString*)
2. **Acceso a Credenciales LSASS** - Detecta acceso no autorizado al proceso LSASS (indicativo de mimikatz)
3. **Trabajos Cron Sospechosos** - Detecta creación de trabajos cron potencialmente maliciosos

### Configuración
En `config.yaml`:
```yaml
rules:
  directory: "vant/modules/rules/examples"  # Directorio de reglas
  reload_interval: 300                      # Intervalo de recarga en segundos (5 min)
```

## 2. Integración de Cyber Threat Intelligence (CTI)

### Descripcion
Servicio de inteligencia de amenazas que enriquece eventos de seguridad con datos de feeds de amenazas en tiempo real.

### Caracteristicas
- Descarga automática periódica de feeds de amenazas reputacionales
- Soporte para múltiples feeds:
  - AlienVault OTX (IPs maliciosas)
  - Abuse.ch SSLBL (IPs asociadas a certificados SSL maliciosos)
  - Abuse.ch Feodo Tracker (IPs de botnets bancarias)
- Enriquecimiento de eventos en tiempo real durante el procesamiento
- Etiquetado de eventos con IPs maliciosas detectadas
- Almacenamiento local de feeds para funcionamiento offline
- Actualización configurable de feeds por servicio

### Archivos Implementados
- `vant/modules/cti/service.py` - Servicio principal de CTI
- `vant/modules/cti/__init__.py` - Paquete CTI

### Integración
El servicio CTI se inicializa automáticamente en el agente y enriquece los eventos antes de ser procesados por el motor de reglas Sigma.

### Configuración
En `config.yaml`:
```yaml
cti:
  enabled: true
  update_interval: 3600                    # Intervalo general (1 hora)
  data_dir: "./cti_data"                   # Directorio para almacenar feeds
  alienvault_otx:
    enabled: true
    update_interval: 3600                  # Feed OTX cada hora
  abuse_ch:
    sslbl:
      enabled: true
      update_interval: 7200                # Feed SSLBL cada 2 horas
    feodotracker:
      enabled: true
      update_interval: 3600                # Feed Feodo cada hora
```

## 3. Capacidades de Reporte de Compliance

### Descripcion
Marco de reporting automatizado para estándares de seguridad comúnmente requeridos en entornos empresariales y regulatorios.

### Caracteristicas
- **Marco Extensible**: Arquitectura diseñada para soportar múltiples frameworks de compliance
- **Frameworks Actualemente Soportados**:
  - PCI DSS v4.0 (Payment Card Industry Data Security Standard)
  - HIPAA (Health Insurance Portability and Accountability Act) - 1996
  - GDPR (General Data Protection Regulation) - 2016
- **Mapeo de Controles Comunes**: Identificación de controles equivalentes entre frameworks
- **Recolección Automática de Evidencia**: Colección programada de evidencia para auditorías
- **Generación de Reportes**: Plantillas para múltiples formatos (JSON, texto, HTML)
- **Widgets para Dashboard**: Generación de datos para visualización de postura de cumplimiento

### Archivos Implementados
- `vant/modules/compliance/service.py` - Servicio principal de compliance
- Integración en `vant/main.py` para inicialización y ejecución periódica

### Funcionamiento
1. El servicio de compliance se ejecuta periódicamente (por defecto cada 24 horas)
2. Recopila evidencia para cada control de los frameworks habilitados
3. Genera reportes en los formatos especificados
4. Sube la evidencia como eventos de log especializados (`source_type: compliance_evidence`) para almacenamiento central
5. Los datos pueden ser utilizados para generar dashboards de postura de cumplimiento

### Configuración
En `config.yaml`:
```yaml
compliance:
  enabled: true
  interval: 86400                         # Intervalo de ejecución (24 horas en segundos)
```

### Próximos Pasos para Producción
- Reemplazar los colectores de evidencia placeholder con verificaciones reales del sistema
  - Escaneo de permisos de archivos y registros
  - Verificación de configuraciones de seguridad
  - Análisis de logs para detección de eventos de seguridad
- Considerar endpoints separados para evidencia de compliance si el tamaño de carga se convierte en un problema
- Implementar políticas de retención de reportes almacenados localmente
- Añadir programadores diferentes para diferentes frameworks (ej. HIPAA mensual, GDPR trimestral)

## 4. Mejoras en la Arquitectura y Documentación

### Actualizaciones en README.md
- Actualización de la sección de descripción para incluir nuevas características
- Actualización del diagrama de arquitectura para mostrar nuevos módulos (rules, cti, compliance)
- Actualización de la sección de configuración para documentar las nuevas opciones
- Actualización de la sección de desarrollo con referencias a los nuevos componentes

### Flujo de Datos Actualizado
```
Endpoint                    VANT-SIEM Agent                    VANT-SIEM Server
    │                            │                                │
    ├── Recolección de eventos ───────────────────────────────┤
    │                            │                                │
    ├── Enriquecimiento con CTI ───────────────────────────────┤
    │                            │                                │
    ├── Procesamiento mediante reglas Sigma ───────────────────┤
    │                            │                                │
    ├── POST /inventory/api/register/ ─────────────────────────┤
    ├── POST /inventory/api/heartbeat/ ────────────────────────┤
    ├── POST /inventory/api/inventory/submit/ ─────────────────┤
    ├── POST /inventory/api/command-result/ ───────────────────┤
    ├── POST /logs/api/ingest/bulk/ ───────────────────────────┤
    └── POST /logs/api/sources/ ───────────────────────────────┤
```

## Beneficios de las Nuevas Caracteristicas

### Seguridad Mejorada
- Detección en tiempo real de amenazas conocidas mediante reglas Sigma
- Enriquecimiento contextual de eventos con inteligencia de amenazas
- Capacidad de generar alertas automatizadas para actividades sospechosas

### Cumplimiento Regulatorio
- Marco preparado para múltiples frameworks de compliance
- Recolección automática de evidencia para reducir carga de preparación de auditorías
- Visibilidad continua de la postura de cumplimiento

### Eficiencia Operativa
- Reducción de falsos positivos mediante enriquecimiento contextual
- Respuesta más rápida a incidentes mediante alertas tempranas
- Menor carga administrativa para preparación de informes de cumplimiento

## Requisitos del Sistema
- Python 3.8+
- Dependencias listadas en requirements.txt
- Conexión a servidor VANT-SIEM para almacenamiento de eventos y evidencias
- Acceso a internet para descarga de feeds de CTI (opcional, funciona en modo offline con feeds previamente descargados)

## Instalación y Configuración
Ver el archivo README.md para instrucciones detalladas de instalación y configuración básica.
Ver config.example.yaml para referencia completa de todas las opciones de configuración disponibles.

---
*Documentación generada como parte del ciclo de desarrollo de VANT-SIEM Agent*
*Fecha: $(date)*