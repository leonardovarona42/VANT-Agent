# CTI Integration Documentation

## 1. Overview of CTI Integration

VANT-SIEM now includes Cyber Threat Intelligence (CTI) integration capabilities that automatically enrich security events with threat intelligence data. This feature enables the agent to:

- Download and maintain local copies of threat intelligence feeds from trusted sources
- Enrich incoming security events with CTI data during processing
- Tag events that match known threat indicators for easier identification and response
- Provide context about malicious IPs, domains, URLs, and file hashes detected in monitored environments

The CTI service operates as a background module within the VANT-Agent, periodically updating threat intelligence data and making it available for real-time event enrichment.

## 2. Configuration Options for CTI Feeds

CTI configuration is managed through the `cti` section in the agent's `config.yaml` file. Below is the complete configuration reference:

```yaml
cti:
  # Global CTI service settings
  enabled: true                    # Enable/disable the CTI service (default: true)
  update_interval: 3600            # Global update interval in seconds (default: 3600/1 hour)
  data_dir: "./cti_data"           # Directory to store CTI data (default: ./cti_data)

  # AlienVault OTX Feed Configuration
  alienvault_otx:
    enabled: true                  # Enable/disable AlienVault OTX feed (default: true)
    # Note: URL and parser are hardcoded in the service for OTX IPv4 feed
    update_interval: 3600          # Feed-specific update interval (default: 3600/1 hour)

  # Abuse.ch Feed Configuration
  abuse_ch:
    sslbl:                         # SSL Blocklist feed
      enabled: true                # Enable/disable SSLBL feed (default: true)
      update_interval: 7200        # Update interval in seconds (default: 7200/2 hours)
    feodotracker:                  # Feodo Tracker IP Blocklist
      enabled: true                # Enable/disable Feodo Tracker feed (default: true)
      update_interval: 3600        # Update interval in seconds (default: 3600/1 hour)
```

### Configuration Notes:

1. **Data Directory**: The CTI service stores downloaded threat intelligence data in the specified directory. Ensure the agent has write permissions to this location.

2. **Feed Sources**: 
   - AlienVault OTX: Provides IPv4 threat indicators from the Open Threat Exchange
   - Abuse.ch SSLBL: Provides IP addresses associated with SSL malware
   - Abuse.ch Feodo Tracker: Provides IP addresses associated with Feodo malware infrastructure

3. **Update Intervals**: 
   - Global `update_interval` serves as a fallback for feeds without specific intervals
   - Individual feed `update_interval` values override the global setting
   - Balance frequency of updates with bandwidth consumption and feed provider rate limits

4. **Enabling/Disabling**: 
   - Set `cti.enabled: false` to completely disable CTI functionality
   - Individual feeds can be disabled by setting their `enabled` field to `false`

## 3. How CTI Enrichment Works in the Event Processing Pipeline

The CTI enrichment process occurs during the event collection and processing workflow:

### Event Processing Flow:

1. **Event Collection**: Collectors (Snort, Suricata, Windows Event Log, etc.) gather raw events from monitored sources

2. **Host Information Enrichment**: The agent adds host-specific information (hostname, IP) to each event

3. **CTI Enrichment**: Before rules processing, each event passes through the CTI enrichment function:
   - The event is checked for IP addresses in common fields (`src_ip`, `dst_ip`, `source_ip`, `destination_ip`, `ip`, `ip_address`)
   - Both top-level event fields and nested `raw_payload` fields are examined
   - If an IP address matches any entry in the CTI malicious IP database:
     - A `cti_malicious_ip` tag is added to the event's tags array
     - The malicious IP is recorded in a `cti_malicious_ips` array for reference
     - Processing stops after the first malicious IP is found (to prevent excessive tagging)

4. **Rules Processing**: Enriched events are evaluated against configured detection rules (Sigma rules, etc.)

5. **Alert Generation**: When rules match, alerts are generated that preserve the CTI enrichment data:
   - The `cti_malicious_ip` tag is included in the alert
   - The `cti_malicious_ips` array is preserved in the alert's `raw_payload`

6. **Event Submission**: Both original events and generated alerts are submitted to the VANT-SIEM server

### Enrichment Example:

**Original Event:**
```json
{
  "source_type": "windows_eventlog",
  "source_name": "Microsoft-Windows-Security-Auditing",
  "host_name": "web-server-01",
  "host_ip": "192.168.1.100",
  "src_ip": "45.33.32.156",
  "dst_ip": "192.168.1.100",
  "event_time": "2024-09-15T10:30:00Z",
  "event_id": 4625,
  "message": "Failed login attempt"
}
```

**After CTI Enrichment (if 45.33.32.156 is malicious):**
```json
{
  "source_type": "windows_eventlog",
  "source_name": "Microsoft-Windows-Security-Auditing",
  "host_name": "web-server-01",
  "host_ip": "192.168.1.100",
  "src_ip": "45.33.32.156",
  "dst_ip": "192.168.1.100",
  "event_time": "2024-09-15T10:30:00Z",
  "event_id": 4625,
  "message": "Failed login attempt",
  "tags": ["cti_malicious_ip"],
  "cti_malicious_ips": ["45.33.32.156"]
}
```

## 4. How to Interpret CTI Tags in Alerts

When reviewing alerts in the VANT-SIEM dashboard or investigating incidents, CTI tags provide valuable context about threat involvement:

### CTI Tags:

- **`cti_malicious_ip`**: Indicates that the event contains an IP address identified as malicious by configured CTI feeds

### Associated Data Fields:

- **`cti_malicious_ips`**: Array containing the specific malicious IP address(es) found in the event
  - This field preserves the actual IP addresses that triggered the CTI tag
  - Useful for threat hunting and IOC (Indicator of Compromise) extraction

### Interpretation Guidelines:

1. **Presence of `cti_malicious_ip` tag**:
   - Indicates the event involves communication with a known malicious IP address
   - Suggests potential compromise, command-and-control activity, or malware distribution

2. **Context from `cti_malicious_ips` array**:
   - Shows exactly which IP address(es) were identified as malicious
   - Enables correlation with specific threat intelligence reports

3. **Combined with Rule Information**:
   - When CTI enrichment coincides with rule matches, it provides stronger evidence of malicious activity
   - Example: A failed login attempt (rule match) from a malicious IP (CTI tag) indicates likely brute force attack

4. **Feed Attribution**:
   - While not explicitly tagged, administrators can cross-reference malicious IPs with feed sources:
     - AlienVault OTX: Generally indicates diverse threat types (malware, scanning, etc.)
     - Abuse.ch SSLBL: Specifically indicates SSL/TLS malware communication
     - Abuse.ch Feodo Tracker: Specifically indicates Feodo malware (trickbot, etc.) infrastructure

### Investigation Workflow:

1. Identify events/alerts with `cti_malicious_ip` tag
2. Extract the specific IP from `cti_malicious_ips` array
3. Research the IP in threat intelligence platforms or internal knowledge base
4. Determine appropriate response based on threat type and confidence level
5. Hunt for related activity using the IP as a pivot point

## 5. Maintenance Procedures for CTI Data

Proper maintenance ensures the CTI service remains effective and efficient:

### 5.1 Monitoring CTI Service Health

**Check Service Status:**
- Review agent logs for CTI service messages:
  - `"CTI Service initialized"` - Service started successfully
  - `"CTI Service started"` - Update thread began
  - `"Updating CTI feeds"` - Feed update in progress
  - `"Updated CTI feed: [feed_name]"`, individual feed updates
  - `"CTI Service stopped"` - Service terminated

**Verify Data Freshness:**
- Check timestamps in the CTI data directory:
  - Feed-specific update files: `[feed_name]_last_update.txt`
  - Data storage files: `malicious_ips.txt` (and others as implemented)
- Compare file modification times with configured update intervals

**Monitor Statistics:**
The CTI service provides statistics accessible through:
- Direct service inspection (if exposing metrics endpoint)
- Custom monitoring scripts calling `cti_service.get_stats()`
- Example stats output:
  ```json
  {
    "malicious_ips": 12543,
    "malicious_domains": 0,
    "malicious_urls": 0,
    "malicious_file_hashes_md5": 0,
    "malicious_file_hashes_sha1": 0,
    "malicious_file_hashes_sha256": 0
  }
  ```

### 5.2 Updating Feed Sources

**Automatic Updates:**
- The service automatically updates feeds according to their configured intervals
- No manual intervention required for routine updates
- Failed downloads are logged and retried on the next cycle

**Manual Updates (if needed):**
To force an immediate update of all feeds:
1. Temporarily disable the CTI service in config.yaml (`enabled: false`)
2. Restart the agent to ensure service is stopped
3. Manually delete the CTI data directory contents (optional, forces fresh download)
4. Re-enable the CTI service in config.yaml (`enabled: true`)
5. Restart the agent

**Adding New Feed Sources:**
To add additional CTI feeds (requires code modification):
1. Add feed configuration to the `feeds` dictionary in `vant/modules/cti/service.py`
2. Implement a parser function for the feed's data format
3. Add the parser to the feed configuration
4. Ensure the `_store_indicators` method handles the new indicator types
5. Update the `get_stats` method to track new indicator types if needed
6. Restart the agent

### 5.3 Managing Storage and Performance

**Data Directory Maintenance:**
- Periodically check the size of the CTI data directory
- The service stores only essential data (IP addresses, domains, etc.) in efficient formats
- Old data is automatically overwritten during updates (no historical retention by design)

**Performance Considerations:**
- CTI lookups use Python sets for O(1) average-case performance
- Memory usage scales with the number of unique indicators stored
- Typical memory consumption for IP-only feeds: ~50-100 MB for 100K-500K IPs
- Performance impact on event processing is minimal (<1ms per event)

**Troubleshooting Common Issues:**

| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| No CTI tags in events | CTI service disabled | Check `cti.enabled: true` in config |
| Empty malicious IP sets | Feed download failures | Check logs for download errors, verify network connectivity |
| High memory usage | Too many feeds or overly aggressive settings | Reduce number of enabled feeds or increase update intervals |
| Service not starting | Invalid configuration | Validate YAML syntax, check data directory permissions |
| Duplicate tags in events | Multiple malicious IPs in single event | Current design limits to first IP found; expected behavior |

### 5.4 Backup and Recovery

**Backup Recommendations:**
- The CTI data directory can be backed up, but since data is re-downloadable from feeds, backup is optional
- If backing up, copy the entire `data_dir` contents
- Backup frequency: Daily or after significant configuration changes

**Recovery Procedure:**
1. Stop the agent
2. Restore the CTI data directory from backup (if available)
3. Start the agent - service will resume with restored data
4. If no backup available, service will automatically re-download feed data on next update cycle

### 5.5 Version Compatibility

The CTI service is compatible with:
- VANT-Agent v2.0.0 and later
- Python 3.7+
- Required packages: requests (included in standard requirements)

When upgrading VANT-Agent:
1. Review release notes for any CTI-specific changes
2. Verify configuration format hasn't changed
3. Test in non-production environment before deploying widely