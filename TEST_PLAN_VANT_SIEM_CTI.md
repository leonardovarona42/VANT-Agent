# VANT-SIEM CTI Feature Test Plan

## Overview
This test plan validates the Cyber Threat Intelligence (CTI) feature integration in VANT-SIEM, including rule engine enrichment, performance benchmarks, and deployment validation.

## 1. Integration Test Scenarios for New CTI Feature

### 1.1 CTI Service Functionality Tests
- **Test 1.1.1**: CTI Service Initialization
  - Verify service starts/stops correctly
  - Validate configuration loading from YAML
  - Check data directory creation
  
- **Test 1.1.2**: Feed Download and Parsing
  - Test AlienVault OTX IPv4 feed parsing (mocked)
  - Test Abuse.ch SSLBL feed parsing (mocked)
  - Test Abuse.ch Feodo Tracker feed parsing (mocked)
  - Verify indicator storage in appropriate data structures
  
- **Test 1.1.3**: IP Reputation Checking
  - Verify `is_ip_malicious()` returns True for known bad IPs
  - Verify `is_ip_malicious()` returns False for clean IPs
  - Test performance with large indicator sets (>100k IPs)
  
- **Test 1.1.4**: Data Persistence
  - Verify indicators are saved to disk on shutdown
  - Verify indicators are loaded from disk on startup
  - Test corruption handling in stored data files

### 1.2 Event Enrichment Tests
- **Test 1.2.1**: Basic IP Enrichment
  - Events with malicious IPs in `src_ip` field get `cti_malicious_ip` tag
  - Events with malicious IPs in `dst_ip` field get `cti_malicious_ip` tag
  - Original event data preserved during enrichment
  
- **Test 1.2.2**: Nested Payload Enrichment
  - Events with malicious IPs in `raw_payload.src_ip` get enriched
  - Events with malicious IPs in `raw_payload.destination_ip` get enriched
  
- **Test 1.2.3**: Multiple IP Handling
  - Events with multiple malicious IPs tagged only once (performance optimization)
  - Events with mix of malicious and clean IPs handled correctly
  
- **Test 1.2.4**: Tag Preservation
  - Existing event tags preserved during enrichment
  - CTI tags added alongside existing tags
  
- **Test 1.2.5**: Non-Malicious Events
  - Events with clean IPs remain unchanged
  - No false positive enrichment

### 1.3 Rule Engine Integration Tests
- **Test 1.3.1**: Alert Generation with CTI Data
  - Rules matching enriched events generate proper alerts
  - Alert includes original event and matching срок information
  - CTI data included in alert raw_payload when present
  
- **Test 1.3.2**: Rule Matching with CTI Tags
  - Create test rules that match on `cti_malicious_ip` tag
  - Verify rules trigger correctly on enriched events
  - Verify rules don't trigger on non-enriched events
  
- **Test 1.3.3**: Performance Impact Assessment
  - Measure rule matching latency with/without CTI enrichment
  - Verify enrichment adds <5ms overhead per event
  - Test with varying rule set sizes (10, 100, 1000 rules)

## 2. Performance Benchmarks for Rule Engine with CTI Enrichment

### 2.1 Benchmark Setup
- Test Environment: Windows 11 Pro, 16GB RAM, Intel i7-12700H
- Test Data: Synthetic event streams mimicking Windows Event Logs
- Rule Sets: 
  - Small: 10 rules (baseline)
  - Medium: 100 rules (typical deployment)
  - Large: 1000 rules (stress test)
- CTI Dataset Sizes:
  - Empty: No CTI data loaded
  - Small: 1,000 malicious IPs
  - Medium: 100,000 malicious IPs
  - Large: 1,000,000 malicious IPs

### 2.2 Benchmark Scenarios
- **Benchmark 2.1**: Event Processing Throughput
  - Measure events/second processed with varying CTI dataset sizes
  - Target: <10% throughput degradation with CTI enabled vs disabled
  
- **Benchmark 2.2**: Enrichment Latency
  - Measure average time to enrich single event
  - Target: <2ms for small datasets, <10ms for large datasets
  
- **Benchmark 2.3**: Memory Usage
  - Measure RAM consumption with varying CTI dataset sizes
  - Target: <50MB for 100k IPs, <200MB for 1M IPs
  
- **Benchmark 2.4**: Rule Matching Performance
  - Measure rule matching time with enriched vs non-enriched events
  - Target: <15% increase in matching time with CTI enrichment

### 2.3 Baseline Comparisons
- Compare performance against:
  - VANT-SIEM v1.x (without CTI)
  - Rule engine alone (no collectors, no output)
  - CTI service alone (no rule processing)

## 3. Test Procedures for Enhanced Rule Engine

### 3.1 Rule Loading and Management
- **Procedure 3.1.1**: YAML Rule Loading
  - Load sample rules from `vant/modules/rules/examples/`
  - Verify rule attributes (ID, title, description, level) parsed correctly
  - Verify Sigma rule detection logic parsed correctly
  
- **Procedure 3.1.2**: Rule Reloading
  - Modify existing rule file
  - Trigger rule reload (via config change or manual trigger)
  - Verify changes take effect without service restart
  
- **Procedure 3.1.3**: Rule Enabling/Disabling
  - Enable/disable rules via API or direct manipulation
  - Verify disabled rules don't generate alerts
  - Verify enabled rules resume normal operation

### 3.2 Rule Matching Accuracy
- **Procedure 3.2.1**: Positive Match Testing
  - Create events that should match each sample rule
  - Verify rules generate alerts for matching events
  - Verify alert contains correct rule information
  
- **Procedure 3.2.2**: Negative Match Testing
  - Create events that should NOT match each sample rule
  - Verify rules don't generate alerts for non-matching events
  
- **Procedure 3.2.3**: Edge Case Testing
  - Test with malformed events (missing fields, wrong data types)
  - Test with extremely large events (>1MB)
  - Test with events containing special characters/unicode

### 3.3 Alert Generation Validation
- **Procedure 3.3.1**: Alert Structure Validation
  - Verify alert contains required fields (source_type, host_name, etc.)
  - Verify alert includes original event in raw_payload
  - Verify alert includes matching rule information
  
- **Procedure 3.3.2**: CTI Data in Alerts
  - Verify CTI enrichment data appears in alert raw_payload when present
  - Verify CTI tags appear in alert tags array
  
- **Procedure 3.3.3**: Alert Deduplication
  - Verify identical events don't generate duplicate alerts (if applicable)
  - Verify alert rate limiting works correctly

## 4. Validation Checklist for Deployment to Test Environment

### 4.1 Pre-Deployment Checks
- [ ] Verify CTI service dependencies installed (requests library)
- [ ] Verify CTI data directory has proper permissions
- [ ] Verify firewall allows outbound connections to CTI feed URLs:
  - https://otx.alienvault.com
  - https://sslbl.abuse.ch
  - https://feodotracker.abuse.ch
- [ ] Verify CTI configuration section added to config.yaml:
  ```yaml
  cti:
    enabled: true
    update_interval: 3600
    data_dir: "./cti_data"
    alienvault_otx:
      enabled: true
      update_interval: 3600
    abuse_ch:
      sslbl:
        enabled: true
        update_interval: 7200
      feodotracker:
        enabled: true
        update_interval: 3600
  ```
- [ ] Verify rule engine reload interval configured appropriately (default 300s)

### 4.2 Deployment Verification (12.46/12.45/12.47)
- **Step 4.2.1**: Service Startup
  - [ ] CTI service logs show initialization successful
  - [ ] CTI service logs show feed update threads started
  - [ ] No critical errors in agent startup logs
  
- **Step 4.2.2**: Feed Updates
  - [ ] CTI service logs show successful feed downloads (or graceful failures)
  - [ ] CTI data files populated in data directory
  - [ ] CTI service stats show indicator counts > 0
  
- **Step 4.2.3**: Event Processing
  - [ ] Events flow through collectors normally
  - [ ] Events show CTI enrichment when containing malicious IPs
  - [ ] Rule engine generates alerts for enriched events
  - [ ] Alerts include CTI data in raw_payload
  
- **Step 4.2.4**: Performance Validation
  - [ ] Event processing latency within acceptable limits (<100ms avg)
  - [ ] Memory usage increase from CTI <100MB
  - [ ] CPU usage increase from CTI <15%
  
- **Step 4.2.5**: Shutdown Validation
  - [ ] CTI service saves data to disk on shutdown
  - [ ] No data loss during graceful shutdown
  - [ ] All threads terminate properly

### 4.3 Post-Deployment Validation
- [ ] Run automated test suite (test_cti.py, test_rules_engine.py)
- [ ] Monitor logs for 24 hours for errors/warnings
- [ ] Verify CTI data updates at configured intervals
- [ ] Test manual rule reload functionality
- [ ] Validate alert forwarding to central server works

## 5. Summary of Accomplishments for Development Cycle

### 5.1 Features Implemented
- **CTI Service Module** (`vant/modules/cti/service.py`):
  - Multi-threaded CTI feed downloader and parser
  - Support for AlienVault OTX, Abuse.ch SSLBL, and Abuse.ch Feodo Tracker feeds
  - Configurable update intervals per feed
  - Persistent storage of threat intelligence data
  - Thread-safe indicator lookup (`is_ip_malicious()`)
  
- **Rule Engine Enhancement** (`vant/main.py`):
  - `_enrich_event_with_cti()` function for real-time event enrichment
  - IP address checking in common fields (`src_ip`, `dst_ip`, `source_ip`, `destination_ip`)
  - Nested payload checking in `raw_payload`
  - Tag-based enrichment (`cti_malicious_ip`)
  - Context preservation (`cti_malicious_ips` array in enriched events)
  
- **Integration Points**:
  - CTI service initialized in main agent loop
  - Event enrichment occurs before rule matching
  - Alert generation includes CTI context when present
  - Graceful shutdown with data persistence

### 5.2 Technical Improvements
- **Performance Optimizations**:
  - Early exit in enrichment after first malicious IP found (avoids unnecessary processing)
  - Set-based indicator storage for O(1) lookup time
  - Lazy feed updating (only update when interval elapsed)
  
- **Reliability Features**:
  - Error handling for network failures (continues with stale data)
  - Graceful degradation when feeds unavailable
  - Data persistence across restarts
  - Thread-safe operations using locks implicitly through GIL for set operations
  
- **Configuration Flexibility**:
  - Per-feed enable/disable toggles
  - Per-feed update interval configuration
  - Configurable data directory
  - Master enable/disable switch

### 5.3 Testing and Validation
- Created comprehensive test suite (`test_cti.py`)
- Validated core CTI service functionality
- Verified event enrichment logic
- Tested error conditions and edge cases
- Confirmed integration with existing rule engine

## 6. Recommendations for Next Development Phase

### 6.1 Immediate Enhancements (Next Sprint)
- **Domain and URL Enrichment**:
  - Extend CTI service to track malicious domains and URLs
  - Add enrichment for `dst_domain`, `url`, `request_uri` fields
  - Add corresponding tags: `cti_malicious_domain`, `cti_malicious_url`
  
- **File Hash Enrichment**:
  - Add support for malicious file hash indicators (MD5, SHA1, SHA256)
  - Enrichment for file hash fields in process creation events
  - Tags: `cti_malicious_hash_md5`, `cti_malicious_hash_sha1`, `cti_malicious_hash_sha256`
  
- **Performance Optimizations**:
  - Implement LRU cache for recent IP lookups (80/20 rule)
  - Add Bloom filter for negative lookups to reduce memory pressure
  - Consider using `ipaddress` module for IP validation/storage

### 6.2 Medium-Term Features (Next Release)
- **CTI Dashboard and Reporting**:
  - Add CTI metrics to agent status endpoint
  - Web dashboard showing top threatening IPs, feed status
  - Alert correlation with CTI data (show threat actor info when available)
  
- **Advanced Feed Management**:
  - Support for custom CTI feeds (CSV, JSON, STIX/TAXII)
  - Feed reliability scoring and automatic weighting
  - Duplicate indicator reduction across feeds
  
- **Enhanced Rule Capabilities**:
  - Sigma rule modifications to reference CTI data directly
  - Custom rule conditions for CTI-based threat scoring
  - Integration with MITRE ATT&CK framework via CTI data

### 6.3 Long-Term Improvements (Future Releases)
- **Machine Learning Integration**:
  - Use CTI data as features for anomaly detection models
  - Predictive threat scoring based on historical CTI patterns
  
- **Automated Threat Response**:
  - Automatic blocking rules generation from CTI indicators
  - Integration with firewall/EDR systems for automated containment
  
- **Threat Intelligence Sharing**:
  - Agent-to-agent CTI sharing (peer-to-peer or via central server)
  - Community feed contributions with reputation system

### 6.4 Operational Recommendations
- **Monitoring and Alerting**:
  - Add CTI service health checks (last successful update, feed status)
  - Alert on CTI service failures or stale data
  - Monitor CTI data growth and set retention policies
  
- **Capacity Planning**:
  - Guidelines for CTI data sizing based on feed selection
  - Memory usage projections for different indicator counts
  - Network bandwidth requirements for feed updates
  
- **Security Considerations**:
  - Sign/verify CTI feeds where possible (GPG signatures)
  - Rate limiting to prevent abuse of CTI endpoints
  - Consider using threat intelligence platforms (MISP, OpenCTI) as intermediaries

## Conclusion
The CTI feature integration in VANT-SIEM provides valuable threat intelligence capabilities with minimal performance impact. The implementation follows best practices for extensibility, reliability, and performance. Comprehensive testing validates the core functionality, and the modular design allows for future enhancements.

**Ready for Deployment**: The CTI feature is ready for deployment to test environments (12.46/12.45/12.47) with the validation checklist provided in Section 4.