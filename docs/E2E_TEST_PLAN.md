# E2E Test Plan: Cloud + Proxy Integration

## Test Environment Setup

- **Cloud**: https://aiproxyguard.com (production) or local
- **Proxy**: Docker image `ovalenzuela/aiproxyguard:0.2.23+`
- **Test accounts**: Free, Pro, Enterprise tiers

---

## 1. Installation & Registration

### 1.1 Fresh Registration
| Test | Steps | Expected |
|------|-------|----------|
| Valid API key | Start proxy with valid `fleet:write` key | Registers successfully, gets instance ID |
| Invalid API key | Start proxy with random key | 401 Unauthorized, retries then continues without registration |
| Expired API key | Use key past expiration date | 401 Unauthorized |
| Single-use key (first use) | Register with single-use key | Success |
| Single-use key (reuse) | Register another instance with same single-use key | 403 "already used" |
| Instance limit exceeded | Register when at plan limit | 403 "Instance limit reached" |
| Missing API key | Start without `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | Runs in standalone mode, no cloud sync |

### 1.2 Re-registration
| Test | Steps | Expected |
|------|-------|----------|
| Restart same container | Stop and restart Docker | Same instance ID, updates last_heartbeat |
| New container same key | New container with multi-use key | New instance ID registered |
| Instance ID collision | Two accounts try same instance_id | 409 Conflict for second account |

---

## 2. Tier & Subscription

### 2.1 Signature Access by Tier
| Test | Steps | Expected |
|------|-------|----------|
| Free tier | Register with free account | Gets ~41 signatures (community only) |
| Pro tier | Register with pro account | Gets ~65 signatures (community + pro) |
| Enterprise tier | Register with enterprise account | Gets all signatures (community + pro + enterprise) |

### 2.2 Tier Changes
| Test | Steps | Expected |
|------|-------|----------|
| Upgrade free -> pro | Change subscription in cloud | Next heartbeat shows tier change, re-syncs signatures |
| Upgrade pro -> enterprise | Change subscription in cloud | Gets enterprise signatures on next sync |
| Downgrade enterprise -> pro | Change subscription in cloud | Loses enterprise signatures (may need restart or cache clear) |
| Downgrade to free | Cancel subscription | Falls back to community signatures only |
| Subscription expired | Let subscription expire | Should revert to free tier behavior |

---

## 3. Signatures & Licensing

### 3.1 Signature Sync
| Test | Steps | Expected |
|------|-------|----------|
| Initial sync | Fresh proxy registration | Downloads all allowed signatures |
| Version change | Publish new signature bundle | Heartbeat detects version change, re-syncs |
| No version change | Heartbeat with same version | No re-download (efficient) |
| Manifest signature verification | Tamper with manifest | Proxy rejects invalid manifest |

### 3.2 Encrypted Bundles (Pro/Enterprise)
| Test | Steps | Expected |
|------|-------|----------|
| License fetch | Pro account requests signatures | License obtained with valid signature |
| License validation | Check license has correct fields | DEK, expires_at, signature present |
| Bundle decryption | Download and decrypt pro bundle | Decrypts successfully, loads signatures |
| Invalid license signature | Tamper with license signature | Proxy rejects, falls back to free |

### 3.3 License Expiration
| Test | Steps | Expected |
|------|-------|----------|
| License near expiry (<24h) | Set short expiry, wait | Auto-refresh triggered on heartbeat |
| License refresh success | Check logs after refresh | "Refreshed license for bundle X" |
| License expired, no refresh | Block license endpoint, restart | Uses cached license if valid, else free only |
| Cached license after restart | Restart proxy with valid cache | Loads from cache without network |
| Expired cache after restart | Restart with expired cached license | Fetches new license from cloud |

---

## 4. Policies

### 4.1 Policy Application
| Test | Steps | Expected |
|------|-------|----------|
| Default policy on register | New instance, no explicit policy | Gets account's default policy |
| Policy content | Check policy has categories | Categories with actions, thresholds |
| Policy version in heartbeat | Check heartbeat response | Returns config_version |

### 4.2 Policy Updates
| Test | Steps | Expected |
|------|-------|----------|
| Update policy in cloud | Change default action to "warn" | Next heartbeat fetches new policy |
| Version change detection | Bump policy version | Proxy logs "Config version changed" |
| Category-specific update | Change jailbreak threshold to 0.5 | New threshold applied |

### 4.3 Policy Behavior
| Test | Steps | Expected |
|------|-------|----------|
| Action: block | Send injection, policy=block | 403 response, request blocked |
| Action: warn | Send injection, policy=warn | 200 response, X-Warning header set |
| Action: log | Send injection, policy=log | 200 response, logged only |
| Threshold 0.9 | Send weak injection | Below threshold, passes |
| Threshold 0.5 | Send weak injection | Above threshold, triggers action |

### 4.4 Allowlists
| Test | Steps | Expected |
|------|-------|----------|
| IP allowlist | Add test IP to allowlist | Requests from IP skip scanning |
| Pattern allowlist | Add pattern to allowlist | Matching content passes |
| User allowlist | Add user/header pattern | Matching requests pass |

### 4.5 Per-Instance Policy
| Test | Steps | Expected |
|------|-------|----------|
| Assign policy to instance | Set instance-specific policy in cloud | Instance gets assigned policy, not default |
| Different instances, different policies | Two instances with different policies | Each behaves per its policy |
| Remove instance policy | Unassign policy | Falls back to default policy |

---

## 5. Fleet Management

### 5.1 Instance Lifecycle
| Test | Steps | Expected |
|------|-------|----------|
| Registration | New proxy starts | Appears in fleet list, status=active |
| Heartbeat | Proxy sends heartbeat | last_heartbeat updated |
| Instance inactive | Stop proxy for >5 minutes | Status changes to inactive |
| Instance deletion | Delete instance from cloud | Proxy continues locally but can't sync |

### 5.2 Instance Limits
| Test | Steps | Expected |
|------|-------|----------|
| Free: 1 instance | Try registering 2nd | 403 "Instance limit reached (1)" |
| Pro: 3 instances | Register 3 | All succeed |
| Pro: 4th instance | Try 4th | 403 "Instance limit reached (3)" |
| Enterprise: 15 instances | Register up to 15 | All succeed |
| Enterprise: 16th | Try 16th | 403 "Instance limit reached (15)" |

---

## 6. ML Models

### 6.1 Model Loading
| Test | Steps | Expected |
|------|-------|----------|
| Free tier model | Start proxy | Loads prompt-classifier-free |
| Pro tier model | Pro account | Should load pro model if available |
| Model in logs | Check startup logs | "ML classifier loaded" with model_id |

### 6.2 Model Sync (if implemented)
| Test | Steps | Expected |
|------|-------|----------|
| Model version change | Publish new model | Proxy downloads and loads |
| Encrypted model | Pro model encrypted | License obtained, decrypted, loaded |
| Model fallback | Pro model unavailable | Falls back to free model |

---

## 7. Scanning Behavior

### 7.1 Detection
| Test | Steps | Expected |
|------|-------|----------|
| Prompt injection | Send "Ignore previous instructions" | Detected, action per policy |
| Jailbreak | Send DAN-style prompt | Detected, action per policy |
| Base64 encoded | Send encoded injection | Decoded and detected |
| Clean prompt | Send normal question | Passes, no detection |

### 7.2 Response Scanning (if enabled)
| Test | Steps | Expected |
|------|-------|----------|
| PII in response | LLM returns SSN | Detected (if enabled) |
| Clean response | Normal LLM response | Passes |

---

## 8. Error Handling & Resilience

### 8.1 Network Issues
| Test | Steps | Expected |
|------|-------|----------|
| Start with no network | Block network, start proxy | Uses cached signatures, runs in standalone |
| Cloud goes down | Block cloud mid-operation | Continues with cached data |
| Network restored | Unblock network | Re-syncs on next heartbeat |

### 8.2 Invalid Data
| Test | Steps | Expected |
|------|-------|----------|
| Corrupted cached bundle | Tamper with cached .enc file | Error logged, fetches fresh |
| Invalid manifest signature | Tamper with manifest | Rejects, uses cached or falls back |
| Malformed policy response | Return invalid JSON | Error logged, keeps previous policy |

### 8.3 Resource Limits
| Test | Steps | Expected |
|------|-------|----------|
| Large request body | Send 10MB+ request | 413 or truncated based on config |
| Scanner timeout | Complex regex causing slowdown | Timeout, request allowed (fail-open) |

---

## 9. Telemetry

### 9.1 Event Reporting
| Test | Steps | Expected |
|------|-------|----------|
| Detection event | Trigger a detection | Event sent to cloud |
| Event in cloud dashboard | Check cloud UI | Detection appears in telemetry |
| Event batching | Multiple detections | Batched and sent efficiently |

### 9.2 Metrics
| Test | Steps | Expected |
|------|-------|----------|
| Prometheus endpoint | GET /metrics | Returns Prometheus format |
| Request count | Send 10 requests | Counter increases |
| Detection count | Trigger detections | Detection counter increases |

---

## 10. Multi-Proxy Scenarios

### 10.1 Multiple Proxies
| Test | Steps | Expected |
|------|-------|----------|
| Same account, multiple proxies | Start 3 proxies | All register, all sync |
| Policy update to all | Update policy | All proxies get update |
| Signature update to all | Publish new bundle | All proxies re-sync |

### 10.2 Load Balancing
| Test | Steps | Expected |
|------|-------|----------|
| Requests to different proxies | Round-robin requests | All behave consistently |
| One proxy down | Stop one proxy | Others continue working |

---

## Test Execution Checklist

### Phase 1: Core Functionality
- [ ] 1.1 Fresh registration with valid key
- [ ] 2.1 Free tier signature access
- [ ] 2.1 Enterprise tier signature access
- [ ] 3.2 Encrypted bundle decryption
- [ ] 4.3 Policy action: block
- [ ] 7.1 Prompt injection detection

### Phase 2: Edge Cases
- [ ] 1.1 Single-use key reuse (fail)
- [ ] 1.1 Instance limit exceeded (fail)
- [ ] 2.2 Tier upgrade
- [ ] 3.3 License auto-refresh
- [ ] 4.2 Policy update propagation
- [ ] 5.2 Instance limits per tier

### Phase 3: Resilience
- [ ] 8.1 Start with no network
- [ ] 8.1 Cloud goes down
- [ ] 8.2 Invalid manifest signature
- [ ] 3.3 Cached license after restart

### Phase 4: Production Readiness
- [ ] 9.1 Telemetry reporting
- [ ] 10.1 Multiple proxies same account
- [ ] Full 24-hour soak test
- [ ] Load test (X requests/sec)

---

## Notes

- Mark each test with PASS/FAIL and date
- Document any bugs found with issue numbers
- Retest after fixes
