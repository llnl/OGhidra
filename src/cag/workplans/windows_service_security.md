# Windows Service Security Analysis

## Goal
Determine if the binary is a Windows service and assess its privilege context.

### Step 1: Identify Service Entry Points

Execute simultaneously to discover service-related imports:

```
EXECUTE: list_imports(offset=0, limit=300)
EXECUTE: list_strings(offset=0, limit=500, filter="Service")
EXECUTE: list_strings(offset=0, limit=500, filter="service")
```

**Look for these service control APIs**:
- `StartServiceCtrlDispatcher` - Primary service entry point (definitive indicator)
- `RegisterServiceCtrlHandler` / `RegisterServiceCtrlHandlerEx` - Control handler registration
- `SetServiceStatus` - Status reporting to SCM
- `ControlService` - Service control operations

**Registry strings indicating service installation**:
- `SYSTEM\\CurrentControlSet\\Services` - Service registration path
- Service-related keywords: "ServiceMain", "SCM", "Service Control Manager"

**If ANY service API found**:
- Binary is confirmed as a Windows service
- Proceed to Step 2: Path Analysis
- Mark investigation as "SERVICE CONTEXT - PRIVILEGED"

**If NO service APIs found**:
- Skip to executable loading analysis (may still be vulnerable)
