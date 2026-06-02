#Requires -RunAsAdministrator
<#
.SYNOPSIS
  One-time setup for Grafana Alloy on this Windows host.
  Configures Windows event log forwarding to Splunk HEC and host metrics to Victoria Metrics.

.PARAMETER splunk_hec_token
  Splunk HTTP Event Collector token.  Run: ./lab.sh hec

.PARAMETER vmauthuser
  Victoria Metrics vmauth basic-auth username.

.PARAMETER vmauthpassword
  Victoria Metrics vmauth basic-auth password.

.EXAMPLE
  .\install.ps1 -splunk_hec_token "abc-123" -vmauthuser "hamid" -vmauthpassword "s3cr3t"
#>

param(
    [Parameter(Mandatory)][string]$splunk_hec_token,
    [Parameter(Mandatory)][string]$vmauthuser,
    [Parameter(Mandatory)][string]$vmauthpassword
)

$ErrorActionPreference = "Continue"

$ALLOY_CONFIG_DIR  = "C:\ProgramData\GrafanaLabs\Alloy"
$ALLOY_CONFIG_DEST = Join-Path $ALLOY_CONFIG_DIR "config.alloy"
$ALLOY_ENV_FILE    = Join-Path $ALLOY_CONFIG_DIR "environment"
$ALLOY_SERVICE     = "Alloy"

# Track per-step outcomes for the final summary
$steps = [ordered]@{
    "Install Alloy"    = "skipped"
    "Write config"     = "pending"
    "Write env file"   = "pending"
    "Start service"    = "pending"
}

function Write-Step  { param([string]$msg) Write-Host "`n==> $msg" }
function Write-Ok    { param([string]$msg) Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Warn  { param([string]$msg) Write-Host "    WARN $msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$msg) Write-Host "    FAIL $msg" -ForegroundColor Red }

# ── 1. Install Alloy if needed ────────────────────────────────────────────────
function Find-AlloyExe {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")

    $cmd = Get-Command alloy -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    foreach ($p in @(
        "C:\Program Files\GrafanaLabs\Alloy\alloy.exe",
        "C:\Program Files (x86)\GrafanaLabs\Alloy\alloy.exe"
    )) { if (Test-Path $p) { return $p } }

    $found = Get-ChildItem "C:\Program Files\GrafanaLabs" -Recurse -Filter alloy.exe -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($null -ne $found) { return $found.FullName }
    return $null
}

Write-Step "Checking for Grafana Alloy"
$alloyExe = Find-AlloyExe

if ($null -eq $alloyExe) {
    Write-Host "    Not found — installing via winget..."
    try {
        winget install --id GrafanaLabs.Alloy --silent --accept-package-agreements --accept-source-agreements
        $alloyExe = Find-AlloyExe
        if ($null -ne $alloyExe) {
            $steps["Install Alloy"] = "ok"
            Write-Ok "Installed: $alloyExe"
        } else {
            $steps["Install Alloy"] = "failed"
            Write-Fail "winget reported success but alloy.exe not found. Continuing — config and env will still be written."
        }
    } catch {
        $steps["Install Alloy"] = "failed"
        Write-Fail "winget error: $_"
        Write-Warn "Continuing — config and env will still be written for when Alloy is installed manually."
    }
} else {
    $steps["Install Alloy"] = "ok"
    Write-Ok "Found: $alloyExe"
}

# ── 2. Write config.alloy ─────────────────────────────────────────────────────
Write-Step "Writing config.alloy"
try {
    if (-not (Test-Path $ALLOY_CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $ALLOY_CONFIG_DIR -Force -ErrorAction Stop | Out-Null
    }

    # Credentials are NOT embedded — they are read at runtime from the environment
    # file written in step 3.  Only the two endpoint URLs are hardcoded.
    @'
// Grafana Alloy — Windows Event Logs → Splunk HEC  +  Host Metrics → Victoria Metrics
//
// Environment variables (written to the service environment file by install.ps1):
//   SPLUNK_HEC_TOKEN  — Splunk HEC token
//   VMAUTH_USER       — Victoria Metrics vmauth username
//   VMAUTH_PASSWORD   — Victoria Metrics vmauth password

// ═══════════════════════════════════════════════════════════════════════════
// LOGS — Windows Event Logs → Splunk HEC (https://localhost:8088)
// ═══════════════════════════════════════════════════════════════════════════

loki.source.windowsevent "security" {
  eventlog_name = "Security"
  xpath_query   = "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4689 or EventID=4698 or EventID=4702 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4725 or EventID=4726 or EventID=4740 or EventID=4776 or EventID=5140)]]"
  forward_to    = [otelcol.receiver.loki.bridge_security.receiver]
}

loki.source.windowsevent "application" {
  eventlog_name = "Application"
  forward_to    = [otelcol.receiver.loki.bridge_application.receiver]
}

loki.source.windowsevent "system" {
  eventlog_name = "System"
  forward_to    = [otelcol.receiver.loki.bridge_system.receiver]
}

otelcol.receiver.loki "bridge_security" {
  output { logs = [otelcol.processor.resourcedetection.security.input] }
}

otelcol.receiver.loki "bridge_application" {
  output { logs = [otelcol.processor.resourcedetection.application.input] }
}

otelcol.receiver.loki "bridge_system" {
  output { logs = [otelcol.processor.resourcedetection.system.input] }
}

otelcol.processor.resourcedetection "security" {
  detectors = ["system"]
  system { hostname_sources = ["os"] }
  output { logs = [otelcol.processor.batch.security.input] }
}

otelcol.processor.resourcedetection "application" {
  detectors = ["system"]
  system { hostname_sources = ["os"] }
  output { logs = [otelcol.processor.batch.application.input] }
}

otelcol.processor.resourcedetection "system" {
  detectors = ["system"]
  system { hostname_sources = ["os"] }
  output { logs = [otelcol.processor.batch.system.input] }
}

otelcol.processor.batch "security" {
  timeout = "5s" ; send_batch_size = 500
  output { logs = [otelcol.exporter.splunkhec.security.input] }
}

otelcol.processor.batch "application" {
  timeout = "5s" ; send_batch_size = 500
  output { logs = [otelcol.exporter.splunkhec.application.input] }
}

otelcol.processor.batch "system" {
  timeout = "5s" ; send_batch_size = 500
  output { logs = [otelcol.exporter.splunkhec.system.input] }
}

otelcol.exporter.splunkhec "security" {
  splunk {
    token      = env("SPLUNK_HEC_TOKEN")
    index      = "winsecurity"
    source     = "WinEventLog:Security"
    sourcetype = "WinEventLog:Security"
  }
  client {
    endpoint             = "https://localhost:8088/services/collector/event"
    insecure_skip_verify = true
  }
}

otelcol.exporter.splunkhec "application" {
  splunk {
    token      = env("SPLUNK_HEC_TOKEN")
    index      = "winsecurity"
    source     = "WinEventLog:Application"
    sourcetype = "WinEventLog:Application"
  }
  client {
    endpoint             = "https://localhost:8088/services/collector/event"
    insecure_skip_verify = true
  }
}

otelcol.exporter.splunkhec "system" {
  splunk {
    token      = env("SPLUNK_HEC_TOKEN")
    index      = "winsecurity"
    source     = "WinEventLog:System"
    sourcetype = "WinEventLog:System"
  }
  client {
    endpoint             = "https://localhost:8088/services/collector/event"
    insecure_skip_verify = true
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// METRICS — Windows host metrics → Victoria Metrics (https://mydomain.lab.net)
// ═══════════════════════════════════════════════════════════════════════════

prometheus.exporter.windows "host" {}

prometheus.scrape "windows" {
  targets         = prometheus.exporter.windows.host.targets
  forward_to      = [prometheus.remote_write.victoriametrics.receiver]
  scrape_interval = "30s"
}

prometheus.remote_write "victoriametrics" {
  endpoint {
    url = "https://mydomain.lab.net/api/v1/write"
    basic_auth {
      username = env("VMAUTH_USER")
      password = env("VMAUTH_PASSWORD")
    }
  }
}
'@ | Out-File -FilePath $ALLOY_CONFIG_DEST -Encoding utf8 -ErrorAction Stop

    $steps["Write config"] = "ok"
    Write-Ok $ALLOY_CONFIG_DEST
} catch {
    $steps["Write config"] = "failed"
    Write-Fail "Could not write config: $_"
}

# ── 3. Write environment file ─────────────────────────────────────────────────
Write-Step "Writing environment file"
try {
    @"
SPLUNK_HEC_TOKEN=$splunk_hec_token
VMAUTH_USER=$vmauthuser
VMAUTH_PASSWORD=$vmauthpassword
"@ | Out-File -FilePath $ALLOY_ENV_FILE -Encoding ascii -ErrorAction Stop

    $steps["Write env file"] = "ok"
    Write-Ok "$ALLOY_ENV_FILE  (3 variables)"
} catch {
    $steps["Write env file"] = "failed"
    Write-Fail "Could not write environment file: $_"
}

# ── 4. Start / restart the Alloy service ─────────────────────────────────────
Write-Step "Starting Alloy service"
try {
    $svc = Get-Service -Name $ALLOY_SERVICE -ErrorAction Stop

    Restart-Service -Name $ALLOY_SERVICE -Force -ErrorAction Stop
    Start-Sleep -Seconds 5

    $svc = Get-Service -Name $ALLOY_SERVICE -ErrorAction SilentlyContinue
    $state = if ($null -ne $svc) { $svc.Status } else { "Unknown" }

    if ($state -eq "Running") {
        $steps["Start service"] = "ok"
        Write-Ok "Service is Running"
    } else {
        $steps["Start service"] = "failed"
        Write-Fail "Service is $state — check: Get-EventLog -LogName Application -Source Alloy -Newest 5"
    }
} catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
    # Service doesn't exist (not yet installed or different install method)
    $steps["Start service"] = "skipped"
    Write-Warn "Service '$ALLOY_SERVICE' not found. Start Alloy manually (as Administrator):"
    Write-Host "    `$env:SPLUNK_HEC_TOKEN = '$splunk_hec_token'"
    Write-Host "    `$env:VMAUTH_USER      = '$vmauthuser'"
    Write-Host "    `$env:VMAUTH_PASSWORD  = '***'"
    Write-Host "    alloy run `"$ALLOY_CONFIG_DEST`""
} catch {
    $steps["Start service"] = "failed"
    Write-Fail "Service restart error: $_"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "─────────────────────────── Summary ────────────────────────────"
$allOk = $true
foreach ($step in $steps.Keys) {
    $result = $steps[$step]
    switch ($result) {
        "ok"      { Write-Host "  [OK]     $step" -ForegroundColor Green }
        "skipped" { Write-Host "  [SKIP]   $step" -ForegroundColor Cyan }
        "failed"  { Write-Host "  [FAILED] $step" -ForegroundColor Red; $allOk = $false }
        "pending" { Write-Host "  [?]      $step" -ForegroundColor Yellow; $allOk = $false }
    }
}
Write-Host "─────────────────────────────────────────────────────────────────"

if ($allOk) {
    Write-Host ""
    Write-Host "All steps completed successfully."
    Write-Host "  Splunk logs:  index=winsecurity  ->  http://localhost:8000"
    Write-Host "  VM metrics:   https://mydomain.lab.net/api/v1/write"
} else {
    Write-Host ""
    Write-Host "One or more steps failed. Review the output above and re-run after fixing." -ForegroundColor Yellow
}
