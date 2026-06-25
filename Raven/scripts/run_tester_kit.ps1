# RAVEN - Interactive Tester Kit (Windows PowerShell)
# Usage:
#   $env:RAVEN_URL = "https://your-app.railway.app"
#   $env:RAVEN_KEY = "raven_beta_001"
#   .\scripts\run_tester_kit.ps1

param(
    [string]$Url  = $env:RAVEN_URL,
    [string]$Key  = $env:RAVEN_KEY
)

if (-not $Url -or -not $Key) {
    Write-Host ""
    Write-Host "  Missing configuration. Set before running:" -ForegroundColor Red
    Write-Host '  $env:RAVEN_URL = "https://your-app.railway.app"'
    Write-Host '  $env:RAVEN_KEY = "raven_beta_001"'
    Write-Host ""
    exit 1
}

$headers = @{ "X-API-Key" = $Key; "Content-Type" = "application/json" }

$scenarios = @(
    @{
        label           = "Repeated failed logins"
        message         = "5 failed login attempts in 2 minutes from IP 45.33.32.156"
        source          = "iam"
        decision_taken  = "BLOCK"
        action_taken    = "Blocked the IP after repeated failed logins"
        minutes         = 10
        replaced        = $true
    },
    @{
        label           = "Unknown device login"
        message         = "Login from device never seen before in account history"
        source          = "iam"
        decision_taken  = "REVIEW"
        action_taken    = "Flagged for manual review and notified user"
        minutes         = 8
        replaced        = $true
    },
    @{
        label           = "Password reset abuse"
        message         = "Password reset requested 4 times in 10 minutes for same account"
        source          = "iam"
        decision_taken  = "BLOCK"
        action_taken    = "Locked account and alerted security team"
        minutes         = 15
        replaced        = $true
    },
    @{
        label           = "API key from new country"
        message         = "API key used from country where account has never been active"
        source          = "network"
        decision_taken  = "BLOCK"
        action_taken    = "Revoked session and required re-authentication"
        minutes         = 12
        replaced        = $false
    },
    @{
        label           = "Rate abuse - search endpoint"
        message         = "1000 requests to /api/search in 60 seconds from single user"
        source          = "application"
        decision_taken  = "BLOCK"
        action_taken    = "Applied rate limit and queued abuse review"
        minutes         = 5
        replaced        = $true
    },
    @{
        label           = "Privilege escalation"
        message         = "User granted admin role by non-admin account"
        source          = "iam"
        decision_taken  = "BLOCK"
        action_taken    = "Reverted permission change and alerted admin"
        minutes         = 20
        replaced        = $true
    },
    @{
        label           = "After-hours SSH"
        message         = "SSH login to production server at 3am outside business hours"
        source          = "infrastructure"
        decision_taken  = "REVIEW"
        action_taken    = "Contacted employee to confirm legitimacy"
        minutes         = 10
        replaced        = $false
    },
    @{
        label           = "Large outbound transfer"
        message         = "Outbound data transfer of 2GB to unknown external IP in 5 minutes"
        source          = "network"
        decision_taken  = "BLOCK"
        action_taken    = "Blocked connection and opened incident"
        minutes         = 25
        replaced        = $true
    },
    @{
        label           = "Unusual payroll access"
        message         = "User accessed payroll data for the first time after 2 years on account"
        source          = "audit"
        decision_taken  = "REVIEW"
        action_taken    = "Flagged for compliance review"
        minutes         = 15
        replaced        = $true
    },
    @{
        label           = "Normal login - baseline"
        message         = "User login successful from registered device during business hours"
        source          = "application"
        decision_taken  = "ACCEPT"
        action_taken    = "No action needed - accepted RAVEN verdict"
        minutes         = 2
        replaced        = $false
    }
)

$submitted = 0
$skipped   = 0

Write-Host ""
Write-Host "  RAVEN - Decision Validation Session" -ForegroundColor Cyan
Write-Host "  $Url" -ForegroundColor DarkGray
Write-Host "  $($scenarios.Count) scenarios. Press ENTER to submit each decision, S to skip, Q to quit." -ForegroundColor DarkGray
Write-Host ""

foreach ($s in $scenarios) {
    Write-Host "  [$($submitted + $skipped + 1)/$($scenarios.Count)] $($s.label)" -ForegroundColor Yellow
    Write-Host "  Event  : $($s.message)" -ForegroundColor DarkGray

    # Call /v1/analyze
    try {
        $body = @{ message = $s.message; source = $s.source } | ConvertTo-Json -Compress
        $resp = Invoke-RestMethod -Method POST -Uri "$Url/v1/analyze" -Headers $headers -Body $body -ErrorAction Stop
    } catch {
        Write-Host "  [ERR] Analyze failed: $_" -ForegroundColor Red
        continue
    }

    $color = switch ($resp.decision) {
        "BLOCK"  { "Red" }
        "REVIEW" { "Yellow" }
        default  { "Green" }
    }

    Write-Host "  RAVEN  : " -NoNewline
    Write-Host $resp.decision -ForegroundColor $color -NoNewline
    Write-Host "  (score $($resp.risk_score))  $($resp.explanation)"
    Write-Host ""

    $input = Read-Host "  Submit decision? [ENTER=yes / S=skip / Q=quit]"

    if ($input -ieq "Q") {
        Write-Host ""
        Write-Host "  Session ended." -ForegroundColor DarkGray
        break
    }

    if ($input -ieq "S") {
        $skipped++
        Write-Host "  Skipped.`n" -ForegroundColor DarkGray
        continue
    }

    # Submit decision impact
    $feedback = @{
        incident_id             = $resp.incident_id
        request_id              = $resp.request_id
        decision_taken          = $s.decision_taken
        action_taken            = $s.action_taken
        confidence              = 4
        replaced_manual_process = $s.replaced
        time_saved_minutes      = $s.minutes
        comments                = "Submitted via tester kit"
    } | ConvertTo-Json -Compress

    try {
        $fr = Invoke-RestMethod -Method POST -Uri "$Url/beta/decision-impact" -Headers $headers -Body $feedback -ErrorAction Stop
        $submitted++
        Write-Host "  [OK] Decision recorded (id: $($fr.id))" -ForegroundColor Green
    } catch {
        Write-Host "  [ERR] Feedback failed: $_" -ForegroundColor Red
    }

    Write-Host ""
}

# Final summary
Write-Host ""
Write-Host "  Session complete." -ForegroundColor Cyan
Write-Host "  Submitted : $submitted decision(s)" -ForegroundColor Green
Write-Host "  Skipped   : $skipped" -ForegroundColor DarkGray
Write-Host ""

if ($submitted -gt 0) {
    try {
        $proof = Invoke-RestMethod -Method GET -Uri "$Url/beta/business-proof" -Headers $headers -ErrorAction Stop
        Write-Host "  Validation status : $($proof.validation_status)" -ForegroundColor Cyan
        Write-Host "  Total decisions   : $($proof.total_decisions_influenced)" -ForegroundColor Cyan
        Write-Host "  Recommendation    : $($proof.recommendation)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  (Could not fetch business-proof: $_)" -ForegroundColor DarkGray
    }
}

Write-Host ""
