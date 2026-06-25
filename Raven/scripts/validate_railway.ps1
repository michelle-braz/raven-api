param(
    [Parameter(Mandatory=$true)]
    [string]$BaseUrl,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey
)

$BaseUrl = $BaseUrl.TrimEnd("/")
$h = @{ "Content-Type" = "application/json" }
$hAuth = @{ "Content-Type" = "application/json"; "X-API-Key" = $ApiKey }
$pass = 0; $fail = 0

function Check($label, $ok, $detail) {
    if ($ok) { Write-Host "  PASS  $label"; $script:pass++ }
    else      { Write-Host "  FAIL  $label -- $detail"; $script:fail++ }
}

Write-Host "`n=== Railway Production Validation ==="
Write-Host "    URL : $BaseUrl"
Write-Host "    Key : $($ApiKey.Substring(0,[Math]::Min(6,$ApiKey.Length)))...`n"

# 1. /status
try {
    $r = Invoke-WebRequest "$BaseUrl/status" -UseBasicParsing -ErrorAction Stop
    $j = $r.Content | ConvertFrom-Json
    Check "/status 200"                    ($r.StatusCode -eq 200)         "got $($r.StatusCode)"
    Check "service = raven-risk-api"        ($j.service -eq "raven-risk-api") "got $($j.service)"
    Check "environment = beta"             ($j.environment -eq "beta")      "got $($j.environment)"
    Check "uptime_seconds is integer > 0"  ($j.uptime_seconds -gt 0)        "got $($j.uptime_seconds)"
    Write-Host "        uptime=$($j.uptime_seconds)s  version=$($j.version)"
} catch { Check "/status reachable" $false $_.Exception.Message }

# 2. Auth guard — no key
try {
    Invoke-WebRequest "$BaseUrl/v1/analyze" -Method POST -Headers $h -Body '{"message":"auth test"}' -UseBasicParsing -ErrorAction Stop
    Check "401 on missing key" $false "got 200"
} catch {
    $j = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "401 on missing key"          ($_.Exception.Response.StatusCode.value__ -eq 401) "got $($_.Exception.Response.StatusCode.value__)"
    Check "error envelope has 'error'"  ($null -ne $j.error)  "missing"
    Check "error envelope has 'code'"   ($null -ne $j.code)   "missing"
    Check "code = unauthorized"         ($j.code -eq "unauthorized") "got $($j.code)"
}

# 3. Functional — /v1/analyze with key
try {
    $body = '{"message":"system recovery test","source":"iam"}'
    $r = Invoke-WebRequest "$BaseUrl/v1/analyze" -Method POST -Headers $hAuth -Body $body -UseBasicParsing -ErrorAction Stop
    $j = $r.Content | ConvertFrom-Json
    Check "/v1/analyze 200"             ($r.StatusCode -eq 200)            "got $($r.StatusCode)"
    Check "risk_score in [0.0, 1.0]"   ($j.risk_score -ge 0 -and $j.risk_score -le 1) "got $($j.risk_score)"
    Check "severity present"            ($null -ne $j.severity)            "missing"
    Check "incident_id present"         ($null -ne $j.incident_id)         "missing"
    Check "source = iam"                ($j.source -eq "iam")              "got $($j.source)"
    Write-Host "        risk=$($j.risk_score)  severity=$($j.severity)  incident=$($j.incident_id)"
} catch { Check "/v1/analyze functional" $false $_.Exception.Message }

# 4. /evaluate legacy engine
try {
    $body = '{"message":"login failed","action":"login_failed","attempts":5,"ip":"192.168.1.1","source":"application"}'
    $r = Invoke-WebRequest "$BaseUrl/evaluate" -Method POST -Headers $hAuth -Body $body -UseBasicParsing -ErrorAction Stop
    $j = $r.Content | ConvertFrom-Json
    Check "/evaluate 200"               ($r.StatusCode -eq 200)            "got $($r.StatusCode)"
    Check "risk_score 0-100"            ($j.risk_score -ge 0 -and $j.risk_score -le 100) "got $($j.risk_score)"
    Check "level present"               ($null -ne $j.level)               "missing"
    Check "source present"              ($null -ne $j.source)              "missing"
    Write-Host "        risk=$($j.risk_score)  level=$($j.level)  source=$($j.source)"
} catch { Check "/evaluate functional" $false $_.Exception.Message }

# 5. 404 envelope
try {
    Invoke-WebRequest "$BaseUrl/no-such-route" -UseBasicParsing -ErrorAction Stop
    Check "404 on unknown route" $false "got 200"
} catch {
    $j = $_.ErrorDetails.Message | ConvertFrom-Json
    Check "404 on unknown route"        ($_.Exception.Response.StatusCode.value__ -eq 404) "got $($_.Exception.Response.StatusCode.value__)"
    Check "404 code = not_found"        ($j.code -eq "not_found")          "got $($j.code)"
}

# 6. Rate limit check (31 rapid requests)
Write-Host "`n  Sending 31 rapid requests to trigger IP rate limit..."
$last = $null
for ($i = 1; $i -le 31; $i++) {
    try {
        $r = Invoke-WebRequest "$BaseUrl/v1/analyze" -Method POST -Headers $hAuth `
             -Body '{"message":"rate limit probe"}' -UseBasicParsing -ErrorAction Stop
        $last = $r
    } catch {
        $last = $_.ErrorDetails.Message | ConvertFrom-Json
        $last | Add-Member -NotePropertyName "_status" -NotePropertyValue $_.Exception.Response.StatusCode.value__ -Force
        break
    }
}
if ($last._status -eq 429) {
    Check "rate limit 429 triggered"       $true ""
    Check "code = rate_limit_exceeded"     ($last.code -eq "rate_limit_exceeded")  "got $($last.code)"
    Check "hint present"                   ($null -ne $last.hint)                  "missing"
} else {
    Check "rate limit 429 triggered" $false "did not hit 429 in 31 requests (limit may be per-day not per-minute here)"
}

Write-Host "`n$('='*40)"
Write-Host "  $pass passed, $fail failed"
Write-Host "$('='*40)`n"
if ($fail -gt 0) { exit 1 }
