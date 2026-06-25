#!/usr/bin/env bash
# RAVEN — Interactive Tester Kit (bash)
# Usage:
#   export RAVEN_URL="https://your-app.railway.app"
#   export RAVEN_KEY="raven_beta_001"
#   bash scripts/run_tester_kit.sh

set -euo pipefail

URL="${RAVEN_URL:-}"
KEY="${RAVEN_KEY:-}"

if [[ -z "$URL" || -z "$KEY" ]]; then
    echo ""
    echo "  Missing configuration. Set before running:"
    echo '  export RAVEN_URL="https://your-app.railway.app"'
    echo '  export RAVEN_KEY="raven_beta_001"'
    echo ""
    exit 1
fi

# Require curl and python3 (for JSON parsing)
command -v curl   >/dev/null 2>&1 || { echo "curl is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }

_jq() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$1',''))" ; }

SUBMITTED=0
SKIPPED=0

# ── Scenarios ─────────────────────────────────────────────────────────────────
# Format: label|message|source|decision_taken|action_taken|minutes|replaced

SCENARIOS=(
"Repeated failed logins|5 failed login attempts in 2 minutes from IP 45.33.32.156|iam|BLOCK|Blocked the IP after repeated failed logins|10|true"
"Unknown device login|Login from device never seen before in account history|iam|REVIEW|Flagged for manual review and notified user|8|true"
"Password reset abuse|Password reset requested 4 times in 10 minutes for same account|iam|BLOCK|Locked account and alerted security team|15|true"
"API key from new country|API key used from country where account has never been active|network|BLOCK|Revoked session and required re-authentication|12|false"
"Rate abuse — search endpoint|1000 requests to /api/search in 60 seconds from single user|application|BLOCK|Applied rate limit and queued abuse review|5|true"
"Privilege escalation|User granted admin role by non-admin account|iam|BLOCK|Reverted permission change and alerted admin|20|true"
"After-hours SSH|SSH login to production server at 3am outside business hours|infrastructure|REVIEW|Contacted employee to confirm legitimacy|10|false"
"Large outbound transfer|Outbound data transfer of 2GB to unknown external IP in 5 minutes|network|BLOCK|Blocked connection and opened incident|25|true"
"Unusual payroll access|User accessed payroll data for the first time after 2 years on account|audit|REVIEW|Flagged for compliance review|15|true"
"Normal login — baseline|User login successful from registered device during business hours|application|ACCEPT|No action needed — accepted RAVEN verdict|2|false"
)

TOTAL=${#SCENARIOS[@]}

echo ""
echo "  RAVEN — Decision Validation Session"
echo "  $URL"
echo "  $TOTAL scenarios. Press ENTER to submit, s to skip, q to quit."
echo ""

IDX=0
for row in "${SCENARIOS[@]}"; do
    IDX=$((IDX + 1))
    IFS='|' read -r LABEL MSG SRC DEC_TAKEN ACT_TAKEN MINUTES REPLACED <<< "$row"

    echo "  [$IDX/$TOTAL] $LABEL"
    echo "  Event  : $MSG"

    RESP=$(curl -s -X POST "$URL/v1/analyze" \
        -H "X-API-Key: $KEY" \
        -H "Content-Type: application/json" \
        -d "{\"message\":\"$MSG\",\"source\":\"$SRC\"}" 2>&1) || true

    DECISION=$(echo "$RESP"    | _jq decision)
    SCORE=$(echo "$RESP"       | _jq risk_score)
    EXPLANATION=$(echo "$RESP" | _jq explanation)
    INCIDENT_ID=$(echo "$RESP" | _jq incident_id)
    REQUEST_ID=$(echo "$RESP"  | _jq request_id)

    if [[ -z "$DECISION" ]]; then
        echo "  [ERR] Analyze failed — response: $RESP"
        echo ""
        continue
    fi

    echo "  RAVEN  : $DECISION  (score $SCORE)  $EXPLANATION"
    echo ""

    read -rp "  Submit decision? [ENTER=yes / s=skip / q=quit] " CHOICE

    if [[ "$CHOICE" == "q" ]]; then
        echo ""
        echo "  Session ended."
        break
    fi

    if [[ "$CHOICE" == "s" ]]; then
        SKIPPED=$((SKIPPED + 1))
        echo "  Skipped."
        echo ""
        continue
    fi

    FEEDBACK=$(python3 -c "
import json, sys
print(json.dumps({
    'incident_id':             '$INCIDENT_ID',
    'request_id':              '$REQUEST_ID',
    'decision_taken':          '$DEC_TAKEN',
    'action_taken':            '$ACT_TAKEN',
    'confidence':              4,
    'replaced_manual_process': $REPLACED,
    'time_saved_minutes':      $MINUTES,
    'comments':                'Submitted via tester kit'
}))
")

    FR=$(curl -s -X POST "$URL/beta/decision-impact" \
        -H "X-API-Key: $KEY" \
        -H "Content-Type: application/json" \
        -d "$FEEDBACK" 2>&1) || true

    FR_ID=$(echo "$FR" | _jq id)
    if [[ -n "$FR_ID" ]]; then
        SUBMITTED=$((SUBMITTED + 1))
        echo "  [OK] Decision recorded (id: $FR_ID)"
    else
        echo "  [ERR] Feedback failed — response: $FR"
    fi
    echo ""
done

echo ""
echo "  Session complete."
echo "  Submitted : $SUBMITTED decision(s)"
echo "  Skipped   : $SKIPPED"
echo ""

if [[ "$SUBMITTED" -gt 0 ]]; then
    PROOF=$(curl -s "$URL/beta/business-proof" \
        -H "X-API-Key: $KEY" 2>&1) || true
    STATUS=$(echo "$PROOF"      | _jq validation_status)
    TOTAL_D=$(echo "$PROOF"     | _jq total_decisions_influenced)
    REC=$(echo "$PROOF"         | _jq recommendation)
    echo "  Validation status : $STATUS"
    echo "  Total decisions   : $TOTAL_D"
    echo "  Recommendation    : $REC"
fi

echo ""
