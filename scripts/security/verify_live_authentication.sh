#!/usr/bin/env bash
# verify_live_authentication.sh — login, MFA, refresh, logout and token rejection
# against a running deployment, run by the person who knows the password.
#
#   scripts/security/verify_live_authentication.sh [https://ccurepro.cdac.in] [ca-file]
#   scripts/security/verify_live_authentication.sh --negative-only   # no credentials
#
# The password (and an MFA code, if the account has MFA) is read from the terminal with
# no echo; nothing is stored, logged or passed on a command line. Only HTTP statuses and
# yes/no answers are printed. The cookie jar lives in a 0700 temp directory that is
# removed on exit.
#
# --negative-only runs the checks that need no credentials, against a non-existent
# account, so no real account is ever counted towards the lockout.
#
# RESOLVE=host:port:addr (curl --resolve) lets it reach a deployment by name from the
# host that runs it.
set -uo pipefail
NEG=0
if [[ "${1:-}" == "--negative-only" ]]; then NEG=1; shift; fi
BASE="${1:-https://ccurepro.cdac.in}"
CA="${2:-$(dirname "$0")/../../certs/ccure-internal-ca.crt}"
API="$BASE/api"
umask 077
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
JAR="$TMP/jar"

cu() { curl -s --cacert "$CA" ${RESOLVE:+--resolve "$RESOLVE"} -c "$JAR" -b "$JAR" "$@"; }
code() { cu -o "$TMP/body" -w '%{http_code}' "$@"; }
jget() { python3 -c "import json;d=json.load(open('$TMP/body'));print($1)" 2>/dev/null; }

fail=0
row() {
  printf '%-58s %s\n' "$1" "$2"
  [[ "$2" == *FAIL* ]] && fail=1
  return 0
}
want() {
  if [[ "$2" == "$3" ]]; then row "$1" "$2 ok"; else row "$1" "$2 FAIL (wanted $3)"; fi
}

want "login, non-existent account" "$(code -H 'Content-Type: application/json' \
  -d '{"email":"no-such-user@example.invalid","password":"x"}' "$API/auth/login")" 401
want "refresh with no session" "$(code -X POST "$API/auth/refresh")" 401
want "forged HS256 bearer is refused" "$(code -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwidHlwZSI6ImFjY2VzcyJ9.c2ln' "$API/auth/me")" 401

if [[ $NEG == 1 ]]; then
  echo "(negative-only: credential steps skipped)"
  exit $fail
fi

read -r -p "Email or username: " ID
read -r -s -p "Password: " PW
echo
PAYLOAD="$(python3 -c "import json,sys;print(json.dumps({'email':sys.argv[1],'password':sys.argv[2]}))" "$ID" "$PW")"
unset PW
c="$(code -H 'Content-Type: application/json' -d "$PAYLOAD" "$API/auth/login")"
unset PAYLOAD
want "login" "$c" 200

if [[ "$(jget "d.get('mfa_required')")" == "True" ]]; then
  CH="$(jget "d.get('mfa_token')")"
  read -r -s -p "MFA code: " CODE
  echo
  c="$(code -H 'Content-Type: application/json' -d "{\"mfa_token\":\"$CH\",\"code\":\"$CODE\"}" "$API/auth/login/verify-mfa")"
  unset CODE CH
  want "MFA verification" "$c" 200
else
  row "MFA" "not required for this account"
fi

TOKEN="$(jget "d.get('access_token')")"
if [[ -z "$TOKEN" ]]; then
  row "access token received" "FAIL"
  exit 1
fi
HDR="$(python3 - "$TOKEN" <<'PY'
import base64, json, sys
h = sys.argv[1].split(".")[0]
h += "=" * (-len(h) % 4)
d = json.loads(base64.urlsafe_b64decode(h))
print(d.get("alg"), "kid" if d.get("kid") else "NO-KID")
PY
)"
if [[ "$HDR" == "ES256 kid" ]]; then row "access token header" "$HDR ok"; else row "access token header" "$HDR FAIL"; fi

want "authenticated request /auth/me" "$(code -H "Authorization: Bearer $TOKEN" "$API/auth/me")" 200
if [[ "$(jget "'role' in d or 'role_id' in d")" == "False" ]]; then
  row "no legacy role fields in /auth/me" "ok"
else
  row "no legacy role fields in /auth/me" "FAIL"
fi

want "refresh (cookie session)" "$(code -X POST "$API/auth/refresh")" 200
NEW="$(jget "d.get('access_token')")"
want "refreshed token works" "$(code -H "Authorization: Bearer ${NEW:-x}" "$API/auth/me")" 200
want "logout" "$(code -X POST -H "Authorization: Bearer ${NEW:-$TOKEN}" "$API/auth/logout")" 200
want "refresh after logout is refused" "$(code -X POST "$API/auth/refresh")" 401

echo
if [[ $fail == 0 ]]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $fail
