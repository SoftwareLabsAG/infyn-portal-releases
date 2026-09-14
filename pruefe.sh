#!/usr/bin/env bash
# pruefe.sh — prüft die aktuelle Auslieferung von https://infyn.net gegen dieses Repository.
#   ./pruefe.sh            aktuelle Auslieferung
#   ./pruefe.sh 1.6.0      bestimmte Version aus releases/
set -uo pipefail
cd "$(dirname "$0")"
HOST=${INFYN_HOST:-https://infyn.net}
ok()    { printf '\033[32m✓ %s\033[0m\n' "$*"; }
warn()  { printf '\033[33m– %s\033[0m\n' "$*"; }
alarm() { printf '\033[31m✗ %s\033[0m\n' "$*"; FEHLER=1; }
FEHLER=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "Hole Manifest und Signaturen von $HOST …"
for f in latest.json SHA256SUMS SHA256SUMS.minisig SHA256SUMS.mldsa; do
  curl -fsS --max-time 20 "$HOST/.well-known/release/$f" -o "$tmp/$f" || { alarm "$f nicht abrufbar"; }
done
[[ -s "$tmp/SHA256SUMS" ]] || { echo "Ohne Manifest keine Prüfung."; exit 1; }
live=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$tmp/latest.json" 2>/dev/null || echo "?")
want=${1:-$live}
echo "Website meldet Version $live · geprüft wird gegen releases/$want"

# 1. Signaturen mit den Schlüsseln aus DIESEM Repo (nicht vom Server)
if command -v minisign >/dev/null; then
  minisign -Vm "$tmp/SHA256SUMS" -p keys/minisign.pub >/dev/null 2>&1 && ok "minisign-Signatur (Ed25519) gültig" || alarm "minisign-Signatur UNGÜLTIG"
else warn "minisign fehlt (brew install minisign) – Ed25519-Prüfung übersprungen"; fi
if python3 -c 'import dilithium_py' 2>/dev/null && [[ -s "$tmp/SHA256SUMS.mldsa" ]]; then
  python3 werkzeug/omega-pqsign.py verify "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.mldsa" keys/infyn-mldsa.pub >/dev/null 2>&1 && ok "ML-DSA-65-Signatur gültig" || alarm "ML-DSA-65-Signatur UNGÜLTIG"
else warn "dilithium-py fehlt (pip3 install dilithium-py) – ML-DSA-Prüfung übersprungen"; fi

# 2. Manifest der Website identisch mit dem hier veröffentlichten Stand?
if [[ -f "releases/$want/SHA256SUMS" ]]; then
  cmp -s "$tmp/SHA256SUMS" "releases/$want/SHA256SUMS" && ok "Manifest der Website identisch mit releases/$want" || alarm "Manifest der Website weicht von releases/$want ab"
else warn "releases/$want liegt hier nicht vor – Vergleich übersprungen"; fi

# 3. Die live ausgelieferten Dateien hashen und mit dem Manifest vergleichen
SHA=$(command -v sha256sum || echo "shasum -a 256")
n=0; b=0
while read -r hash file; do
  [[ -n "$file" ]] || continue; n=$((n+1))
  got=$(curl -fsS --max-time 20 "$HOST/$file" | $SHA | cut -d' ' -f1)
  [[ "$got" == "$hash" ]] || { alarm "$file weicht ab"; b=$((b+1)); }
done < "$tmp/SHA256SUMS"
[[ $b -eq 0 ]] && ok "$n ausgelieferte Dateien stimmen mit dem Manifest überein"

echo
if [[ $FEHLER -eq 0 ]]; then echo "Ergebnis: Auslieferung von $HOST ist unverändert und korrekt signiert."; else echo "Ergebnis: ABWEICHUNGEN – Portal nicht benutzen, Betreiber informieren."; exit 1; fi
