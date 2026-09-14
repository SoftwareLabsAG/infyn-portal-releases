# infyn-portal-releases

Signierte Auslieferungen des **Infyn Portals** (https://infyn.net) – der öffentliche Prüfpunkt.
Hier liegt kein Quellcode, keine Konfiguration und kein privater Schlüssel: nur das, was man zum
Prüfen braucht.

| Ordner / Datei | Inhalt |
|---|---|
| `releases/<version>/SHA256SUMS` | Manifest: SHA-256 jeder Datei, die der Browser eines Nutzers unverändert erhält (JavaScript, Bilder, Favicon, Web-Manifest) |
| `releases/<version>/SHA256SUMS.minisig` | Signatur 1 – minisign (Ed25519) |
| `releases/<version>/SHA256SUMS.mldsa` | Signatur 2 – ML-DSA-65 (FIPS 204, quantensicher) |
| `releases/<version>/latest.json` | Version, Commit-Kurzhash, Datum, Dateiliste |
| `latest.json` | Kopie des aktuellen Standes |
| `keys/minisign.pub`, `keys/infyn-mldsa.pub` | öffentliche Schlüssel – bewusst hier und nicht auf dem Server |
| `werkzeug/omega-pqsign.py` | prüft (und erzeugt) ML-DSA-Signaturen; braucht `python3` und `dilithium-py` |
| `pruefe.sh` | holt Manifest und Signaturen von infyn.net, prüft beide Signaturen, vergleicht mit diesem Repo und hasht die live ausgelieferten Dateien |

## Prüfen

```bash
git clone https://github.com/SoftwareLabsAG/infyn-portal-releases.git
cd infyn-portal-releases
./pruefe.sh
```

Benötigt: `minisign` (`brew install minisign`), `curl`, `shasum`/`sha256sum`; für die ML-DSA-Prüfung
`python3` mit `dilithium-py` (`pip3 install dilithium-py`). Fehlt etwas, prüft das Skript, was es kann,
und sagt, was übersprungen wurde.

## Was die Prüfung aussagt

Signieren tut ausschliesslich ein Rechner ausserhalb des Servers. Wer den Server übernimmt, kann Dateien
ändern, aber das Manifest nicht neu signieren – die privaten Schlüssel waren dort nie. Stimmen Signaturen
und Prüfsummen, ist das ausgelieferte JavaScript (insbesondere `js/wallet-link.js`, das die Wallet zur
Signatur auffordert) genau das, was freigegeben wurde. Die dynamischen Seiten selbst (Login, Onboarding)
lassen sich wegen wechselnder Sicherheits-Nonces nicht hashen; ihr Verhalten steckt in den signierten
Skripten.

Die Prüfseite im Portal: https://infyn.net/pruefen
