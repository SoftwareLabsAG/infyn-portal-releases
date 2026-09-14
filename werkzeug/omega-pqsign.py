#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
omega-pqsign — post-quantensichere Zweitsignatur fuer die Omega-Websites
===========================================================================

Was das hier ist
----------------
Ein kleines Werkzeug, das eine Datei mit **ML-DSA-65** signiert und prueft.
ML-DSA ist das Verfahren, das frueher Dilithium hiess und seit August 2024
als FIPS 204 standardisiert ist. Es gilt als sicher gegen Angriffe mit
Quantenrechnern.

Es ERSETZT die minisign-Signatur nicht — es kommt dazu. Beide decken
dieselbe Datei ab (`SHA256SUMS`):

    SHA256SUMS.minisig   Ed25519, prueft jeder mit `minisign`
    SHA256SUMS.mldsa     ML-DSA-65, prueft man mit diesem Skript

Warum beides und nicht nur ML-DSA: minisign ist ein etabliertes Werkzeug,
das viele Leute schon haben. Eine reine ML-DSA-Signatur koennte heute kaum
jemand pruefen — die Verfahren stecken noch nicht in den Standardwerkzeugen
(OpenSSL kann ML-DSA erst ab 3.5). Ein Umstieg, der die Pruefbarkeit
verschlechtert, waere keiner. Zwei Signaturen nebeneinander sind ausserdem
genau das, was das NIST fuer die Uebergangszeit empfiehlt: faellt eines der
beiden Verfahren, haelt das andere.

Ehrlicher Hinweis zur Bibliothek
--------------------------------
Gerechnet wird mit `dilithium-py`, einer Implementierung in reinem Python.
Sie ist korrekt (gegen die FIPS-204-Testvektoren geprueft), aber **nicht
seitenkanalgehaertet** — die Laufzeit haengt in Teilen von den Daten ab.
Fuers Signieren heisst das: nur auf einer Maschine ausfuehren, auf der
niemand sonst Zeitmessungen anstellen kann, also auf dem eigenen Rechner
und nicht auf einem geteilten Server. Fuers *Pruefen* ist das ohne Belang —
dabei kommt kein Geheimnis vor.

Der private Schluessel
----------------------
Gesichert wird nur ein 32 Byte langer Startwert (Seed); das Schluesselpaar
entsteht daraus jedes Mal neu und identisch (FIPS 204, Abschnitt 5.1).
Die Datei wird mit einem Passwort verschluesselt — mit `openssl enc`, das
auf jedem Mac und Linux schon da ist, damit dieses Skript ohne weitere
Abhaengigkeit auskommt.

Der private Schluessel gehoert NICHT ins Repository, nicht ins Paket, nicht
auf den Server und nicht in ein Backup, das das Haus verlaesst.

Installation
------------
    pip3 install dilithium-py

Aufruf
------
    ./omega-pqsign.py keygen                       einmalig, erzeugt das Paar
    ./omega-pqsign.py sign   DATEI "Kontext"       erzeugt DATEI.mldsa
    ./omega-pqsign.py verify DATEI DATEI.mldsa PUB prueft

Standardorte (wie bei minisign, damit beides beieinander liegt):
    ~/.minisign/omegastack-mldsa.key    privater Seed, verschluesselt
    ~/.minisign/omegastack-mldsa.pub    oeffentlicher Schluessel
"""

import base64
import getpass
import hashlib
import os
import subprocess
import sys
import tempfile

VERSION = 'omega-pqsign 1.0'
FORMAT_SIG = 'omega-pqsig-v1'
FORMAT_PUB = 'omega-pqkey-v1'
ALG = 'ML-DSA-65 (FIPS 204)'

STD_KEY = os.path.expanduser('~/.minisign/omegastack-mldsa.key')
STD_PUB = os.path.expanduser('~/.minisign/omegastack-mldsa.pub')

# Wie oft die Passwortableitung rechnet. Hoch genug, dass Durchprobieren
# teuer wird, niedrig genug, dass das Signieren nicht spuerbar wartet.
PBKDF2_RUNDEN = 600000


# --------------------------------------------------------------- Hilfsmittel
def fehler(text):
    print('\n\033[1;31m✗ %s\033[0m\n' % text, file=sys.stderr)
    sys.exit(1)


def sagen(text):
    print('\n\033[1;31m▸ %s\033[0m' % text)


def ok(text):
    print('  \033[0;32m✓\033[0m %s' % text)


def ml_dsa():
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
    except ImportError:
        fehler('Die Bibliothek fehlt.  Installation:  pip3 install dilithium-py')
    return ML_DSA_65


def openssl_da():
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
    except Exception:
        fehler('openssl wurde nicht gefunden — es wird fuer den Passwortschutz gebraucht.')


def seed_schreiben(pfad, seed, passwort):
    """Seed mit Passwort verschluesselt ablegen (AES-256-CBC, PBKDF2)."""
    openssl_da()
    os.makedirs(os.path.dirname(pfad) or '.', exist_ok=True)
    p = subprocess.run(
        ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', str(PBKDF2_RUNDEN),
         '-salt', '-pass', 'stdin', '-out', pfad],
        input=passwort.encode() + b'\n' + seed, capture_output=True)
    # `-pass stdin` liest die erste Zeile als Passwort, der Rest ist der Inhalt.
    if p.returncode != 0:
        fehler('Der Schluessel liess sich nicht verschluesseln:\n' + p.stderr.decode())
    os.chmod(pfad, 0o600)


def seed_lesen(pfad, passwort):
    openssl_da()
    p = subprocess.run(
        ['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', str(PBKDF2_RUNDEN),
         '-pass', 'stdin', '-in', pfad],
        input=passwort.encode() + b'\n', capture_output=True)
    if p.returncode != 0:
        fehler('Falsches Passwort, oder die Schluesseldatei ist beschaedigt.')
    seed = p.stdout
    if len(seed) != 32:
        fehler('Die Schluesseldatei enthaelt keinen 32-Byte-Startwert (%d gelesen).' % len(seed))
    return seed


def kennung(pk):
    """Kurzer, stabiler Fingerabdruck des oeffentlichen Schluessels."""
    return hashlib.sha256(pk).hexdigest()[:16].upper()


def b64(daten):
    return base64.b64encode(daten).decode()


def umbruch(text, breite=76):
    return '\n'.join(text[i:i + breite] for i in range(0, len(text), breite))


def zu_signieren(kontext, inhalt):
    """Was tatsaechlich signiert wird.

    Nicht nur der Dateiinhalt: der Kontext haengt mit drin. Sonst waere eine
    Signatur fuer die Wallet-Seite auch eine gueltige Signatur fuer die
    Hauptseite, sobald beide dieselbe Datei haetten. Die Zeichenkette am
    Anfang trennt ausserdem diese Verwendung von jeder anderen, die denselben
    Schluessel je benutzen koennte.
    """
    return FORMAT_SIG.encode() + b'\n' + kontext.encode('utf-8') + b'\n' + inhalt


def felder_lesen(zeilen):
    """Einfaches Feldformat:  name: wert

    Lange Werte (die Base64-Bloecke) stehen umbrochen ueber mehrere Zeilen.
    Eine Zeile ohne Doppelpunkt setzt deshalb das vorherige Feld fort —
    Base64 enthaelt nie einen Doppelpunkt, das laesst sich sauber trennen.
    """
    felder, letzt = {}, None
    for z in zeilen:
        if not z.strip():
            continue
        if ':' in z:
            k, _, v = z.partition(':')
            letzt = k.strip()
            felder[letzt] = v.strip()
        elif letzt is not None:
            felder[letzt] += z.strip()
    return felder


def pub_lesen(pfad):
    try:
        zeilen = open(pfad, encoding='utf-8').read().splitlines()
    except OSError as e:
        fehler('Oeffentlicher Schluessel nicht lesbar: %s' % e)
    felder = felder_lesen(zeilen)
    if 'pub' not in felder:
        fehler('In %s steht kein oeffentlicher Schluessel.' % pfad)
    try:
        pk = base64.b64decode(felder['pub'])
    except Exception:
        fehler('Der oeffentliche Schluessel ist nicht lesbar (Base64 fehlerhaft).')
    if len(pk) != 1952:
        fehler('Der oeffentliche Schluessel hat %d statt 1952 Bytes.' % len(pk))
    return pk, felder


def sig_lesen(pfad):
    try:
        zeilen = open(pfad, encoding='utf-8').read().splitlines()
    except OSError as e:
        fehler('Signatur nicht lesbar: %s' % e)
    felder = felder_lesen(zeilen)
    if 'sig' not in felder:
        fehler('In %s steht keine Signatur.' % pfad)
    try:
        sig = base64.b64decode(felder['sig'])
    except Exception:
        fehler('Die Signatur ist nicht lesbar (Base64 fehlerhaft).')
    return sig, felder.get('context', ''), felder


# ------------------------------------------------------------------ Befehle
def cmd_keygen(argv):
    pfad_key = argv[0] if argv else STD_KEY
    pfad_pub = argv[1] if len(argv) > 1 else STD_PUB
    if os.path.exists(pfad_key):
        fehler('Es gibt schon einen Schluessel: %s\n'
               '   Ein neuer wuerde alle bisherigen Signaturen entwerten.\n'
               '   Wenn das gewollt ist, die alte Datei vorher wegbewegen.' % pfad_key)

    M = ml_dsa()
    print(__doc__.split('Installation')[0].rstrip())
    sagen('Neues ML-DSA-65-Schluesselpaar')
    pw1 = getpass.getpass('  Passwort fuer den privaten Schluessel: ')
    if len(pw1) < 12:
        fehler('Bitte mindestens zwoelf Zeichen — dieser Schluessel steht fuer die Echtheit '
               'aller Auslieferungen.')
    pw2 = getpass.getpass('  Passwort wiederholen: ')
    if pw1 != pw2:
        fehler('Die beiden Eingaben stimmen nicht ueberein.')

    seed = os.urandom(32)
    pk, sk = M.key_derive(seed)
    # Gegenprobe: taugt das erzeugte Paar wirklich?
    probe = M.sign(sk, b'selbsttest')
    if not M.verify(pk, b'selbsttest', probe):
        fehler('Selbsttest fehlgeschlagen — das Schluesselpaar wurde nicht gespeichert.')

    seed_schreiben(pfad_key, seed, pw1)
    with open(pfad_pub, 'w', encoding='utf-8') as f:
        f.write('%s\n' % FORMAT_PUB)
        f.write('alg: %s\n' % ALG)
        f.write('id: %s\n' % kennung(pk))
        f.write('pub: %s\n' % umbruch(b64(pk)))
    os.chmod(pfad_pub, 0o644)

    ok('privat:      %s  (Mode 600, mit Passwort verschluesselt)' % pfad_key)
    ok('oeffentlich: %s' % pfad_pub)
    ok('Kennung:     %s' % kennung(pk))
    print("""
  Zwei Dinge jetzt, nicht spaeter:

    1. Der private Schluessel existiert genau einmal. Geht er verloren,
       laesst sich nichts mehr nachsignieren; wird er kopiert, kann jemand
       anderes in eurem Namen signieren. Eine verschluesselte Sicherung an
       einem zweiten Ort ist richtig — eine Kopie im Projektordner nicht.

    2. Der oeffentliche Schluessel gehoert auf die Website, damit ihn
       jemand pruefen kann. Das erledigt release.sh von allein.
""")


def cmd_sign(argv):
    if not argv:
        fehler('Aufruf:  omega-pqsign.py sign DATEI ["Kontext"] [SCHLUESSEL]')
    datei = argv[0]
    kontext = argv[1] if len(argv) > 1 else os.path.basename(datei)
    pfad_key = argv[2] if len(argv) > 2 else STD_KEY
    if not os.path.exists(pfad_key):
        fehler('Kein privater Schluessel unter %s\n   Einmalig anlegen:  %s keygen'
               % (pfad_key, sys.argv[0]))
    try:
        inhalt = open(datei, 'rb').read()
    except OSError as e:
        fehler('Datei nicht lesbar: %s' % e)

    M = ml_dsa()
    pw = os.environ.get('OMEGA_PQ_PASS') or getpass.getpass('  Passwort des ML-DSA-Schluessels: ')
    seed = seed_lesen(pfad_key, pw)
    pk, sk = M.key_derive(seed)
    sig = M.sign(sk, zu_signieren(kontext, inhalt))
    # Sofort gegenpruefen — eine Signatur, die nicht traegt, faellt hier auf
    # und nicht erst beim Besucher.
    if not M.verify(pk, zu_signieren(kontext, inhalt), sig):
        fehler('Die eben erzeugte Signatur liess sich nicht verifizieren. Nichts geschrieben.')

    ziel = datei + '.mldsa'
    with open(ziel, 'w', encoding='utf-8') as f:
        f.write('%s\n' % FORMAT_SIG)
        f.write('alg: %s\n' % ALG)
        f.write('context: %s\n' % kontext)
        f.write('key: %s\n' % kennung(pk))
        f.write('file: %s\n' % os.path.basename(datei))
        f.write('sha256: %s\n' % hashlib.sha256(inhalt).hexdigest())
        f.write('sig: %s\n' % umbruch(b64(sig)))
    ok('%s geschrieben (%d Bytes Signatur, Schluessel %s)' % (ziel, len(sig), kennung(pk)))
    return 0


def cmd_verify(argv):
    if len(argv) < 2:
        fehler('Aufruf:  omega-pqsign.py verify DATEI DATEI.mldsa [SCHLUESSEL.pub]')
    datei, pfad_sig = argv[0], argv[1]
    pfad_pub = argv[2] if len(argv) > 2 else STD_PUB
    try:
        inhalt = open(datei, 'rb').read()
    except OSError as e:
        fehler('Datei nicht lesbar: %s' % e)

    pk, pubfelder = pub_lesen(pfad_pub)
    sig, kontext, sigfelder = sig_lesen(pfad_sig)

    # Sagt die Signatur, sie gehoere zu einem anderen Schluessel?
    if sigfelder.get('key') and sigfelder['key'] != kennung(pk):
        fehler('Die Signatur nennt Schluessel %s, geprueft wurde gegen %s.'
               % (sigfelder['key'], kennung(pk)))

    M = ml_dsa()
    if not M.verify(pk, zu_signieren(kontext, inhalt), sig):
        print('\n\033[1;31m✗ UNGUELTIG\033[0m — die Datei passt nicht zu dieser Signatur.\n'
              '   Entweder wurde sie veraendert, oder die Signatur stammt von woanders.\n',
              file=sys.stderr)
        return 2

    print('\n\033[0;32m✓ GUELTIG\033[0m')
    print('  Datei:     %s' % datei)
    print('  Kontext:   %s' % kontext)
    print('  Verfahren: %s' % ALG)
    print('  Schluessel: %s' % kennung(pk))
    print('\n  Das beweist: diese Datei ist unveraendert und wurde mit dem privaten')
    print('  Gegenstueck zu diesem Schluessel signiert. Ob der Schluessel der richtige')
    print('  ist, muss aus einer zweiten Quelle kommen — etwa der Website selbst.\n')
    return 0


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help', 'help'):
        print(__doc__)
        return 0
    if sys.argv[1] in ('-V', '--version'):
        print(VERSION)
        return 0
    befehl, argv = sys.argv[1], sys.argv[2:]
    if befehl == 'keygen':
        return cmd_keygen(argv) or 0
    if befehl == 'sign':
        return cmd_sign(argv) or 0
    if befehl == 'verify':
        return cmd_verify(argv) or 0
    fehler('Unbekannter Befehl: %s   (keygen | sign | verify)' % befehl)


if __name__ == '__main__':
    sys.exit(main())
