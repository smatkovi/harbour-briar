#!/bin/sh
# Two daemons on this machine, talking to each other through real Tor.
#
#   tools/tor-e2e.sh /usr/bin/harbour-briar-briard
#
# Each daemon publishes its own hidden service and knows nothing but the
# other's link and onion address -- no LAN address, no Bluetooth -- so a
# message that arrives has gone out through SOCKS and come back in through
# the hidden service.
set -e
DAEMON=${1:-/usr/bin/harbour-briar-briard}
WORK=${WORK:-/tmp/briar-tor-e2e}
rm -rf "$WORK"; mkdir -p "$WORK/a" "$WORK/b"

# Each daemon gets its own Tor: since the control port wants the cookie from
# the daemon's own tor/ directory, the second daemon cannot share the first
# one's Tor any more. BRIAR_TOR names the Tor binary when none is installed
# where the packages put it (tools/build-tor.sh leaves them in /tmp/tor-build).
start() {   # start <dir> <api> <lan> <torport> <torcontrol>
    "$DAEMON" --state "$WORK/$1/state.json" --api-port "$2" \
        --lan-port "$3" --tor-port "$4" --tor-control-port "$5" > "$WORK/$1.log" 2>&1 &
    echo $!
}
api() {     # api <port> <method> <path> [json]
    if [ -n "$4" ]; then
        curl -s -X "$2" -H 'Content-Type: application/json' -d "$4" \
            "http://127.0.0.1:$1$3"
    else
        curl -s -X "$2" "http://127.0.0.1:$1$3"
    fi
}
feld() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]) or '')" "$1"; }

PID_A=$(start a 8301 7401 7402 59051)
PID_B=$(start b 8302 7403 7404 59061)
trap 'kill $PID_A $PID_B 2>/dev/null' EXIT
sleep 2
api 8301 POST /identity '{"name":"Anna"}' > /dev/null
api 8302 POST /identity '{"name":"Bert"}' > /dev/null

echo "== warte auf die beiden versteckten Dienste (kann eine Minute dauern)"
for i in $(seq 1 90); do
    ONION_A=$(api 8301 GET /status | feld "['onion']")
    ONION_B=$(api 8302 GET /status | feld "['onion']")
    [ -n "$ONION_A" ] && [ -n "$ONION_B" ] && break
    sleep 2
done
[ -n "$ONION_A" ] && [ -n "$ONION_B" ] || { echo "FEHLER: kein Onion-Dienst"; tail -5 "$WORK"/a.log "$WORK"/b.log; exit 1; }
echo "   A: $ONION_A"
echo "   B: $ONION_B"

LINK_A=$(api 8301 GET /status | feld "['link']")
LINK_B=$(api 8302 GET /status | feld "['link']")

# Beide Seiten kennen einander nur über Tor.
api 8301 POST /pending "$(python3 -c "
import json,sys; print(json.dumps({'link': sys.argv[1], 'onion': sys.argv[2]}))" "$LINK_B" "$ONION_B")" > /dev/null
api 8302 POST /pending "$(python3 -c "
import json,sys; print(json.dumps({'link': sys.argv[1], 'onion': sys.argv[2]}))" "$LINK_A" "$ONION_A")" > /dev/null

echo "== Handschlag über Tor"
for i in $(seq 1 60); do
    N=$(api 8301 GET /status | feld "[\"contacts\"]" | wc -c)
    [ "$N" -gt 3 ] && break
    api 8301 POST /connect '{}' > /dev/null 2>&1 || true
    sleep 3
done
api 8301 GET /status | python3 -c "
import json,sys; d=json.load(sys.stdin); print('   Kontakte A:', [c['name'] for c in d['contacts']])"
api 8302 GET /status | python3 -c "
import json,sys; d=json.load(sys.stdin); print('   Kontakte B:', [c['name'] for c in d['contacts']])"

ID=$(api 8301 GET /status | feld "['contacts'][0]['id']")
[ -n "$ID" ] || { echo "FEHLER: kein Kontakt zustande gekommen"; tail -15 "$WORK"/a.log; exit 1; }

# Seit 0.40.0 traegt die Handschlagverbindung gleich die erste Abgleichrunde
# (wie bei Briar: "Reuse the connection as a transport connection"). Beide
# Seiten muessen also eine Runde protokolliert haben, bevor irgendjemand
# angewaehlt hat -- und keine der beiden darf "no sync round on the
# handshake connection" melden.
echo "== Abgleich auf der Handschlagverbindung"
for i in $(seq 1 20); do
    grep -q "sync round on the handshake connection with contact 1 done" "$WORK/a.log" \
        && grep -q "sync round on the handshake connection with contact 1 done" "$WORK/b.log" && break
    sleep 1
done
for seite in a b; do
    grep -q "sync round on the handshake connection with contact 1 done" "$WORK/$seite.log" \
        || { echo "FEHLER: $seite hat auf der Handschlagverbindung keine Runde gemacht"; grep -i "handshake\|sync" "$WORK/$seite.log" | tail -8; exit 1; }
done
echo "   beide Seiten haben auf der Handschlagverbindung abgeglichen"
# Und der Handschlag lief genau einmal je Seite: die Wache gegen parallele
# Handschlaege (0.40.0) laesst den zweiten Versuch nicht mehr zu, solange
# der erste laeuft -- vorher standen hier bis zu sieben, und zwei davon
# hinterliessen verschiedene Hauptschluessel.
for seite in a b; do
    # Beide Ausgaenge zaehlen: ein zweiter, parallel abgeschlossener Handschlag
    # landet im "again"-Zweig -- genau der gefaehrliche Fall.
    N=$(grep -c "contact exchange succeeded\|handshake with .* again" "$WORK/$seite.log")
    [ "$N" -eq 1 ] || { echo "FEHLER: $seite hat $N Handschlaege abgeschlossen statt einem"; grep "contact exchange\|again" "$WORK/$seite.log"; exit 1; }
done
echo "   je Seite genau ein abgeschlossener Handschlag"

echo "== Nachricht über Tor"
api 8301 POST /send "$(python3 -c "
import json,sys; print(json.dumps({'contact': int(sys.argv[1]), 'text': 'Hallo durch Tor'}))" "$ID")" > /dev/null
for i in $(seq 1 40); do
    OUT=$(api 8302 GET "/messages?contact=1" | feld "[\"messages\"]")
    echo "$OUT" | grep -q "Hallo durch Tor" && break
    sleep 3
done
echo "$OUT" | grep -q "Hallo durch Tor" \
    && echo "   angekommen: $OUT" \
    || { echo "FEHLER: nichts angekommen"; tail -15 "$WORK"/a.log "$WORK"/b.log; exit 1; }
echo "== Tor-Weg steht"

# Abschalten: der Lauscher laesst sein Tor fallen (Drop), das Tor soll von
# selbst enden und sein Cookie wegraeumen -- ein liegengebliebenes Cookie
# waere die Ablage, aus der sich ein Fremder auf unserem Port bedienen
# koennte. Geprueft werden beide: kein Prozess mehr, keine Cookie-Datei.
echo "== Tor aus bei A"
api 8301 POST /tor '{"enabled":false}' > /dev/null
for i in $(seq 1 30); do
    if ! pgrep -f "$WORK/a/tor/torrc" > /dev/null 2>&1 \
        && [ ! -e "$WORK/a/tor/control_auth_cookie" ]; then
        echo "   Tor von A ist weg, Cookie auch (nach $i s)"
        break
    fi
    sleep 1
done
pgrep -f "$WORK/a/tor/torrc" > /dev/null 2>&1 && { echo "FEHLER: Tor von A laeuft noch"; exit 1; }
[ -e "$WORK/a/tor/control_auth_cookie" ] && { echo "FEHLER: das Cookie von A liegt noch da"; exit 1; }
echo "== Abschalten sauber"
