# Briar for Sailfish OS and MeeGo Harmattan

Briar's protocol on phones Briar itself will never run on.

Briar is Java, and it needs Java 8. The Nokia N9 and N950 have no JVM and will
never get one; Sailfish has no Android runtime on every device either. So this
is **not a port of Briar's code**. It is a fresh implementation of Briar's
**wire formats** in Rust, with two native interfaces on top — Silica on
Sailfish OS, `com.nokia.meego` on Harmattan.

Both interfaces talk to the same daemon (`briard`) over a small HTTP interface
on `127.0.0.1:8105`, the same shape the WhatsApp and Signal ports on these
devices use.

**It interoperates because every layer is checked against Briar's own bytes**,
not because it looks similar. `vectors/java/` loads the real classes out of
Briar's fat jar (briar-headless 1.5.20) and prints their output as
`key=hex`; `cargo test` in `kern/` compares the Rust side against that, layer
by layer. Without those vectors a reimplementation is guesswork.

## Status

Running and tested between a Jolla (Sailfish 5.2, aarch64), a Nokia N9 and a
Nokia N950 (Harmattan, armv7):

- Handshake and contact exchange over Wi-Fi and over Bluetooth
- Messages both ways, with delivery receipts
- Private groups: create, invite, join, post — posts reach members who are not
  contacts of each other
- Attachments up to 32 KB (images are scaled down first)
- Tor: a statically built Tor 0.4.8.14 ships in the package; the daemon starts
  it, publishes a hidden service and reaches peers at their onion address
- English and German, switchable in the menu; the choice lives in the daemon,
  so it applies to both interfaces and survives a restart

The Tor path was tested twice: between two daemons on one machine (each
reachable only by its onion address), and between the Jolla and the N950 with
Wi-Fi and Bluetooth taken away from the contact — the message arrived over the
hidden service. Addresses announce themselves from then on: the N950 learned
the Jolla's onion address without anyone typing it in.

Not tested: the MeeGo interface has only been looked at by hand (no screenshot
— the device sleeps), and the attachment path is verified byte for byte on the
build machine but only exercised on the devices.

## What is Briar's, and what is not

Every row below is verified against reference bytes from `bramble-core` 1.5.20
(see `vectors/`):

| Layer | File | Vectors |
|---|---|---|
| BLAKE2b derivations, labelled Ed25519 signatures, X25519 | `kern/src/crypto.rs` | `hash`, `mac`, `derive_key`, `sign`, `agree_*` |
| Transport keys, tags, time periods | `kern/src/transport.rs` | `static_master_key`, `hs_*`, `rot_*`, `tag_v4_s3` |
| Stream cipher (XSalsa20-Poly1305, frames) | `kern/src/stream.rs` | `stream` |
| BDF, the data format | `kern/src/bdf.rs` | `bdf_simple`, `bdf_nested`, `bdf_text` |
| Identifiers (author, group, message) | `kern/src/ids.rs` | `author_id`, `group_id`, `message_id` |
| Handshake 0.1 and contact exchange | `kern/src/handshake.rs`, `exchange.rs` | `hs_master_*`, `ex_*` |
| `briar://` links | `kern/src/ids.rs` | `link`, `link_pending_id` |
| Sync protocol, private groups, attachments | `kern/src/sync.rs`, `groups.rs` | format read from the source |

What this port does **differently**, and why:

- **No Tor rendezvous for new contacts.** Briar finds a new contact over Tor.
  Here one of the two sides enters the other's address once — on the LAN, over
  Bluetooth, or as an onion address. After that the devices exchange addresses
  by themselves.
- **No SDP over Bluetooth.** Briar registers a UUID per device and looks up the
  channel. Without a BlueZ binding this port uses a fixed RFCOMM channel (11).
- **No forums, no blogs, no introductions.**
- **A QR code, but not Briar's BQP.** Briar exchanges a handshake secret
  through the code. Here the code carries the `briar://` link with the
  addresses behind it (`?lan=…&bt=…&tor=…`); the other side photographs it and
  has everything filled in. The encoder is our own (`src/qrencode.h`, checked
  against zbar), the decoder is quirc (`src/quirc/`) — neither device has a QR
  library. On the N9 the shutter fires and the picture is read afterwards: Qt
  4.7 gives QML no live camera frames.
- **Addresses follow Briar's shape, not its plan.** Briar's properties client
  announces addresses as its own versioned messages; here they travel in the
  same shape (transport, version, dictionary) through the outbox and are
  repeated until the other side confirms. That way a contact from before Tor
  still learns the onion address.
- **Storage is a JSON file**, not an encrypted H2 database. The format is not
  Briar's business — only the wire has to match.

## Ways to reach a contact

| Way | Address | Needs |
|---|---|---|
| Wi-Fi | `IP:port`, e.g. `192.168.1.12:7327` | same network |
| Bluetooth | `40:98:4E:AD:BD:42` | paired, Bluetooth on |
| Tor | onion address | nothing — a static Tor ships in the package |

If several are known they are tried in order: Wi-Fi, Bluetooth, Tor.

Tor ships with the package because none of these devices can install one:
Sailfish has no Tor in its repositories and Harmattan's have been dead for
years. `tools/build-tor.sh` cross-compiles Tor 0.4.8.14 statically against
musl. On Harmattan it starts switched off (about 30 MB of RAM), on the Jolla
switched on.

## Layout

```
kern/       the daemon in Rust (briard), static against musl
  src/crypto.rs transport.rs stream.rs record.rs   Briar's foundation
  src/handshake.rs exchange.rs sync.rs groups.rs   the protocols
  src/bt.rs tor.rs net.rs                          the transports
  src/store.rs api.rs                              storage and interface
qml/        Silica interface (Sailfish OS)
meego/      Qt 4.7 interface and Debian package (Harmattan)
qml/Briar.js qml/Strings.js                        used by both
src/imageprep.h                                    scaling images (Qt 4 and 5)
vectors/    reference bytes from bramble-core
tools/      building, packaging, installing
```

## Building

Everything is built on a separate build machine (Rust, the musl toolchains,
the Harmattan SDK, the Sailfish SDK container); `tools/buildhost.sh` finds it.

```sh
tools/build.sh                    # daemon (aarch64, armv7, i486) + Harmattan UI
tools/build-tor.sh                # static Tor for the two devices
tools/build-tor.sh i486           # and for the Sailfish emulator
tools/build-rpm.sh aarch64        # Sailfish package -> ~/ps/rpms/briar/
tools/build-rpm.sh armv7hl i486   # the other two Sailfish architectures
tools/build-deb.sh 0.20           # Harmattan package
```

The daemon is **not** built by the RPM: it is the cross-built static binary
from `tools/build.sh`, copied into the tree so qmake can install it. One
consequence worth knowing: the architecture of the package and the architecture
of the binaries inside it come from different places, so check them — an
`i486` package must not end up carrying an ARM daemon.

## Installing

```sh
sudo rpm -Uvh harbour-briar-0.20.0-1.aarch64.rpm
N9_HOST=192.168.1.15 tools/install-meego.sh briar_0.20_armel.deb
```

On Harmattan use **`aegis-dpkg -i`**, never plain `dpkg -i`: otherwise the
files land without registered checksums and nothing out of the package will
start ("Operation not permitted").

## Sailfish OS integration

- **Notifications come from the daemon**, not from the interface, so they
  arrive with the app closed. Category `x-nemo.messaging.im`, one notification
  per chat — the next message replaces the previous one.
- **Replying inside the notification**: the remote action `reply` with
  `x-nemo-remote-action-type-reply=input` calls
  `harbour.briar.Backend.Reply(contact, text)` on the session bus. The daemon
  passes the text to its own HTTP interface, so a reply from the notification
  takes exactly the same path as one from the app.
- **Tapping opens the chat**: remote action `default` to
  `harbour.briar.Gui.openChat`; if the app is not running, the D-Bus service
  starts it.
- **Background daemon** (optional): `harbour-briar-briard.service` as a user
  unit, a switch under "My link" flips it.
- **"Send with Briar"** in the share menu: `harbour-briar-share.desktop` with
  `X-Share-Methods`.
- The daemon speaks D-Bus only in the Sailfish build (`--features sfos`);
  Harmattan has no `org.freedesktop.Notifications` at all.

**No sandbox**: the desktop file sets `Sandboxing=Disabled`. `Base.permission`
allows the `unix` protocol family, `Internet` adds `inet`, `inet6` and
`netlink`, and **no** permission under `/etc/sailjail/permissions` mentions
Bluetooth — a raw `AF_BLUETOOTH` socket fails inside the sandbox with errno 95.
On top of that the sandbox ends with the window, while the daemon is supposed
to keep running.

## MeeGo: inside the built-in Messages app

On the N9 and N950 the message bridge carries Briar into the stock Messages
app — the same bridge that already brings WhatsApp, Signal, Telegram and Matrix
there. It needed almost nothing: the daemon answers the four routes the bridge
knows from the other services.

| Route | Answer |
|---|---|
| `GET /chats` | all contacts and joined groups |
| `GET /messages?jid=c3` | the messages of one chat |
| `GET /send?to=c3&text=…` | send |
| `GET /events?since=N` | long poll, returns on change |

An identifier is `c<contact number>` or `g<group id>`. The app's own interface
keeps using `/messages?contact=` and `POST /send`; both exist side by side.

## When the network comes and goes

The listeners no longer give up. The Bluetooth listener used to bail out if it
could not bind at startup — if Bluetooth happened to be off at that moment, it
stayed silent for the whole run. Now the Wi-Fi and Bluetooth listeners retry
every five seconds (and say so only once), and after several failed `accept`
calls the socket is thrown away and rebound. The Tor control connection is
checked every minute; if it breaks, the hidden service is republished with the
same key, so the address does not change.

On top of that a watcher on the **system bus** waits instead of asking:
ConnMan (Sailfish), ICd2 (Harmattan) and BlueZ report when a network appears or
disappears. Only then does the daemon look whether its own addresses changed.
No polling, no waking the device: six messages to a locked, sleeping phone
arrived with 0 s delay — the incoming connection wakes it by itself.

## Licence

See `LICENSE`. Briar itself is a separate project; this port is neither
affiliated with nor endorsed by it.
