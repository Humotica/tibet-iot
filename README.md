# tibet-iot

**IoT Transport Layer for TIBET — UDP transport, LAN discovery, and mesh relay.**

[![PyPI](https://img.shields.io/pypi/v/tibet-iot)](https://pypi.org/project/tibet-iot/)

The missing wire layer. tibet-ping defines the protocol, tibet-iot sends it over the network.

## How It Fits Together

```
tibet-core          tibet-ping           tibet-iot
(provenance)        (protocol)           (transport)
 Token, Chain  ───►  PingPacket    ───►  UDP, multicast
 Store, HMAC        Airlock, Trust       LAN discovery
 NetworkBridge      Vouching, Beacon     Mesh relay

pip install         pip install          pip install
tibet-core          tibet-ping           tibet-iot
```

- **tibet-core** stores every action as an immutable, verifiable token
- **tibet-ping** defines the protocol — packets, trust zones, vouching, beacons
- **tibet-iot** sends them over the wire — UDP transport, multicast discovery, mesh relay (this package)

tibet-iot wraps tibet-ping (sync) with async transport. First async package in the TIBET ecosystem.

## Install

```bash
pip install tibet-iot
```

Optional msgpack for compact wire format:
```bash
pip install tibet-iot[msgpack]
```

## Quick Start

```python
import asyncio
from tibet_iot import IoTNode, TransportConfig

async def main():
    node = IoTNode("jis:home:hub", config=TransportConfig(bind_port=7150))
    node.set_trust("jis:home:sensor", 0.9)
    await node.start()

    # Send a real ping over UDP
    response = await node.send_ping(
        target="jis:home:sensor",
        addr=("192.168.1.42", 7150),
        intent="temperature.read",
        purpose="Check room temperature",
    )

    if response:
        print(f"{response.decision} — zone: {response.airlock_zone}")

    await node.stop()

asyncio.run(main())
```

## CLI

```bash
# Listen for incoming pings
tibet-iot listen --did jis:home:hub

# Send a ping to a device
tibet-iot send jis:home:sensor 192.168.1.42:7150 temperature.read --my-did jis:home:hub

# Discover devices on LAN (multicast)
tibet-iot discover

# Demo mode (starts two nodes, pings between them)
tibet-iot demo
```

## Architecture

```
IoTNode (async, this package)
  ├── PingNode (sync, tibet-ping) — protocol layer
  │     ├── Airlock — trust-gated access (GROEN/GEEL/ROOD)
  │     ├── NonceTracker — replay protection
  │     └── TrustStore — per-DID trust scores
  ├── UDPTransport — asyncio DatagramProtocol
  ├── PacketCodec — wire framing (8-byte header + JSON/msgpack)
  ├── PeerTracker — connection state, stale detection
  ├── NetworkDiscovery — LAN multicast beacons
  └── MeshRelay — multi-hop forwarding with loop detection
```

IoTNode uses **composition**, not inheritance. PingNode handles protocol logic synchronously; IoTNode handles I/O asynchronously.

## Wire Format

```
Offset  Size  Field
0       2     Magic: 0x54 0x50 ("TP")
2       1     Version: 0x01
3       1     Flags: bit 0 = is_response, bit 1 = msgpack
4       4     Payload length (uint32, big-endian)
8       N     Payload (JSON or msgpack)
```

## Network

| Port | Purpose |
|------|---------|
| **7150/udp** | Main transport |
| **7151/udp** | Discovery multicast |
| **224.0.71.50** | Multicast group (TTL 2, LAN only) |

## Background Tasks

IoTNode runs three background loops:

| Task | Interval | Purpose |
|------|----------|---------|
| Heartbeat | 30s | Announce presence to known peers |
| Discovery | 60s | Multicast beacon for LAN discovery |
| Peer cleanup | 45s | Prune stale peers (>120s inactive) |

## Mesh Relay

Multi-hop forwarding for devices not directly reachable:

```python
# Packet with routing_mode=MESH gets relayed
packet = sensor.ping(
    target="jis:remote:device",
    intent="data.sync",
    routing_mode=RoutingMode.MESH,
)

# IoTNode automatically:
# 1. Checks if target is a known peer → forward directly
# 2. If not → broadcast to all known peers
# 3. Loop detection via seen-cache (OrderedDict)
# 4. Max 10 hops, then drop
```

## Recording Provenance

Connect network events to tibet-core audit trail:

```python
from tibet_core import Provider, NetworkBridge

tibet = Provider(actor="jis:home:hub")
bridge = NetworkBridge(tibet)

# Every network event becomes a verifiable token
bridge.record_ping(packet, response)
bridge.record_discovery("jis:new:sensor", ("192.168.1.50", 7150), "accepted")
bridge.record_heartbeat("jis:sensor:temp1", addr=("192.168.1.50", 7150))
bridge.record_trust_change("jis:sensor:temp1", 0.5, 0.9, "Vouched by admin")

# Full audit chain of all network activity
for token in tibet.find(action="discovery"):
    print(f"{token.timestamp}: {token.erachter}")
```

## Real-World Example

Tested on a real network: laptop (Kali) → DL360 server over LAN.

```bash
# On the hub (DL360, 192.168.4.76):
python3 listen_hub.py
# Hub listening on 0.0.0.0:7150 as jis:dl360:hub

# From the laptop:
tibet-iot send jis:dl360:hub 192.168.4.76:7150 hello.world --my-did jis:laptop:jasper
# GROEN — trust: 0.95 — RTT: 0.383ms
```

## Trust Zones

Inherited from tibet-ping. No configuration needed — just set trust scores.

| Zone | Score | Behavior |
|------|-------|----------|
| **GROEN** | >= 0.7 | Auto-accept, response sent |
| **GEEL** | 0.3 - 0.7 | Pending review |
| **ROOD** | < 0.3 | Silent drop — no response at all |

## License

MIT — Humotica

## Links

- [tibet-core](https://pypi.org/project/tibet-core/) — Provenance engine (tokens, chains, stores, NetworkBridge)
- [tibet-ping](https://pypi.org/project/tibet-ping/) — Protocol layer (packets, trust, airlock, vouching)
- [tibet-overlay](https://pypi.org/project/tibet-overlay/) — Encrypted mesh networking (WireGuard + noise)
- [Humotica](https://humotica.com)
- [IETF TIBET Draft](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)
- [IETF JIS Draft](https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/)
