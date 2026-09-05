"""
DL360 Hub Node — tibet-ping transport listener on port 7150.

Trusted DIDs:
  jis:laptop:jasper  (0.95) — Jasper's Kali laptop
  jis:p520:hubby     (0.90) — Gemini/HUBby on P520
  jis:pixel:jasper   (0.95) — JTM app (Pixel 10)
  jis:root:ai        (0.95) — Root AI (localhost)
"""
"""
DL360 Hub Node — tibet-ping transport listener on port 7150.

Integrates tibet-overlay for DID-to-endpoint resolution.

Trusted DIDs:
  jis:laptop:jasper  (0.95) — Jasper's Kali laptop
  jis:p520:hubby     (0.90) — Gemini/HUBby on P520
  jis:pixel:jasper   (0.95) — JTM app (Pixel 10)
  jis:root:ai        (0.95) — Root AI (localhost)
"""
import asyncio
import json
import logging
import os
import secrets
import urllib.request
from dataclasses import fields as _fields
from datetime import datetime, timezone
from pathlib import Path
from tibet_ping import IoTNode, TransportConfig
from tibet_ping.handler import PingHandler
from tibet_ping.proto import PingDecision, PingResponse, PingType, Priority, RoutingMode
from tibet_overlay import IdentityOverlay, OverlayResolver

logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
logger = logging.getLogger("hub")

# HTTP-resolver bridge: the UDP hub is the source of truth for a did's OBSERVED bearer addr (identity is the
# motor, the LAN/hotspot/5G bearer is just the carrier). brain_api's /api/overlay/resolve reads a SEPARATE
# in-process OverlayResolver, so we push every observed did->endpoint into it — that is how a phone off-LAN
# resolves the box by identity over plain HTTPS (api.ainternet.org), then reaches it P2P. Content-blind,
# best-effort; the real gate stays box_status.verify_proof (a spoofed register can only DoS the route).
_BRIDGE_URL = "http://127.0.0.1:8000/api/overlay/register"


def _http_register(did: str, ip: str, port: int) -> None:
    try:
        body = json.dumps({"did": did, "endpoint": f"{ip}:{port}"}).encode("utf-8")
        req = urllib.request.Request(_BRIDGE_URL, data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=3).close()
    except Exception as e:
        logger.debug(f"bridge register failed for {did}: {e}")


# COORDINATED-PUNCH coordinator (MUX-mediated carrier setup): an app that resolved a box but can't reach it
# through a port-restricted CGNAT sends `overlay.want(target=box)` over the live lane. The hub sees the app's
# OBSERVED addr (peer tracker) and relays `overlay.punch_request(app_addr, nonce)` to the box over the
# already-open box<->hub hole. The box then punches toward the app (box_status_ping._punch_sender). The hub
# holds NO trust here — it only reflects addresses and relays the request; the box.status gate stays the proof.
# EEN GEVESTIGDE STANDING, IN DE VORM DIE HET PAKKET KENT.
#
# 0.3.2 zegt 't met een scalar (`trust_score=1.0`), 0.3.5 met een posture (`posture="known"`) —
# en 0.3.5 WEIGERT trust_score met een TypeError. Zonder deze shim zou een uitrol elke
# `overlay.want` breken, en dat is precies het punch-pad waarmee de app door een CGNAT komt.
# Zelfde einddatum als de andere arm: weg zodra 0.3.5 overal draait.
_STANDING = ({"posture": "known"}
             if "posture" in {f.name for f in _fields(PingResponse)}
             else {"trust_score": 1.0})

WANT_INTENT = "overlay.want"
PUNCH_REQUEST_INTENT = "overlay.punch_request"
_WANT_QUEUE: list = []            # (app_did, target_box_did, nonce) enqueued by the sync handler


class WantHandler(PingHandler):
    """Short-circuits overlay.want; delegates everything else to the normal airlock handler."""

    def __init__(self, base):
        super().__init__(base.device_did, base.airlock, base.nonce_tracker, base.vouch_registry)

    def handle(self, packet):
        if packet.intent and packet.intent not in ("heartbeat", ""):
            logger.info(f"handler saw intent={packet.intent!r} from {packet.source_did}")
        if packet.intent == WANT_INTENT:
            p = packet.payload or {}
            logger.info(f"want received: {packet.source_did} -> target {p.get('target')}")
            _WANT_QUEUE.append((packet.source_did, p.get("target"), p.get("nonce")))
            return PingResponse(
                response_id="resp_" + secrets.token_hex(8), in_response_to=packet.packet_id,
                responder_did=self.device_did, decision=PingDecision.ACCEPT, airlock_zone="GROEN",
                payload={"queued": True}, **_STANDING)
        return super().handle(packet)


async def punch_coordinator(node):
    """Drain _WANT_QUEUE: resolve the app + box observed addrs from the peer tracker and relay a
    punch_request to the box, so the box opens its CGNAT toward the app's addr."""
    while True:
        while _WANT_QUEUE:
            app_did, box_did, nonce = _WANT_QUEUE.pop(0)
            try:
                app_addr = node.peers.get_address(app_did)
                box_addr = node.peers.get_address(box_did)
                if app_addr and box_addr:
                    pkt = node._ping_node.ping(
                        target=box_did, intent=PUNCH_REQUEST_INTENT, purpose="coordinated punch",
                        ping_type=PingType.INTENT, priority=Priority.NORMAL, routing_mode=RoutingMode.DIRECT,
                        payload={"app_addr": f"{app_addr[0]}:{app_addr[1]}", "nonce": nonce, "requester": app_did})
                    await node._transport.send_packet(pkt, box_addr)
                    logger.info(f"punch coordinate: {app_did}@{app_addr} -> box {box_did}@{box_addr}")
                else:
                    logger.info(f"punch coordinate: MISSING addr app={app_did}@{app_addr} box={box_did}@{box_addr}")
            except Exception as e:
                logger.debug(f"punch coordinate failed: {e}")
        await asyncio.sleep(0.2)

TRUSTED_DEVICES = {
    "jis:laptop:jasper":         0.95,   # Kali laptop
    "jis:smartphone:jasper":     0.95,   # Smartphone (5G/WiFi)
    "jis:p520:hubby":            0.90,   # Gemini/HUBby (P520)
    "jis:pixel:jasper":          0.95,   # JTM app
    "jis:root:ai":               0.95,   # Root AI (localhost)
    "jis:router:edge":           0.95,   # MIPS Edge Relay
    "jis:bridge:healthcheck":    0.80,   # HTTP bridge health check
    "jis:api:resolver":          0.80,   # API resolver probes
}

# Global overlay instance
overlay = IdentityOverlay(actor="jis:dl360:hub")
resolver = OverlayResolver()

async def sync_overlay_loop(node: IoTNode):
    """Sync node peers to identity overlay."""
    while True:
        try:
            for peer in node.peers.alive_peers():
                did = peer.device_did
                addr = peer.address
                _http_register(did, addr[0], addr[1])   # bridge the observed bearer addr into the HTTP resolver (by identity)
                # Extract device name from DID
                device_id = did.split(":")[-1] if ":" in did else did

                # Check if already registered
                if did not in overlay.nodes:
                    logger.info(f"Registering new node in overlay: {did}")
                    overlay.register(
                        device_id=device_id,
                        ip=addr[0],
                        port=addr[1],
                        behind_nat=True, # Assume NAT for roaming devices
                        capabilities=["tibet-ping"]
                    )
                else:
                    # Update endpoint if changed
                    current_endpoint = f"{addr[0]}:{addr[1]}"
                    if overlay.nodes[did].endpoint != current_endpoint:
                        logger.info(f"Updating endpoint for {did}: {current_endpoint}")
                        overlay.update_endpoint(did, current_endpoint, ip=addr[0], port=addr[1])
            
            await asyncio.sleep(5.0)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Overlay sync error: {e}")
            await asyncio.sleep(10.0)

# GEEL HEEFT EEN BEL NODIG — anders is de hold een zwart gat (#131/#169).
#
# De AirlockGate biedt `on_hitl_needed` al aan en `approve_pending()` bestaat, maar deze hub gaf
# de callback nooit mee. Gemeten 5 sep 2026: pings landden in de pending queue, er werd nooit
# iemand gebeld, en de beller zag een timeout die niet van een kapotte kabel te onderscheiden was.
#
# De wachtrij is een JSONL zodat 'ie een herstart overleeft. Zonder duurzaamheid is een hold geen
# hold maar een drop met betere manieren.
HITL_QUEUE = os.environ.get(
    "TIBET_HUB_HITL_QUEUE", str(Path(__file__).resolve().parent / "hitl-pending.jsonl"))
HITL_OWNER = os.environ.get("TIBET_HUB_HITL_OWNER", "jasper.aint")
# EEN BEL MAG GEEN AANVALSVLAK WORDEN. GEEL komt van een VOUCHED posture, dus 'ie is al begrensd
# door de vouch-registry — maar een plafond is goedkoper dan vertrouwen op die aanname.
HITL_MAX_PENDING = int(os.environ.get("TIBET_HUB_HITL_MAX", "512"))
_hitl_written = 0


def _hitl_bell(pending) -> None:
    """Schrijf de hold duurzaam weg en roep de eigenaar. Loopt NOOIT stil af."""
    global _hitl_written
    src = getattr(pending, "source_did", None) or getattr(pending, "packet_id", "?")
    if _hitl_written >= HITL_MAX_PENDING:
        # EERLIJK DEGRADEREN, NIET STIL. Het record zegt zelf dat het niet meer schrijft.
        logger.warning("HITL queue at cap %d — holding in memory only, from %s",
                       HITL_MAX_PENDING, src)
        return
    row = {
        "kind": "org.ainternet.tping.hitl-pending.v1",
        "packet_id": getattr(pending, "packet_id", None),
        "source_did": getattr(pending, "source_did", None),
        "intent": getattr(pending, "intent", None),
        "at": datetime.now(timezone.utc).isoformat(),
        "notifies": HITL_OWNER,
        "exit": "airlock.approve_pending(packet_id) / reject — and that writes its own receipt",
    }
    try:
        with open(HITL_QUEUE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        _hitl_written += 1
    except OSError as exc:
        logger.error("HITL queue unwritable (%s) — hold is NOT durable: %s", HITL_QUEUE, exc)
    logger.info("HITL held for %s: %s intent=%s -> %s",
                HITL_OWNER, row["source_did"], row["intent"], HITL_QUEUE)


def _wire_hitl_bell(node) -> int:
    """Haak de bel aan de airlock en meld hoeveel holds een herstart overleefd hebben."""
    gate = getattr(getattr(node._ping_node, "handler", None), "airlock", None)
    if gate is None:
        logger.error("no airlock on the handler — GEEL would queue with nobody to ask")
        return -1
    gate.on_hitl_needed = _hitl_bell
    carried = 0
    try:
        with open(HITL_QUEUE, encoding="utf-8") as fh:
            carried = sum(1 for line in fh if line.strip())
    except OSError:
        pass
    logger.info("HITL bell wired -> %s (owner=%s, %d carried over a restart)",
                HITL_QUEUE, HITL_OWNER, carried)
    return carried


async def main():
    config = TransportConfig(bind_port=7150)
    node = IoTNode("jis:dl360:hub", config=config)

    for did, trust in TRUSTED_DEVICES.items():
        # POSTURE, GEEN SCALAR — en bestand tegen beide pakketversies.
        #
        # tibet-ping 0.3.5 haalde `set_trust(did, float)` weg: "zero-trust by identity, not by a
        # scalar — the scalar is dead" (#92/#94). De hub draait nu nog op 0.3.2. Zonder deze tak
        # zou een uitrol van 0.3.5 de hub bij het opstarten doden op een AttributeError, en zou
        # een terugrol 'm nog eens doden. Twee armen maakt de volgorde onbelangrijk.
        #
        # DEZE SHIM HEEFT EEN EINDDATUM: zodra 0.3.5 overal draait valt de else-tak weg, samen
        # met de getallen in TRUSTED_DEVICES. Blijft 'ie staan, dan is het schuld i.p.v. overgang.
        if hasattr(node, "set_known"):
            node.set_known(did)
        else:
            node.set_trust(did, trust)
        # Pre-register trusted devices
        device_id = did.split(":")[-1] if ":" in did else did
        overlay.register(device_id=device_id, capabilities=["trusted"])

    await node.start()

    # Inject the coordinated-punch want-handler (overlay.want short-circuit; everything else = normal airlock)
    node._ping_node.handler = WantHandler(node._ping_node.handler)

    # De hold krijgt z'n EXIT: bel + duurzame wachtrij (#131/#169).
    _wire_hitl_bell(node)

    # Global access for API integration
    global hub_node
    hub_node = node

    print(f"\nHub listening on 0.0.0.0:7150 as jis:dl360:hub")
    print(f"Overlay Registry started (TIBET provenance active)")
    print(f"Trusted devices:")
    for did, trust in TRUSTED_DEVICES.items():
        print(f"  {did} ({trust})")
    
    # Start sync loop + the coordinated-punch coordinator
    sync_task = asyncio.create_task(sync_overlay_loop(node))
    punch_task = asyncio.create_task(punch_coordinator(node))

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        sync_task.cancel()
        punch_task.cancel()
        await node.stop()

if __name__ == "__main__":
    asyncio.run(main())
