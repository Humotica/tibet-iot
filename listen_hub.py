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
import secrets
import urllib.request
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
                trust_score=1.0, payload={"queued": True})
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

async def main():
    config = TransportConfig(bind_port=7150)
    node = IoTNode("jis:dl360:hub", config=config)

    for did, trust in TRUSTED_DEVICES.items():
        node.set_trust(did, trust)
        # Pre-register trusted devices
        device_id = did.split(":")[-1] if ":" in did else did
        overlay.register(device_id=device_id, capabilities=["trusted"])

    await node.start()

    # Inject the coordinated-punch want-handler (overlay.want short-circuit; everything else = normal airlock)
    node._ping_node.handler = WantHandler(node._ping_node.handler)

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
