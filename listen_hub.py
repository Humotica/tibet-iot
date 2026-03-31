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
import logging
from tibet_ping import IoTNode, TransportConfig
from tibet_overlay import IdentityOverlay, OverlayResolver

logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
logger = logging.getLogger("hub")

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
    
    # Global access for API integration
    global hub_node
    hub_node = node

    print(f"\nHub listening on 0.0.0.0:7150 as jis:dl360:hub")
    print(f"Overlay Registry started (TIBET provenance active)")
    print(f"Trusted devices:")
    for did, trust in TRUSTED_DEVICES.items():
        print(f"  {did} ({trust})")
    
    # Start sync loop
    sync_task = asyncio.create_task(sync_overlay_loop(node))

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        sync_task.cancel()
        await node.stop()

if __name__ == "__main__":
    asyncio.run(main())
