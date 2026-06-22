# Finding — Guest Wi-Fi Has No Client Isolation (Intra-Guest L2 → ARP MitM)

> ⚠️ **OPERATOR COPY.** Sanitize captured peer MAC/IP lists before client delivery.

| | |
|---|---|
| **Severity** | High |
| **Category** | Wireless Client Isolation Bypass (Layer-2) |
| **Status** | Confirmed |
| **Date** | 2026-06-17 |
| **Affected SSID** | `Guest_WiFi` (open + captive portal) |

---

## 1. Summary

The guest WLAN **`Guest_WiFi`** enforces a captive portal but provides **no Layer-2
client isolation**. Any associated client can enumerate and send unicast frames to every
other guest device, enabling **ARP-spoofing man-in-the-middle** between guests.

## 2. Affected Components

| Component | Detail |
|---|---|
| SSID | `Guest_WiFi` — open (`key_mgmt=NONE`) with captive portal |
| Guest VLAN | `10.0.0.0/16`, gateway `10.0.0.1` |

## 3. Reproduction

```bash
arp-scan -I wlan0 10.0.0.0/16
# -> ~72 hosts answered, each a distinct MAC -> AP forwards client-to-client traffic
```

## 4. Impact

* **Intra-guest MitM via ARP spoofing** — harvest credentials, hijack sessions, or
  inject content into another guest's traffic. Effective regardless of host firewalls.
* **Guest device enumeration** — full inventory of concurrent devices (IP + MAC).

## 5. Remediation

* **Enable client/peer-to-peer isolation on the guest WLAN.**
  * Cisco WLC/9800: *P2P Blocking Action = Drop*.
  * Meraki: *Client isolation* on the guest SSID.
* Treat the captive portal as Layer-3 only; complement it with Layer-2 isolation.

## Appendix A — `guest_isolation_check.sh`

Associates to the guest SSID, forces a fresh lease, then runs L2 peer discovery.
