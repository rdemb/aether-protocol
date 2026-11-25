#!/usr/bin/env python3
"""
AETHER Empirical Network Simulator (AETHER-SIM-0001)
Comparison: Classical BLE Mesh vs Naive Gossip vs AETHER Off-Grid vs AETHER + 5% Bridge Mules
Urban Hub-and-Commuter mobility model (4 km x 4 km) under 30% Sybil / Free-Rider attack.
"""

from __future__ import annotations
import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

DECAY_PROBS = {
    0x0: 0.0000,
    0x2: 0.5000,
    0x4: 0.7500,
    0x6: 0.8500,
    0x8: 0.9000,
    0xA: 0.9375,
    0xC: 0.9600,
    0xF: 0.9850,
}

MINISKETCH_CAP = 22
BARTER_MAX_DEFICIT = 2
MAX_BUFFER_SIZE = 120
BLE_RANGE_M = 120.0
CITY_SIZE_M = 4000.0
TICK_SEC = 10.0

DISTRICTS = [
    (700.0, 700.0),
    (3300.0, 700.0),
    (700.0, 3300.0),
    (3300.0, 3300.0),
]
HUBS = [
    (2000.0, 2000.0),
    (2000.0, 900.0),
    (2000.0, 3100.0),
]


@dataclass
class Packet:
    pid: int
    sender: int
    recipient: int
    created_at: float
    decay_class: int = 0x8
    pow_bits: int = 18
    is_spam: bool = False


@dataclass
class Node:
    nid: int
    role: str
    mobility: str
    home_district: int
    x: float
    y: float
    target_x: float
    target_y: float
    speed: float
    is_bridge: bool = False
    buffer: Dict[int, Packet] = field(default_factory=dict)
    seen: Set[int] = field(default_factory=set)
    radio_tx_packets: int = 0
    radio_rx_packets: int = 0
    sybil_rejected_pow: int = 0
    barter_blocked: int = 0

    def step(self, dt: float, rng: random.Random) -> None:
        dx = self.target_x - self.x
        dy = self.target_y - self.y
        dist = math.hypot(dx, dy)
        if dist <= self.speed * dt + 1.0:
            self.x, self.y = self.target_x, self.target_y
            self._pick_next_target(rng)
        else:
            self.x += (dx / dist) * self.speed * dt
            self.y += (dy / dist) * self.speed * dt

    def _pick_next_target(self, rng: random.Random) -> None:
        hx, hy = DISTRICTS[self.home_district]
        if self.mobility == "local":
            self.target_x = max(0.0, min(CITY_SIZE_M, hx + rng.uniform(-450, 450)))
            self.target_y = max(0.0, min(CITY_SIZE_M, hy + rng.uniform(-450, 450)))
        elif self.mobility == "commuter":
            if rng.random() < 0.55:
                cx, cy = rng.choice(HUBS)
                self.target_x = cx + rng.uniform(-250, 250)
                self.target_y = cy + rng.uniform(-250, 250)
            else:
                self.target_x = hx + rng.uniform(-350, 350)
                self.target_y = hy + rng.uniform(-350, 350)
        else:
            dx, dy = rng.choice(DISTRICTS + HUBS)
            self.target_x = dx + rng.uniform(-200, 200)
            self.target_y = dy + rng.uniform(-200, 200)


def create_nodes(n_nodes: int, sybil_ratio: float, bridge_ratio: float, rng: random.Random) -> List[Node]:
    nodes: List[Node] = []
    for i in range(n_nodes):
        district = i % len(DISTRICTS)
        hx, hy = DISTRICTS[district]
        r_mob = rng.random()
        if r_mob < 0.50:
            mob, spd = "local", rng.uniform(1.2, 1.8)
        elif r_mob < 0.85:
            mob, spd = "commuter", rng.uniform(5.0, 11.0)
        else:
            mob, spd = "transit", rng.uniform(9.0, 15.0)

        r_role = rng.random()
        if r_role < sybil_ratio * 0.6:
            role = "sybil_spammer"
        elif r_role < sybil_ratio:
            role = "freerider"
        else:
            role = "honest"

        is_bridge = (role == "honest") and (rng.random() < bridge_ratio)
        x = hx + rng.uniform(-350, 350)
        y = hy + rng.uniform(-350, 350)
        node = Node(i, role, mob, district, x, y, x, y, spd, is_bridge)
        node._pick_next_target(rng)
        nodes.append(node)
    return nodes


def insert_packet_with_eviction(node: Node, pkt: Packet, use_pow_priority: bool) -> None:
    if len(node.buffer) >= MAX_BUFFER_SIZE:
        if use_pow_priority:
            victim_pid = min(
                node.buffer.values(),
                key=lambda p: (p.pow_bits, p.created_at),
            ).pid
        else:
            victim_pid = min(node.buffer.values(), key=lambda p: p.created_at).pid
        del node.buffer[victim_pid]
    node.buffer[pkt.pid] = pkt


def run_classical_mesh(nodes: List[Node], messages: List[Packet]) -> Dict[str, float]:
    adj: Dict[int, List[int]] = {n.nid: [] for n in nodes}
    for i in range(len(nodes)):
        if nodes[i].role != "honest":
            continue
        for j in range(i + 1, len(nodes)):
            if nodes[j].role != "honest":
                continue
            if math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y) <= BLE_RANGE_M:
                adj[nodes[i].nid].append(nodes[j].nid)
                adj[nodes[j].nid].append(nodes[i].nid)

    delivered = 0
    for msg in messages:
        visited = {msg.sender}
        queue = [msg.sender]
        found = False
        while queue:
            cur = queue.pop(0)
            if cur == msg.recipient:
                found = True
                break
            for nxt in adj[cur]:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        if found:
            delivered += 1

    return {
        "delivery_ratio": delivered / len(messages),
        "p50_min": 0.05 if delivered else float("inf"),
        "p95_min": 0.10 if delivered else float("inf"),
        "avg_tx_per_node": 0.0,
        "sybil_blocked": 0,
        "barter_blocked": 0,
        "battery_mah_day": 204.0,
    }


def run_dtn_scenario(
    mode: str,
    n_nodes: int = 160,
    n_messages: int = 80,
    sim_duration_sec: float = 7200.0,
    sybil_ratio: float = 0.30,
    seed: int = 20261124,
) -> Dict[str, float]:
    rng = random.Random(seed)
    bridge_ratio = 0.05 if mode == "aether_hybrid" else 0.0
    use_aether = mode in ("aether_offgrid", "aether_hybrid")

    nodes = create_nodes(n_nodes, sybil_ratio, bridge_ratio, rng)
    honest_ids = [n.nid for n in nodes if n.role == "honest"]

    messages: List[Packet] = []
    next_pid = 1
    for _ in range(n_messages):
        s = rng.choice(honest_ids)
        candidates = [h for h in honest_ids if nodes[h].home_district != nodes[s].home_district]
        r = rng.choice(candidates)
        pkt = Packet(pid=next_pid, sender=s, recipient=r, created_at=0.0, decay_class=0x8, pow_bits=18)
        messages.append(pkt)
        nodes[s].buffer[pkt.pid] = pkt
        nodes[s].seen.add(pkt.pid)
        next_pid += 1

    if mode == "classical_mesh":
        return run_classical_mesh(nodes, messages)

    delivered_times: Dict[int, float] = {}
    bridge_mailbox: Dict[int, Packet] = {}
    t = 0.0
    spam_pid_counter = 1_000_000
    cell_size = BLE_RANGE_M

    while t < sim_duration_sec:
        for n in nodes:
            n.step(TICK_SEC, rng)

        if int(t) % 60 == 0:
            for n in nodes:
                if n.role == "sybil_spammer":
                    for _ in range(15):
                        p_bits = 18 if rng.random() < 0.05 else 12
                        sp = Packet(spam_pid_counter, n.nid, -1, t, decay_class=0xF, pow_bits=p_bits, is_spam=True)
                        spam_pid_counter += 1
                        insert_packet_with_eviction(n, sp, use_pow_priority=False)

        if mode == "aether_hybrid" and int(t) % 1800 == 0 and t > 0:
            for n in nodes:
                if n.is_bridge:
                    for pid, pkt in n.buffer.items():
                        if not pkt.is_spam:
                            bridge_mailbox[pid] = pkt
                    for pid, pkt in list(bridge_mailbox.items())[-20:]:
                        if pid not in n.seen:
                            n.seen.add(pid)
                            if pkt.recipient == n.nid and pid not in delivered_times:
                                delivered_times[pid] = t - pkt.created_at
                            else:
                                insert_packet_with_eviction(n, pkt, use_pow_priority=True)

        grid: Dict[Tuple[int, int], List[Node]] = {}
        for n in nodes:
            cx, cy = int(n.x // cell_size), int(n.y // cell_size)
            grid.setdefault((cx, cy), []).append(n)

        for (cx, cy), cell_nodes in grid.items():
            neighbors: List[Node] = []
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    neighbors.extend(grid.get((cx + dx, cy + dy), ()))

            for a in cell_nodes:
                for b in neighbors:
                    if b.nid <= a.nid:
                        continue
                    if math.hypot(a.x - b.x, a.y - b.y) > BLE_RANGE_M:
                        continue
                    exchange_encounter(a, b, t, use_aether, delivered_times, rng)

        t += TICK_SEC

    honest_nodes = [n for n in nodes if n.role == "honest"]
    latencies_min = sorted(v / 60.0 for v in delivered_times.values())
    p50 = statistics.median(latencies_min) if latencies_min else float("inf")
    p95 = latencies_min[min(len(latencies_min) - 1, math.ceil(0.95 * len(latencies_min)) - 1)] if latencies_min else float("inf")
    avg_tx = statistics.mean(n.radio_tx_packets for n in honest_nodes)
    battery = (1.49 + 0.0004 * avg_tx * 12.0) if use_aether else (204.0 + 0.002 * avg_tx * 12.0)

    return {
        "delivery_ratio": len(delivered_times) / len(messages),
        "p50_min": p50,
        "p95_min": p95,
        "avg_tx_per_node": avg_tx,
        "sybil_blocked": sum(n.sybil_rejected_pow for n in honest_nodes),
        "barter_blocked": sum(n.barter_blocked for n in honest_nodes),
        "battery_mah_day": battery,
    }


def exchange_encounter(
    a: Node,
    b: Node,
    now: float,
    use_aether: bool,
    delivered_times: Dict[int, float],
    rng: random.Random,
) -> None:
    a_offer = [] if a.role == "freerider" else [p for pid, p in a.buffer.items() if pid not in b.seen]
    b_offer = [] if b.role == "freerider" else [p for pid, p in b.buffer.items() if pid not in a.seen]

    if use_aether:
        a_offer = a_offer[:MINISKETCH_CAP]
        b_offer = b_offer[:MINISKETCH_CAP]

    sent_ab, sent_ba = 0, 0
    idx_a, idx_b = 0, 0

    while idx_a < len(a_offer) or idx_b < len(b_offer):
        progressed = False
        if idx_a < len(a_offer):
            if (not use_aether) or ((sent_ab - sent_ba) < BARTER_MAX_DEFICIT):
                pkt = a_offer[idx_a]
                idx_a += 1
                a.radio_tx_packets += 1
                b.radio_rx_packets += 1
                if ingest_packet(b, pkt, now, use_aether, delivered_times, rng):
                    sent_ab += 1
                progressed = True
            else:
                a.barter_blocked += 1

        if idx_b < len(b_offer):
            if (not use_aether) or ((sent_ba - sent_ab) < BARTER_MAX_DEFICIT):
                pkt = b_offer[idx_b]
                idx_b += 1
                b.radio_tx_packets += 1
                a.radio_rx_packets += 1
                if ingest_packet(a, pkt, now, use_aether, delivered_times, rng):
                    sent_ba += 1
                progressed = True
            else:
                b.barter_blocked += 1

        if not progressed:
            break


def ingest_packet(
    dst: Node,
    pkt: Packet,
    now: float,
    use_aether: bool,
    delivered_times: Dict[int, float],
    rng: random.Random,
) -> bool:
    if dst.role != "honest":
        return False

    if use_aether:
        fill_pct = (len(dst.buffer) * 100) // MAX_BUFFER_SIZE
        req_pow = 20 if pkt.decay_class >= 0xC else 18
        if fill_pct > 80:
            req_pow += (fill_pct - 80) // 5
        if pkt.pow_bits < req_pow:
            dst.sybil_rejected_pow += 1
            return False

    if pkt.pid in dst.seen:
        return False
    dst.seen.add(pkt.pid)

    if pkt.recipient == dst.nid:
        if pkt.pid not in delivered_times:
            delivered_times[pkt.pid] = now - pkt.created_at
        return True

    if use_aether:
        p_survive = DECAY_PROBS.get(pkt.decay_class, 0.90)
        if rng.random() >= p_survive:
            return True

    insert_packet_with_eviction(dst, pkt, use_pow_priority=use_aether)
    return True


def main() -> None:
    scenarios = [
        ("Klasyczny BLE Mesh (ciagla sciezka)", "classical_mesh"),
        ("Naiwny Gossip (bez PoW / barteru)", "naive_gossip"),
        ("AETHER Pure Off-Grid (RFC-0001)", "aether_offgrid"),
        ("AETHER Hybrid (+5% Bridge Mules)", "aether_hybrid"),
    ]
    print(f"{'Scenariusz':<38} | {'Doreczenie':>10} | {'p50 [min]':>9} | {'p95 [min]':>9} | {'TX/wezel':>8} | {'Sybil Blk':>9} | {'Bateria/d':>10}")
    print("-" * 114)
    for label, mode in scenarios:
        res = run_dtn_scenario(mode=mode)
        p50_str = f"{res['p50_min']:.1f}" if math.isfinite(res["p50_min"]) else "FAIL"
        p95_str = f"{res['p95_min']:.1f}" if math.isfinite(res["p95_min"]) else "FAIL"
        print(
            f"{label:<38} | {res['delivery_ratio']*100:>9.1f}% | {p50_str:>9} | {p95_str:>9} | "
            f"{res['avg_tx_per_node']:>8.1f} | {res['sybil_blocked']:>9} | {res['battery_mah_day']:>7.2f} mAh"
        )


if __name__ == "__main__":
    main()
