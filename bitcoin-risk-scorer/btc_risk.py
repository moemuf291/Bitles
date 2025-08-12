#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import sys
import time
from typing import Dict, List, Set, Tuple

import requests

# Optional color support for nicer terminal output
try:
    from colorama import init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    pass  # safe to ignore if colorama isn't installed

# ANSI colors (work even without colorama on most terminals)
ORANGE = "\033[38;5;208m"
CYAN = "\033[36m"
RESET = "\033[0m"

def print_banner():
    art = r"""
     ____  _ _   _ _             
    | __ )(_) |_(_) | ___  ___   
    |  _ \| | __| | |/ _ \/ __|  
    | |_) | | |_| | |  __/\__ \  
    |____/|_|\__|_|_|\___||___/  
        Bitcoin Address Risk
    """
    print(f"{ORANGE}{art}{RESET}")
    print(f"{CYAN}Heuristic AML scorer for Bitcoin addresses{RESET}\n")


BLOCKSTREAM_API = "https://blockstream.info/api"
SATOSHI_PER_BTC = 100_000_000


def sats_to_btc(sats: int) -> float:
    return round(sats / SATOSHI_PER_BTC, 8)


def fetch_json(session: requests.Session, url: str, retries: int = 3, timeout: int = 20) -> Dict:
    for attempt in range(retries):
        try:
            resp = session.get(url, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                raise ValueError("Address or resource not found")
            # Retry on 5xx or rate-limits
            if resp.status_code >= 500 or resp.status_code == 429:
                time.sleep(1.5 * (attempt + 1))
                continue
            resp.raise_for_status()
        except requests.RequestException as exc:
            if attempt == retries - 1:
                raise RuntimeError(f"Network/API error: {exc}") from exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("Failed to fetch after retries")


def fetch_address_stats(session: requests.Session, address: str) -> Dict:
    url = f"{BLOCKSTREAM_API}/address/{address}"
    return fetch_json(session, url)


def fetch_transactions(session: requests.Session, address: str, max_txs: int = 300) -> List[Dict]:
    # First page: 25 most recent
    txs: List[Dict] = []
    url = f"{BLOCKSTREAM_API}/address/{address}/txs"
    batch = fetch_json(session, url)
    if isinstance(batch, dict):
        # When address invalid, API can respond with object
        raise ValueError("Unexpected response when fetching transactions")
    txs.extend(batch)

    # Paginate older using /txs/chain/{last_seen_txid}
    while len(txs) < max_txs and len(batch) == 25:
        last_txid = batch[-1]["txid"]
        page_url = f"{BLOCKSTREAM_API}/address/{address}/txs/chain/{last_txid}"
        batch = fetch_json(session, page_url)
        if not isinstance(batch, list) or len(batch) == 0:
            break
        txs.extend(batch)
    return txs[:max_txs]


def compute_largest_flows_and_blacklist(
    address: str, txs: List[Dict], blacklist: Set[str]
) -> Tuple[int, int, int]:
    largest_received_sats = 0
    largest_sent_sats = 0
    blacklist_interactions = 0

    norm_blacklist = {normalize_address(a) for a in blacklist}
    my_addr_norm = normalize_address(address)

    for tx in txs:
        # Received in this tx: sum of outputs to our address
        received_in_tx = 0
        if "vout" in tx:
            for vout in tx["vout"]:
                out_addr = vout.get("scriptpubkey_address")
                if out_addr and normalize_address(out_addr) == my_addr_norm:
                    received_in_tx += int(vout.get("value", 0))

        # Sent in this tx: sum of inputs that spend our address's prevouts
        sent_in_tx = 0
        if "vin" in tx:
            for vin in tx["vin"]:
                prevout = vin.get("prevout") or {}
                in_addr = prevout.get("scriptpubkey_address")
                if in_addr and normalize_address(in_addr) == my_addr_norm:
                    sent_in_tx += int(prevout.get("value", 0))

        if received_in_tx > largest_received_sats:
            largest_received_sats = received_in_tx
        if sent_in_tx > largest_sent_sats:
            largest_sent_sats = sent_in_tx

        # Counterparty blacklist check: any other addr in tx is blacklisted?
        interacted = False
        # Outputs counterparties
        if "vout" in tx:
            for vout in tx["vout"]:
                out_addr = vout.get("scriptpubkey_address")
                if out_addr and normalize_address(out_addr) != my_addr_norm:
                    if normalize_address(out_addr) in norm_blacklist:
                        interacted = True
                        break
        # Inputs counterparties (senders)
        if not interacted and "vin" in tx:
            for vin in tx["vin"]:
                prevout = vin.get("prevout") or {}
                in_addr = prevout.get("scriptpubkey_address")
                if in_addr and normalize_address(in_addr) != my_addr_norm:
                    if normalize_address(in_addr) in norm_blacklist:
                        interacted = True
                        break
        if interacted:
            blacklist_interactions += 1

    return largest_received_sats, largest_sent_sats, blacklist_interactions


def normalize_address(addr: str) -> str:
    # Bech32 is case-insensitive; legacy is case-sensitive. For simplicity, lowercase bech32.
    if addr.lower().startswith(("bc1", "tb1")):
        return addr.lower()
    return addr


def classify_status(latest_block_time: int) -> str:
    if not latest_block_time:
        return "Unknown"
    # Timezone-aware fix to avoid deprecation warnings
    latest = dt.datetime.fromtimestamp(latest_block_time, tz=dt.timezone.utc)
    days = (dt.datetime.now(dt.timezone.utc) - latest).days
    return "Active (30d)" if days <= 30 else "Dormant"


def score_risk(
    address: str,
    stats: Dict,
    largest_received_sats: int,
    largest_sent_sats: int,
    blacklist_interactions: int,
    is_self_blacklisted: bool,
) -> Tuple[int, str, List[str]]:
    reasons: List[str] = []
    score = 0

    chain = stats.get("chain_stats", {})
    funded_sum = int(chain.get("funded_txo_sum", 0))
    spent_sum = int(chain.get("spent_txo_sum", 0))
    tx_count = int(chain.get("tx_count", 0))
    funded_count = int(chain.get("funded_txo_count", 0))
    spent_count = int(chain.get("spent_txo_count", 0))

    # Self blacklisted
    if is_self_blacklisted:
        return 100, "Critical", ["Address is in the blacklist"]

    # Blacklist interactions
    if blacklist_interactions > 0:
        score += min(80, 50 + 10 * min(3, blacklist_interactions - 1))
        reasons.append(f"Interacted with {blacklist_interactions} blacklisted address(es)")

    # Transaction volume
    if tx_count > 1000:
        score += 10
        reasons.append("Very high transaction count")
    elif tx_count > 100:
        score += 5
        reasons.append("High transaction count")

    # Flow imbalance
    if funded_sum > 0 and spent_sum == 0 and funded_count >= 5:
        score += 10
        reasons.append("Only incoming funds, no outgoing")
    elif spent_sum > 0 and funded_sum == 0:
        score += 8
        reasons.append("Only outgoing funds, no incoming")

    # Large sudden transfers (absolute)
    max_tx_sats = max(largest_received_sats, largest_sent_sats)
    max_tx_btc = sats_to_btc(max_tx_sats)
    if max_tx_btc >= 10:
        score += 25
        reasons.append("Very large single transfer (>= 10 BTC)")
    elif max_tx_btc >= 1:
        score += 10
        reasons.append("Large single transfer (>= 1 BTC)")
    elif max_tx_btc >= 0.2:
        score += 5
        reasons.append("Notable single transfer (>= 0.2 BTC)")

    # Cap 0..100
    score = max(0, min(100, score))

    # Levels
    if score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    elif score <= 80:
        level = "High"
    else:
        level = "Critical"

    if not reasons:
        reasons.append("No specific risk flags identified")
    return score, level, reasons


def format_report(
    address: str,
    stats: Dict,
    largest_received_sats: int,
    largest_sent_sats: int,
    latest_block_time: int,
    score: int,
    level: str,
    reasons: List[str],
) -> str:
    chain = stats.get("chain_stats", {})
    total_received_btc = sats_to_btc(int(chain.get("funded_txo_sum", 0)))
    tx_count = int(chain.get("tx_count", 0))
    largest_tx_btc = sats_to_btc(max(largest_received_sats, largest_sent_sats))
    status = classify_status(latest_block_time)

    lines = []
    lines.append("==== bitcoin address risk report ====")
    lines.append(f"address: {address}")
    lines.append(f"transactions: {tx_count}")
    lines.append(f"total received: {total_received_btc} BTC")
    lines.append(f"largest transaction: {largest_tx_btc} BTC")
    lines.append(f"bitcoin status: {status}")
    lines.append(f"risk score: {score}/100")
    lines.append(f"risk level: {level}")
    lines.append(f"reason: {', '.join(reasons)}")
    return "\n".join(lines)


def main() -> int:
    print_banner()

    parser = argparse.ArgumentParser(
        description="Bitcoin address risk scorer (no DB, blacklist via JSON)."
    )
    parser.add_argument("address", help="Bitcoin address to analyze")
    parser.add_argument(
        "--blacklist",
        default="blacklist.json",
        help="Path to blacklist JSON (array of addresses). Default: blacklist.json",
    )
    parser.add_argument(
        "--max-txs",
        type=int,
        default=300,
        help="Max transactions to scan for largest transfer and blacklist interaction (default: 300)",
    )
    args = parser.parse_args()

    # Load blacklist
    try:
        with open(args.blacklist, "r", encoding="utf-8") as f:
            bl = json.load(f)
            if not isinstance(bl, list):
                raise ValueError("blacklist.json must be a JSON array of addresses")
            blacklist_set = {normalize_address(str(a)) for a in bl}
    except FileNotFoundError:
        blacklist_set = set()
    except Exception as exc:
        print(f"Failed to load blacklist: {exc}", file=sys.stderr)
        return 2

    address = args.address.strip()
    is_self_blacklisted = normalize_address(address) in blacklist_set

    session = requests.Session()
    session.headers.update({"User-Agent": "btc-risk-scorer/1.0"})

    # Fetch address stats
    try:
        stats = fetch_address_stats(session, address)
    except ValueError:
        print("Address not found or invalid.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Failed to fetch address stats: {exc}", file=sys.stderr)
        return 1

    # Latest activity timestamp from recent txs if available
    latest_block_time = 0

    # Fetch transactions and compute largest flows + blacklist interactions
    try:
        txs = fetch_transactions(session, address, max_txs=args.max_txs)
        if txs:
            # Find most recent block_time among fetched txs
            times = []
            for tx in txs:
                status = tx.get("status") or {}
                if status.get("block_time"):
                    times.append(int(status["block_time"]))
            if times:
                latest_block_time = max(times)
        largest_received_sats, largest_sent_sats, bl_interactions = compute_largest_flows_and_blacklist(
            address, txs, blacklist_set
        )
    except Exception as exc:
        print(f"Failed to process transactions: {exc}", file=sys.stderr)
        return 1

    score, level, reasons = score_risk(
        address,
        stats,
        largest_received_sats,
        largest_sent_sats,
        bl_interactions,
        is_self_blacklisted,
    )

    report = format_report(
        address,
        stats,
        largest_received_sats,
        largest_sent_sats,
        latest_block_time,
        score,
        level,
        reasons,
    )
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())