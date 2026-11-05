from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

from ...core.contract import PollContext
from ...core.models import EventCandidate


IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
CHAINS = {
    "etherscan.io": (1, "Ethereum", "ETH_RPC_URL"),
    "arbiscan.io": (42161, "Arbitrum", "ARBITRUM_RPC_URL"),
    "optimistic.etherscan.io": (10, "Optimism", "OPTIMISM_RPC_URL"),
    "basescan.org": (8453, "Base", "BASE_RPC_URL"),
    "polygonscan.com": (137, "Polygon", "POLYGON_RPC_URL"),
    "bscscan.com": (56, "BNB Chain", "BSC_RPC_URL"),
    "snowtrace.io": (43114, "Avalanche", "AVALANCHE_RPC_URL"),
    "gnosisscan.io": (100, "Gnosis", "GNOSIS_RPC_URL"),
}


class OnchainConfigError(ValueError):
    pass


def discover_assets(payload):
    """Extract scoped addresses with an explicit chain, without RPC requests."""
    found = {}
    for raw in payload.get("scope") or []:
        if isinstance(raw, dict):
            row = raw
        else:
            link = re.search(r'https?://[^\s<>"\']+', str(raw))
            row = {"url": link.group(0) if link else str(raw)}
        category = str(row.get("category") or row.get("type") or "").lower().replace("-", "_")
        if category and category not in {"smart_contract", "blockchain_dlt", "contract"}:
            continue
        parsed = urlparse(str(row.get("url") or ""))
        if parsed.username or parsed.password or (parsed.scheme and parsed.scheme not in ('http', 'https')):
            continue
        host = (parsed.hostname or "").removeprefix("www.").lower()
        known = CHAINS.get(host)
        match = re.search(r"^/(?:address|token)/(0x[0-9a-fA-F]{40})(?:/|$)", parsed.path)
        explicit = row.get("chain_id")
        if known:
            chain_id, chain, rpc_env = known
            if explicit is not None and str(explicit) != str(chain_id):
                continue
            address = match.group(1) if match else row.get("address")
        elif explicit is not None and not isinstance(explicit, bool):
            try:
                chain_id = int(explicit)
            except (ValueError, TypeError):
                continue
            if chain_id < 1:
                continue
            chain_id, chain, rpc_env = next((value for value in CHAINS.values() if value[0] == chain_id),
                                           (chain_id, f"Chain {chain_id}", f"EVM_{chain_id}_RPC_URL"))
            address = row.get("address")
        else:
            continue
        if not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            continue
        address = address.lower()
        if address == "0x" + "0" * 40 or (row.get("address") and str(row['address']).lower() != address):
            continue
        found[(chain_id, address)] = {"chain_id": chain_id, "chain": chain, "proxy": address,
            "rpc_env": rpc_env, "label": row.get("label") or row.get("description") or address,
            "url": parsed.geturl() if parsed.scheme in ("http", "https") else None}
    return [found[key] for key in sorted(found)]


def inspect_asset(client, asset, sessions):
    """Inspect one scoped candidate at a fixed block; called only by a manual job."""
    chain_id = int(asset['chain_id'])
    rpc_env = asset['rpc_env']
    rpc_url = os.getenv(rpc_env)
    if not rpc_url:
        raise OnchainConfigError(f"Configure {rpc_env} and restart the app.")
    session_key = (chain_id, rpc_env)
    if session_key not in sessions:
        actual_chain = int(_rpc(client, rpc_url, 'eth_chainId', []), 16)
        if actual_chain != chain_id:
            raise OnchainConfigError(f"{rpc_env} connects to chain {actual_chain}, expected {chain_id}.")
        sessions[session_key] = (rpc_url, _rpc(client, rpc_url, 'eth_blockNumber', []))
    rpc_url, block = sessions[session_key]
    address = _address(asset['proxy'])
    code = _rpc(client, rpc_url, 'eth_getCode', [address, block])
    if code in ('0x', '0x0', None):
        return {"status": "no_contract", "block": int(block, 16)}
    implementation = _storage_address(_rpc(client, rpc_url, 'eth_getStorageAt', [address, IMPLEMENTATION_SLOT, block]))
    return {"status": "implementation" if int(implementation, 16) else "unsupported",
            "implementation": implementation if int(implementation, 16) else None, "block": int(block, 16)}


def derive_targets(config: Any) -> list[tuple[str, Any]]:
    """One target per proxy deployment; the key identifies it across programs so
    a proxy shared by several programs is checked once."""
    targets: list[tuple[str, Any]] = []
    for target in config or []:
        chain_id = int(target["chain_id"])
        proxy = _address(str(target["proxy"]))
        targets.append((f"{chain_id}:proxy:{proxy}", dict(target)))
    return targets


def poll(context: PollContext) -> list[EventCandidate]:
    target_config = (context.target or {}).get("config")
    configs = [target_config] if target_config is not None else list(context.config or [])
    programs = tuple(context.programs) or (context.protocol,)
    store = context.store
    client = context.client
    events: list[EventCandidate] = []
    for target in configs:
        chain_id = int(target["chain_id"])
        proxy = _address(str(target["proxy"]))
        rpc_env = str(target["rpc_env"])
        rpc_url = os.getenv(rpc_env)
        if not rpc_url:
            raise ValueError(f"Missing RPC URL environment variable: {rpc_env}")
        source_key = f"{context.source_type}:{chain_id}:proxy:{proxy}"
        previous = store.get_state(source_key)
        raw = _rpc(client, rpc_url, "eth_getStorageAt", [proxy, IMPLEMENTATION_SLOT, "latest"])
        implementation = _storage_address(raw)
        block = _rpc(client, rpc_url, "eth_blockNumber", [])
        snapshot = {
            "chain_id": chain_id,
            "proxy": proxy,
            "implementation": implementation,
            "block": int(block, 16),
            "label": target.get("label", proxy),
        }
        if previous and previous.payload.get("implementation") != implementation:
            for program in programs:
                events.append(
                    EventCandidate(
                        protocol_id=program["id"],
                        source_key=source_key,
                        kind="PROXY_IMPLEMENTATION_CHANGED",
                        entity=proxy,
                        before=previous.payload.get("implementation"),
                        after=implementation,
                        metadata={
                            "chain_id": chain_id,
                            "block": snapshot["block"],
                            "label": snapshot["label"],
                            "changed_files": [],
                            "platform": program.get("platform"),
                        },
                    )
                )
        store.save_state(
            source_key=source_key,
            protocol_id=str(programs[0]["id"]),
            source_type=context.source_type,
            payload=snapshot,
            cursor=str(snapshot["block"]),
            events=events,
        )
    return events


def _rpc(client: Any, url: str, method: str, params: list[Any]) -> Any:
    response = client.post_json(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "error" in response.payload:
        raise RuntimeError(f"RPC {method} failed: {response.payload['error']}")
    return response.payload["result"]


def _address(value: str) -> str:
    value = value.lower()
    if not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"Invalid EVM address: {value}")
    int(value[2:], 16)
    return value


def _storage_address(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise ValueError(f"Unexpected storage value: {value!r}")
    return _address("0x" + value[-40:])
