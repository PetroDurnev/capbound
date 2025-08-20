#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
capbound — Capped Permit Generator & Allowance Auditor
Автор: вы

Функции:
  • scan        — аудит allowance по списку токенов (ERC-20)
  • permit      — офлайн генерация подписанного EIP-2612 permit с лимитом и дедлайном
  • revoke-tx   — сформировать raw-tx для approve(spender, 0)
  • revoke-all  — сгенерировать пакет raw-tx для всех найденных рисковых allowance

Требует переменные окружения (или .env):
  RPC_URL       — HTTPS RPC (например, Alchemy/Infura/ваш нод)
  PRIVATE_KEY   — для подписания permit и raw-транзакций (hex, без 0x)
Внимание: приватный ключ никуда не отправляется, используется локально.

Пример:
  python capbound.py scan --owner 0xYourAddress --tokens tokens.txt
  python capbound.py permit --owner 0xYou --token 0xERC20 --spender 0xDapp --cap 100.0 --decimals 6 --deadline-min 30
  python capbound.py revoke-tx --owner 0xYou --token 0xERC20 --spender 0xDapp --nonce 1 --gas 65000 --gas-price 12
  python capbound.py revoke-all --owner 0xYou --tokens tokens.txt --risk-threshold 10000
"""

import os
import json
import time
import math
import argparse
from decimal import Decimal

from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_structured_data
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

load_dotenv()
console = Console()

ERC20_ABI = [
    {"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
    {"constant":True,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],
     "name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],
     "name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"name":"","type":"bytes32"}],"type":"function"},
    {"constant":True,"inputs":[{"name":"owner","type":"address"}],"name":"nonces","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"type":"function"},
    # Некоторые токены используют permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
    {"constant":False,"inputs":[
        {"name":"owner","type":"address"},
        {"name":"spender","type":"address"},
        {"name":"value","type":"uint256"},
        {"name":"deadline","type":"uint256"},
        {"name":"v","type":"uint8"},
        {"name":"r","type":"bytes32"},
        {"name":"s","type":"bytes32"}],
     "name":"permit","outputs":[],"type":"function"},
]

def w3():
    rpc = os.getenv("RPC_URL")
    if not rpc:
        console.print("[red]RPC_URL не задан. Укажите RPC_URL в .env или окружении.[/red]")
        raise SystemExit(1)
    return Web3(Web3.HTTPProvider(rpc))

def load_tokens(token_file: str):
    """
    Формат tokens.txt:
      0xTokenAddress[,label]
    Пустые строки/комментарии (# ...) игнорируются.
    """
    tokens = []
    with open(token_file, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split(",")]
            addr = Web3.to_checksum_address(parts[0])
            label = parts[1] if len(parts) > 1 else ""
            tokens.append((addr, label))
    return tokens

def get_contract(web3, addr):
    return web3.eth.contract(address=Web3.to_checksum_address(addr), abi=ERC20_ABI)

def safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default

def human(v: int, decimals: int) -> str:
    q = Decimal(v) / (Decimal(10) ** decimals)
    # красивый обрез хвоста
    s = f"{q.normalize()}"
    return s

def get_token_meta(c):
    name = safe_call(lambda: c.functions.name().call(), "Unknown")
    symbol = safe_call(lambda: c.functions.symbol().call(), "???")
    decimals = safe_call(lambda: c.functions.decimals().call(), 18)
    return name, symbol, decimals

def supports_permit(c) -> bool:
    # Эвристика: наличие nonces(owner) и/или DOMAIN_SEPARATOR
    has_nonces = safe_call(lambda: c.functions.nonces("0x0000000000000000000000000000000000000000").call(), None) is not None
    has_domain = safe_call(lambda: c.functions.DOMAIN_SEPARATOR().call(), None) is not None
    return has_nonces or has_domain

def scan_allowances(args):
    web3 = w3()
    owner = Web3.to_checksum_address(args.owner)
    tokens = load_tokens(args.tokens)
    spenders = [Web3.to_checksum_address(s) for s in args.spender] if args.spender else None

    table = Table(title="capbound — аудит allowance", box=box.SIMPLE_HEAVY)
    table.add_column("Токен")
    table.add_column("Адрес токена")
    table.add_column("Spender")
    table.add_column("Allowance")
    table.add_column("Permit?")

    risky = []
    for token, label in tokens:
        c = get_contract(web3, token)
        name, symbol, decimals = get_token_meta(c)

        # Если spender не задан, покажем несколько популярных (эвристика): сам владелец и нулевой неинтересны
        check_spenders = spenders or []
        if not check_spenders:
            # Часто встречающиеся router/marketplaces (пользователь может дополнить):
            candidates = [
                # Примеры; замените на свои в tokens.txt + --spender
                "0x1111111254eeb25477b68fb85ed929f73a960582", # 1inch router v4
                "0xE592427A0AEce92De3Edee1F18E0157C05861564", # Uniswap V3 Router
                "0xDef1C0ded9bec7F1a1670819833240f027b25EfF", # 0x Exchange Proxy
            ]
            check_spenders = [Web3.to_checksum_address(x) for x in candidates]

        for sp in check_spenders:
            allowance = safe_call(lambda: c.functions.allowance(owner, sp).call(), 0)
            if allowance > 0:
                sup = "✅" if supports_permit(c) else "—"
                table.add_row(f"{symbol or '?'} ({label})",
                              token,
                              sp,
                              f"{human(allowance, decimals)}",
                              sup)
                # риск-эвристика: всё, что выше порога
                if Decimal(human(allowance, decimals)) >= Decimal(args.risk_threshold):
                    risky.append((token, symbol, decimals, sp, allowance))

    console.print(table)
    if risky:
        console.print(f"[yellow]Рискованные allowance (>{args.risk_threshold}): {len(risky)}[/yellow]")
    else:
        console.print("[green]Рисковых allowance не найдено по заданным spenders.[/green]")

def build_permit_struct(web3, token_addr, owner, spender, value, deadline):
    c = get_contract(web3, token_addr)
    name = safe_call(lambda: c.functions.name().call(), "Token")
    chain_id = web3.eth.chain_id
    nonce = safe_call(lambda: c.functions.nonces(owner).call(), None)
    if nonce is None:
        console.print("[red]Токен не поддерживает EIP-2612 (нет nonces).[/red]")
        raise SystemExit(1)
    version = safe_call(lambda: c.functions.version().call(), "1")

    domain = {
        "name": name,
        "version": str(version),
        "chainId": chain_id,
        "verifyingContract": Web3.to_checksum_address(token_addr),
    }
    message = {
        "owner": owner,
        "spender": spender,
        "value": int(value),
        "nonce": int(nonce),
        "deadline": int(deadline),
    }
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name":"name","type":"string"},
                {"name":"version","type":"string"},
                {"name":"chainId","type":"uint256"},
                {"name":"verifyingContract","type":"address"},
            ],
            "Permit": [
                {"name":"owner","type":"address"},
                {"name":"spender","type":"address"},
                {"name":"value","type":"uint256"},
                {"name":"nonce","type":"uint256"},
                {"name":"deadline","type":"uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": domain,
        "message": message,
    }
    return typed_data

def cmd_permit(args):
    web3 = w3()
    owner = Web3.to_checksum_address(args.owner)
    spender = Web3.to_checksum_address(args.spender)
    token = Web3.to_checksum_address(args.token)

    # Рассчитать значение и deadline
    decimals = args.decimals
    value = int(Decimal(str(args.cap)) * (Decimal(10) ** decimals))
    deadline = int(time.time() + args.deadline_min * 60)

    typed = build_permit_struct(web3, token, owner, spender, value, deadline)

    pk = os.getenv("PRIVATE_KEY")
    if not pk:
        console.print("[yellow]PRIVATE_KEY не задан. Сгенерирую JSON с typed data для подписи во внешнем кошельке.[/yellow]")
        out = {
            "typed_data": typed,
            "who_signs": owner,
            "note": "Подпишите EIP-712 (Permit) своим кошельком и отправьте permit(...) на контракт токена."
        }
        fname = args.out or "permit_unsigned.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        console.print(f"[green]Сохранено:[/green] {fname}")
        return

    acct = Account.from_key(bytes.fromhex(pk))
    if acct.address.lower() != owner.lower():
        console.print(f"[red]PRIVATE_KEY принадлежит {acct.address}, а owner указан {owner}. Исправьте.[/red]")
        raise SystemExit(1)

    signable = encode_structured_data(typed)
    signed = Account.sign_message(signable, private_key=bytes.fromhex(pk))
    out = {
        "typed_data": typed,
        "signature": {
            "v": signed.v,
            "r": "0x" + signed.r.hex(),
            "s": "0x" + signed.s.hex(),
        },
        "owner": owner,
        "token": token,
        "spender": spender,
        "cap_units": str(args.cap),
        "deadline_unix": typed["message"]["deadline"],
        "how_to_use": "Вызовите token.permit(owner, spender, value, deadline, v, r, s). Затем (опционально) совершайте swap/spend."
    }
    fname = args.out or "permit_signed.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Сохранено подписанное разрешение:[/green] {fname}")

def build_approve_zero_tx(args):
    web3 = w3()
    owner = Web3.to_checksum_address(args.owner)
    token = Web3.to_checksum_address(args.token)
    spender = Web3.to_checksum_address(args.spender)

    pk = os.getenv("PRIVATE_KEY")
    if not pk:
        console.print("[red]PRIVATE_KEY не задан для формирования raw-tx.[/red]")
        raise SystemExit(1)

    acct = Account.from_key(bytes.fromhex(pk))
    if acct.address.lower() != owner.lower():
        console.print(f"[red]PRIVATE_KEY принадлежит {acct.address}, а owner указан {owner}.[/red]")
        raise SystemExit(1)

    c = get_contract(web3, token)
    tx = c.functions.approve(spender, 0).build_transaction({
        "from": owner,
        "nonce": web3.eth.get_transaction_count(owner),
        "gas": args.gas,
        "gasPrice": web3.to_wei(args.gas_price, "gwei"),
        # "chainId": web3.eth.chain_id  # web3 подставит сам, но можно явно
    })
    signed = Account.sign_transaction(tx, private_key=bytes.fromhex(pk))
    raw = "0x" + signed.rawTransaction.hex()
    return raw

def cmd_revoke_tx(args):
    raw = build_approve_zero_tx(args)
    fname = args.out or "revoke_rawtx.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(raw)
    console.print(f"[green]Raw-транзакция на отзыв allowance сохранена:[/green] {fname}")
    console.print("Подайте её через любой broadcaster/кошелёк, поддерживающий raw tx.")

def cmd_revoke_all(args):
    # Эвристический пакет для популярных spenders из scan() — пользователь может указать свой список через --spender
    args_scan = argparse.Namespace(owner=args.owner, tokens=args.tokens, spender=args.spender,
                                   risk_threshold=args.risk_threshold)
    web3 = w3()
    owner = Web3.to_checksum_address(args.owner)
    tokens = load_tokens(args.tokens)
    spenders = [Web3.to_checksum_address(s) for s in args.spender] if args.spender else []
    if not spenders:
        spenders = [
            "0x1111111254eeb25477b68fb85ed929f73a960582",
            "0xE592427A0AEce92De3Edee1F18E0157C05861564",
            "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",
        ]
        spenders = [Web3.to_checksum_address(x) for x in spenders]

    pk = os.getenv("PRIVATE_KEY")
    if not pk:
        console.print("[red]PRIVATE_KEY не задан.[/red]")
        raise SystemExit(1)

    batch = []
    for token, _ in tokens:
        c = get_contract(web3, token)
        decimals = safe_call(lambda: c.functions.decimals().call(), 18)
        for sp in spenders:
            allowance = safe_call(lambda: c.functions.allowance(owner, sp).call(), 0)
            if allowance == 0:
                continue
            value_h = Decimal(allowance) / (Decimal(10) ** decimals)
            if value_h < Decimal(args.risk_threshold):
                continue
            # строим raw-tx
            args_tmp = argparse.Namespace(owner=owner, token=token, spender=sp, gas=args.gas, gas_price=args.gas_price, out=None)
            raw = build_approve_zero_tx(args_tmp)
            batch.append({"token": token, "spender": sp, "raw": raw, "human_value": str(value_h)})

    if not batch:
        console.print("[green]Ничего не собрано для отзыва по заданным порогам и spenders.[/green]")
        return
    fname = args.out or "revoke_batch.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(batch, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Сохранён пакет raw-транзакций:[/green] {fname}")

def main():
    parser = argparse.ArgumentParser(description="capbound — ограниченные permit'ы и аудит allowance (ERC-20/EIP-2612)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Аудит allowance")
    p_scan.add_argument("--owner", required=True, help="Адрес владельца")
    p_scan.add_argument("--tokens", required=True, help="Файл со списком токенов")
    p_scan.add_argument("--spender", action="append", help="Адрес spender (можно несколько флагов)")
    p_scan.add_argument("--risk-threshold", type=Decimal, default=Decimal("1000"), help="Порог (человеческих единиц)")
    p_scan.set_defaults(func=scan_allowances)

    p_perm = sub.add_parser("permit", help="Сгенерировать EIP-2612 permit офлайн")
    p_perm.add_argument("--owner", required=True, help="Адрес подписанта")
    p_perm.add_argument("--token", required=True, help="Токен (ERC-20 с EIP-2612)")
    p_perm.add_argument("--spender", required=True, help="Кому разрешаем")
    p_perm.add_argument("--cap", type=Decimal, required=True, help="Лимит в человеко-единицах (например, 100.5)")
    p_perm.add_argument("--decimals", type=int, default=18, help="Десятичность токена (если name/decimals недоступны)")
    p_perm.add_argument("--deadline-min", type=int, default=15, help="Срок действия разрешения, минут")
    p_perm.add_argument("--out", help="Имя файла для сохранения JSON")
    p_perm.set_defaults(func=cmd_permit)

    p_rev = sub.add_parser("revoke-tx", help="Сформировать raw approve(0) для одного токена/spender")
    p_rev.add_argument("--owner", required=True, help="Ваш адрес")
    p_rev.add_argument("--token", required=True, help="Адрес токена")
    p_rev.add_argument("--spender", required=True, help="Адрес spender")
    p_rev.add_argument("--gas", type=int, default=65000, help="Лимит газа")
    p_rev.add_argument("--gas-price", type=int, default=10, help="Gas price в gwei")
    p_rev.add_argument("--out", help="Файл для сохранения raw-tx (txt)")
    p_rev.set_defaults(func=cmd_revoke_tx)

    p_batch = sub.add_parser("revoke-all", help="Пакет raw approve(0) по всем рисковым allowance")
    p_batch.add_argument("--owner", required=True, help="Ваш адрес")
    p_batch.add_argument("--tokens", required=True, help="Файл токенов")
    p_batch.add_argument("--spender", action="append", help="Ограничить списком spender (можно несколько)")
    p_batch.add_argument("--risk-threshold", type=Decimal, default=Decimal("1000"), help="Порог (человеческих единиц)")
    p_batch.add_argument("--gas", type=int, default=65000)
    p_batch.add_argument("--gas-price", type=int, default=10)
    p_batch.add_argument("--out", help="Файл JSON с пакетными raw-tx")
    p_batch.set_defaults(func=cmd_revoke_all)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
