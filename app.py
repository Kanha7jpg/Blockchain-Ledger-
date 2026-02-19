import hashlib
import json
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

import PySimpleGUI as sg


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def simple_private_key() -> str:
    return hashlib.sha256(f"{random.random()}:{time.time_ns()}".encode("utf-8")).hexdigest()


def derive_public_key(private_key: str) -> str:
    return sha256_hex(f"pub:{private_key}")


def sign_message(private_key: str, message: str) -> str:
    # Demonstration signature model:
    # signature = H(public_key || message), so it can be verified with public key only.
    public_key = derive_public_key(private_key)
    return sha256_hex(f"{public_key}:{message}")


def verify_signature(public_key: str, message: str, signature: str) -> bool:
    return sha256_hex(f"{public_key}:{message}") == signature


@dataclass
class Wallet:
    name: str
    private_key: str
    public_key: str


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: float
    timestamp: str
    signature: str

    def payload(self) -> str:
        return f"{self.sender}|{self.recipient}|{self.amount:.8f}|{self.timestamp}"

    def txid(self) -> str:
        return sha256_hex(self.to_json())

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "txid": self.txid(),
        }

    def to_json(self) -> str:
        return json.dumps(
            {
                "sender": self.sender,
                "recipient": self.recipient,
                "amount": self.amount,
                "timestamp": self.timestamp,
                "signature": self.signature,
            },
            sort_keys=True,
        )


class MerkleTree:
    @staticmethod
    def root(transactions: List[Transaction]) -> str:
        if not transactions:
            return sha256_hex("EMPTY")
        level = [tx.txid() for tx in transactions]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            next_level = []
            for i in range(0, len(level), 2):
                next_level.append(sha256_hex(level[i] + level[i + 1]))
            level = next_level
        return level[0]


@dataclass
class Block:
    index: int
    previous_hash: str
    timestamp: str
    nonce: int
    difficulty: int
    transactions: List[Transaction]
    merkle_root: str
    miner: str

    def header(self) -> str:
        return (
            f"{self.index}|{self.previous_hash}|{self.timestamp}|"
            f"{self.nonce}|{self.difficulty}|{self.merkle_root}|{self.miner}"
        )

    def block_hash(self) -> str:
        return sha256_hex(self.header())

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "merkle_root": self.merkle_root,
            "miner": self.miner,
            "hash": self.block_hash(),
        }


class Blockchain:
    def __init__(self, difficulty: int = 4, mining_reward: float = 10.0):
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.wallets: List[Wallet] = []
        self._wallet_lookup = {}
        self._create_demo_wallets()
        self._create_genesis_block()

    def _create_demo_wallets(self) -> None:
        for name in ("Alice", "Bob", "Charlie", "Miner"):
            priv = simple_private_key()
            pub = derive_public_key(priv)
            wallet = Wallet(name=name, private_key=priv, public_key=pub)
            self.wallets.append(wallet)
            self._wallet_lookup[wallet.public_key] = wallet

    def _create_genesis_block(self) -> None:
        genesis = Block(
            index=0,
            previous_hash="0" * 64,
            timestamp=datetime.utcnow().isoformat(),
            nonce=0,
            difficulty=self.difficulty,
            transactions=[],
            merkle_root=MerkleTree.root([]),
            miner="GENESIS",
        )
        self.chain.append(genesis)

    def wallet_by_name(self, name: str) -> Optional[Wallet]:
        for wallet in self.wallets:
            if wallet.name == name:
                return wallet
        return None

    def balance_of(self, public_key: str) -> float:
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient == public_key:
                    balance += tx.amount
                if tx.sender == public_key:
                    balance -= tx.amount
        return balance

    def create_signed_transaction(self, sender_name: str, recipient_name: str, amount: float) -> Tuple[bool, str]:
        sender = self.wallet_by_name(sender_name)
        recipient = self.wallet_by_name(recipient_name)
        if sender is None or recipient is None:
            return False, "Unknown sender/recipient."
        if sender.public_key == recipient.public_key:
            return False, "Sender and recipient must be different."
        if amount <= 0:
            return False, "Amount must be > 0."
        # Allow demo wallets to go negative only for genesis-like onboarding.
        # If a sender already has funds, enforce spending limit.
        current_balance = self.balance_of(sender.public_key)
        if current_balance > 0 and amount > current_balance:
            return False, f"Insufficient funds. Balance: {current_balance:.4f}"
        timestamp = datetime.utcnow().isoformat()
        unsigned_payload = f"{sender.public_key}|{recipient.public_key}|{amount:.8f}|{timestamp}"
        signature = sign_message(sender.private_key, unsigned_payload)
        tx = Transaction(
            sender=sender.public_key,
            recipient=recipient.public_key,
            amount=amount,
            timestamp=timestamp,
            signature=signature,
        )
        if not self.verify_transaction(tx):
            return False, "Signature verification failed."
        self.pending_transactions.append(tx)
        return True, f"Transaction queued. txid={tx.txid()[:12]}..."

    def verify_transaction(self, tx: Transaction) -> bool:
        payload = tx.payload()
        return verify_signature(tx.sender, payload, tx.signature)

    def _mine_block(self, miner_name: str, progress_callback) -> Tuple[Optional[Block], int, float]:
        miner = self.wallet_by_name(miner_name)
        if miner is None:
            return None, 0, 0.0
        reward_payload = f"NETWORK|{miner.public_key}|{self.mining_reward:.8f}|{datetime.utcnow().isoformat()}"
        reward_sig = sha256_hex(f"reward:{reward_payload}")
        reward_tx = Transaction(
            sender="NETWORK",
            recipient=miner.public_key,
            amount=self.mining_reward,
            timestamp=datetime.utcnow().isoformat(),
            signature=reward_sig,
        )
        txs = self.pending_transactions[:] + [reward_tx]
        valid_txs = [tx for tx in txs if tx.sender == "NETWORK" or self.verify_transaction(tx)]
        merkle_root = MerkleTree.root(valid_txs)
        candidate = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].block_hash(),
            timestamp=datetime.utcnow().isoformat(),
            nonce=0,
            difficulty=self.difficulty,
            transactions=valid_txs,
            merkle_root=merkle_root,
            miner=miner.public_key,
        )
        prefix = "0" * self.difficulty
        attempts = 0
        start = time.time()
        while not candidate.block_hash().startswith(prefix):
            candidate.nonce += 1
            attempts += 1
            if attempts % 3000 == 0:
                elapsed = max(time.time() - start, 0.001)
                hps = attempts / elapsed
                progress_callback(candidate.nonce, attempts, hps, candidate.block_hash()[:16])
        elapsed = max(time.time() - start, 0.001)
        hps = attempts / elapsed
        self.chain.append(candidate)
        self.pending_transactions.clear()
        return candidate, attempts, hps

    def validate_chain(self) -> Tuple[bool, str]:
        if not self.chain:
            return False, "Chain empty."
        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            block = self.chain[i]
            if block.previous_hash != prev.block_hash():
                return False, f"Block {i}: previous hash mismatch."
            if block.merkle_root != MerkleTree.root(block.transactions):
                return False, f"Block {i}: invalid Merkle root."
            if not block.block_hash().startswith("0" * block.difficulty):
                return False, f"Block {i}: PoW invalid."
            for tx in block.transactions:
                if tx.sender != "NETWORK" and not self.verify_transaction(tx):
                    return False, f"Block {i}: invalid transaction signature."
        return True, "Chain valid."

    def short_address(self, public_key: str) -> str:
        for w in self.wallets:
            if w.public_key == public_key:
                return f"{w.name} ({public_key[:10]}...)"
        if public_key == "NETWORK":
            return "NETWORK"
        return public_key[:12] + "..."


def build_block_list_rows(chain: List[Block]) -> List[List[str]]:
    rows = []
    for block in reversed(chain):
        rows.append(
            [
                str(block.index),
                block.block_hash()[:16],
                block.previous_hash[:16],
                str(len(block.transactions)),
                str(block.nonce),
            ]
        )
    return rows


def build_pending_rows(ledger: Blockchain) -> List[List[str]]:
    rows = []
    for tx in ledger.pending_transactions:
        rows.append(
            [
                tx.txid()[:16],
                ledger.short_address(tx.sender),
                ledger.short_address(tx.recipient),
                f"{tx.amount:.4f}",
            ]
        )
    return rows


def build_balances_text(ledger: Blockchain) -> str:
    lines = []
    for wallet in ledger.wallets:
        lines.append(f"{wallet.name}: {ledger.balance_of(wallet.public_key):.4f}")
    return "\n".join(lines)


def block_details_text(ledger: Blockchain, block: Block) -> str:
    lines = [
        f"Index: {block.index}",
        f"Hash: {block.block_hash()}",
        f"Previous: {block.previous_hash}",
        f"Timestamp: {block.timestamp}",
        f"Nonce: {block.nonce}",
        f"Difficulty: {block.difficulty}",
        f"Merkle Root: {block.merkle_root}",
        f"Miner: {ledger.short_address(block.miner)}",
        "Transactions:",
    ]
    for tx in block.transactions:
        lines.append(
            f"  - {tx.txid()[:12]}... {ledger.short_address(tx.sender)} -> "
            f"{ledger.short_address(tx.recipient)} amount={tx.amount:.4f}"
        )
    return "\n".join(lines)


def run_gui():
    sg.theme("SystemDefault")
    ledger = Blockchain(difficulty=4, mining_reward=12.5)
    mining_lock = threading.Lock()

    wallet_names = [w.name for w in ledger.wallets]
    table_headings = ["Idx", "Hash", "Prev", "Txs", "Nonce"]

    layout = [
        [
            sg.Frame(
                "Create Transaction",
                [
                    [
                        sg.Text("Sender"),
                        sg.Combo(wallet_names, default_value="Alice", key="-SENDER-", readonly=True, size=(12, 1)),
                        sg.Text("Recipient"),
                        sg.Combo(wallet_names, default_value="Bob", key="-RECIPIENT-", readonly=True, size=(12, 1)),
                        sg.Text("Amount"),
                        sg.Input("1.0", key="-AMOUNT-", size=(8, 1)),
                        sg.Button("Sign & Queue", key="-QUEUE-"),
                    ]
                ],
                expand_x=True,
            )
        ],
        [
            sg.Frame(
                "Mining",
                [
                    [
                        sg.Text("Miner"),
                        sg.Combo(wallet_names, default_value="Miner", key="-MINER-", readonly=True, size=(12, 1)),
                        sg.Button("Mine Pending Transactions", key="-MINE-"),
                        sg.Text("Status: idle", key="-MINE-STATUS-", size=(62, 1)),
                    ],
                    [sg.ProgressBar(100, orientation="h", size=(60, 12), key="-PBAR-")],
                ],
                expand_x=True,
            )
        ],
        [
            sg.Column(
                [
                    [
                        sg.Text("Blocks"),
                        sg.Table(
                            values=build_block_list_rows(ledger.chain),
                            headings=table_headings,
                            auto_size_columns=False,
                            col_widths=[5, 18, 18, 6, 10],
                            justification="left",
                            key="-BLOCKS-",
                            num_rows=10,
                            enable_events=True,
                            expand_x=True,
                            expand_y=True,
                        ),
                    ]
                ],
                expand_x=True,
                expand_y=True,
            ),
            sg.Column(
                [
                    [
                        sg.Frame(
                            "Pending Transactions",
                            [
                                [
                                    sg.Table(
                                        values=build_pending_rows(ledger),
                                        headings=["txid", "from", "to", "amount"],
                                        auto_size_columns=False,
                                        col_widths=[18, 22, 22, 8],
                                        justification="left",
                                        key="-PENDING-",
                                        num_rows=6,
                                        expand_x=True,
                                    )
                                ]
                            ],
                            expand_x=True,
                        )
                    ],
                    [
                        sg.Frame(
                            "Wallet Balances",
                            [[sg.Multiline(build_balances_text(ledger), size=(62, 6), key="-BAL-", disabled=True)]],
                            expand_x=True,
                        )
                    ],
                    [
                        sg.Frame(
                            "Block Details",
                            [[sg.Multiline("", size=(62, 12), key="-DETAILS-", disabled=True)]],
                            expand_x=True,
                            expand_y=True,
                        )
                    ],
                ],
                expand_x=True,
                expand_y=True,
            ),
        ],
        [sg.Text("Ledger: genesis block initialized.", key="-STATUS-", size=(120, 1))],
    ]

    window = sg.Window(
        "Blockchain Ledger System (PySimpleGUI)",
        layout,
        resizable=True,
        finalize=True,
    )

    def refresh_views() -> None:
        window["-BLOCKS-"].update(values=build_block_list_rows(ledger.chain))
        window["-PENDING-"].update(values=build_pending_rows(ledger))
        window["-BAL-"].update(build_balances_text(ledger))

    def mine_worker(miner_name: str):
        def progress(nonce: int, attempts: int, hps: float, hash_prefix: str):
            pct = (nonce % 10000) / 100.0
            window.write_event_value(
                "-MINE-PROGRESS-",
                {"nonce": nonce, "attempts": attempts, "hps": hps, "hash_prefix": hash_prefix, "pct": pct},
            )

        try:
            block, attempts, hps = ledger._mine_block(miner_name, progress)
            window.write_event_value("-MINE-DONE-", {"block": block, "attempts": attempts, "hps": hps})
        finally:
            mining_lock.release()

    while True:
        event, values = window.read(timeout=100)
        if event in (sg.WIN_CLOSED, "Exit"):
            break

        if event == "-QUEUE-":
            try:
                amount = float(values["-AMOUNT-"])
            except ValueError:
                window["-STATUS-"].update("Invalid amount.")
                continue
            ok, message = ledger.create_signed_transaction(values["-SENDER-"], values["-RECIPIENT-"], amount)
            refresh_views()
            window["-STATUS-"].update(message)

        if event == "-MINE-":
            if mining_lock.locked():
                window["-STATUS-"].update("Mining already in progress.")
                continue
            if not ledger.pending_transactions:
                window["-STATUS-"].update("No pending transactions to mine.")
                continue
            mining_lock.acquire()
            miner = values["-MINER-"]
            window["-MINE-STATUS-"].update(f"Status: mining by {miner}...")
            window["-PBAR-"].update(1)
            thread = threading.Thread(target=mine_worker, args=(miner,), daemon=True)
            thread.start()

        if event == "-MINE-PROGRESS-":
            data = values[event]
            window["-PBAR-"].update(max(1, int(data["pct"])))
            window["-MINE-STATUS-"].update(
                f"Status: nonce={data['nonce']} attempts={data['attempts']} "
                f"h/s={data['hps']:.0f} hash={data['hash_prefix']}..."
            )

        if event == "-MINE-DONE-":
            data = values[event]
            block = data["block"]
            if block is None:
                window["-STATUS-"].update("Mining failed.")
            else:
                refresh_views()
                valid, reason = ledger.validate_chain()
                window["-STATUS-"].update(
                    f"Mined block #{block.index} | txs={len(block.transactions)} | "
                    f"attempts={data['attempts']} | {reason}"
                )
                window["-MINE-STATUS-"].update(f"Status: complete at {data['hps']:.0f} h/s")
                window["-PBAR-"].update(100)

        if event == "-BLOCKS-":
            selected = values["-BLOCKS-"]
            if selected:
                # Table is reversed for newest-first view.
                chain_index = len(ledger.chain) - 1 - selected[0]
                block = ledger.chain[chain_index]
                window["-DETAILS-"].update(block_details_text(ledger, block))

    window.close()


if __name__ == "__main__":
    run_gui()
