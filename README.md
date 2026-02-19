# Blockchain Ledger System

Interactive desktop blockchain demo with:
- SHA-256 hashing
- Transaction signing and signature verification
- Merkle root construction for block integrity
- Proof-of-work mining
- Live GUI updates for pending transactions, blocks, balances, and mining progress

## Requirements
- Python 3.9+
- `PySimpleGUI`

## Install
```powershell
python -m pip install PySimpleGUI
```

## Run
```powershell
python app.py
```

## What You Can Do In The GUI
- Create and queue signed transactions between demo wallets
- Mine pending transactions into a new block
- Watch real-time mining status (nonce, attempts, hash rate)
- Inspect blocks, hashes, Merkle roots, and transaction contents
- Validate chain integrity after mining
