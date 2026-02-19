import hashlib
import time
import csv
import PySimpleGUI as sg
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from collections import defaultdict


# Helper functions for hashing
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

class MerkleNode:
    def init(self, left=None, right=None, hash_value=None):
        self.left = left
        self.right = right
        self.hash = hash_value or hash_data(left.hash + right.hash)


class MerkleTree:
    def init(self, transactions):
        self.leaves = [MerkleNode(hash_value=hash_data(tx)) for tx in transactions]
        self.root = self.build_merkle_tree(self.leaves)

    def build_merkle_tree(self, nodes):
        if len(nodes) == 1:
            return nodes[0]
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else left
            parent = MerkleNode(left, right)
            new_level.append(parent)
        return self.build_merkle_tree(new_level)

    def get_merkle_root(self):
        return self.root.hash if self.root else None

# Blockchain Block Class
class Block:
    def _init_(self, index, previous_hash, transactions, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.transactions = transactions
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = str(self.index) + self.previous_hash + str(self.timestamp) + str(self.transactions)
        return hashlib.sha256(block_string.encode()).hexdigest()


# Blockchain Ledger Class
class Blockchain:
    def _init_(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.accounts = defaultdict(float)
        self.transaction_history = defaultdict(list)

    def create_genesis_block(self):
        return Block(0, "0", ["Genesis Block"])

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        if self.validate_block(block):
            self.chain.append(block)
        else:
            sg.popup("Invalid block. It was not added to the blockchain.")

    def validate_block(self, block):
        return block.previous_hash == self.get_latest_block().hash

    def add_transaction(self, sender, receiver, amount, signature, public_key):
        if not self.verify_signature(sender, signature, public_key, f"{sender}->{receiver}:{amount}"):
            sg.popup("Invalid transaction signature!")
            return
        if self.accounts[sender] < amount:
            sg.popup(f"Transaction failed: {sender} has insufficient balance.")
            return
        self.accounts[sender] -= amount
        self.accounts[receiver] += amount
        transaction_details = f"{sender}->{receiver}:{amount}"
        self.pending_transactions.append(transaction_details)
        self.transaction_history[sender].append(f"Sent {amount} to {receiver}")
        self.transaction_history[receiver].append(f"Received {amount} from {sender}")

    def withdraw(self, account, amount):
        if self.accounts[account] >= amount:
            self.accounts[account] -= amount
            self.transaction_history[account].append(f"Withdrew {amount}")
            sg.popup(f"Withdrawal successful: {amount} deducted from {account}")
        else:
            sg.popup("Insufficient funds for withdrawal.")

    def view_transaction_history(self, account):
        history = self.transaction_history.get(account, [])
        if not history:
            sg.popup("No transactions found.")
        else:
            sg.popup_scrolled("Transaction History", "\n".join(history))

    def mine_block(self, miner_address):
        self.add_transaction("Network", miner_address, 1, "", "")
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        self.add_block(new_block)
        self.pending_transactions = []
        sg.popup(f"Block {new_block.index} mined successfully.")

    def verify_signature(self, sender, signature, public_key, message):
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
            return vk.verify(bytes.fromhex(signature), message.encode())
        except:
            return False

    def export_ledger(self, filename="ledger.csv"):
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Block Index", "Previous Hash", "Timestamp", "Transactions", "Hash"])
            for block in self.chain:
                writer.writerow([block.index, block.previous_hash, block.timestamp, block.transactions, block.hash])
        sg.popup(f"Ledger exported successfully to {filename}.")


# Function to create a new digital signature
def create_signature(private_key, message):
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    signature = sk.sign(message.encode())
    return signature.hex()


# Creating and managing account keys
def create_account():
    private_key = SigningKey.generate(curve=SECP256k1).to_string().hex()
    public_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1).verifying_key.to_string().hex()
    return private_key, public_key


# Initialize the Blockchain
blockchain = Blockchain()
accounts = {}

# GUI Layout
layout = [
    [sg.Text("Blockchain Ledger", font=("Helvetica", 16))],
    [sg.Button("Create Account"), sg.Button("View Balance")],
    [sg.Button("Deposit Funds"), sg.Button("Withdraw Funds")],
    [sg.Button("Create Transaction"), sg.Button("View Transaction History")],
    [sg.Button("Mine Block"), sg.Button("View Blockchain")],
    [sg.Button("Export Ledger")],
    [sg.Output(size=(80, 20))]
]

# Create the window
window = sg.Window("Blockchain Ledger", layout)

# Event loop
while True:
    event, values = window.read()

    if event == sg.WINDOW_CLOSED:
        break

    if event == "Create Account":
        name = sg.popup_get_text("Enter account name:")
        if name:
            private_key, public_key = create_account()
            accounts[name] = (private_key, public_key)
            blockchain.accounts[public_key] = 0
            sg.popup("Account Created", f"Public Key: {public_key}")

    elif event == "View Balance":
        name = sg.popup_get_text("Enter account name:")
        if name in accounts:
            public_key = accounts[name][1]
            balance = blockchain.accounts[public_key]
            sg.popup("Balance", f"Balance of {name}: {balance}")
        else:
            sg.popup("Account not found!")

    elif event == "Deposit Funds":
        name = sg.popup_get_text("Enter account name:")
        amount = sg.popup_get_text("Enter deposit amount:")
        if amount and name in accounts:
            amount = float(amount)
            public_key = accounts[name][1]
            blockchain.accounts[public_key] += amount
            blockchain.transaction_history[public_key].append(f"Deposited {amount}")
            sg.popup(f"{amount} deposited to {name}'s account.")
        else:
            sg.popup("Account not found or invalid amount!")

    elif event == "Withdraw Funds":
        name = sg.popup_get_text("Enter account name:")
        amount = sg.popup_get_text("Enter withdrawal amount:")
        if amount and name in accounts:
            amount = float(amount)
            public_key = accounts[name][1]
            blockchain.withdraw(public_key, amount)
            sg.popup(f"{amount}has been withdrawn.")

        else:
            sg.popup("Account not found or invalid amount!")

    elif event == "Create Transaction":
        sender_name = sg.popup_get_text("Enter sender account name:")
        receiver_name = sg.popup_get_text("Enter receiver account name:")
        amount = sg.popup_get_text("Enter amount:")

        if amount and sender_name in accounts and receiver_name in accounts:
            amount = float(amount)
            sender_private, sender_public = accounts[sender_name]
            receiver_public = accounts[receiver_name][1]
            message = f"{sender_public}->{receiver_public}:{amount}"
            signature = create_signature(sender_private, message)
            blockchain.add_transaction(sender_public, receiver_public, amount, signature, sender_public)
            sg.popup(f" transaction sucessful \n {amount} sent to {receiver_public} ")

        else:
            sg.popup("One or both accounts not found!")

    elif event == "View Transaction History":
        name = sg.popup_get_text("Enter account name:")
        if name in accounts:
            public_key = accounts[name][1]
            blockchain.view_transaction_history(public_key)
        else:
            sg.popup("Account not found!")

    elif event == "Mine Block":
        miner_name = sg.popup_get_text("Enter miner account name:")
        if miner_name in accounts:
            miner_public = accounts[miner_name][1]
            blockchain.mine_block(miner_public)
        else:
            sg.popup("Account not found!")

    elif event == "View Blockchain":
        blockchain_data = "\n".join([f"Block {block.index}, Hash: {block.hash}" for block in blockchain.chain])
        sg.popup_scrolled("Blockchain", blockchain_data)

    elif event == "Export Ledger":
        filename = sg.popup_get_file("Save Ledger as CSV", save_as=True, file_types=(("CSV Files", "*.csv"),))
        if filename:
            blockchain.export_ledger(filename)

# Close the window
window.close()