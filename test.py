import itertools
import asyncio
from mnemonic import Mnemonic
from bip32 import BIP32
import hashlib
import ecdsa
from bit.network import NetworkAPI
import bech32  # Add this line to import the bech32 library

# Define the word list
word_list = [
    "elite", "usual", "surround", "kiwi", "angry", "aerobic", "force", "public", "awake",
    "divide", "yellow", "foot", "remove", "cycle", "obvious", "seven", "business", "sister", "fortune", "coach", "oppose", "forest",
    "dish", "detail"
]

# Initialize Mnemonic and BIP32
mnemo = Mnemonic("english")

# Function to derive the first Bitcoin native SegWit address from a seed phrase
def derive_address(seed_phrase):
    seed = mnemo.to_seed(seed_phrase)
    root_key = BIP32.from_seed(seed)
    child_key = root_key.get_privkey_from_path("m/84'/0'/0'/0/0")

    sk = ecdsa.SigningKey.from_string(child_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Compressed public key
    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

    # Calculate the address
    sha256_1 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_public_key = ripemd160.digest()

    # Create the SegWit address
    witness_version = 0
    witness_program = hashlib.new('sha256', public_key).digest()
    address = bech32.encode('bc', witness_version, witness_program)

    return address

# Function to check the balance of a Bitcoin address asynchronously
async def check_balance_async(address):
    try:
        balance = await asyncio.to_thread(NetworkAPI.get_balance, address)
        return balance
    except Exception as e:
        print(f"Error checking balance for {address}: {e}")
        return None

# Function to read all tried combinations from log file
def read_tried_combinations():
    tried_combinations = set()
    try:
        with open("tried_combinations.log", "r") as f:
            for line in f:
                tried_combinations.add(tuple(line.strip().split()))
    except FileNotFoundError:
        pass  # Handle if the file doesn't exist
    return tried_combinations

# Function to log tried combinations to a file
def log_tried_combinations(combination):
    with open("tried_combinations.log", "a") as f:
        f.write(" ".join(combination) + "\n")

# Generate all combinations of 24 words
async def main():
    tried_combinations = read_tried_combinations()

    for combination in itertools.combinations(word_list, 24):

        combination_list = list(combination)

        if tuple(combination_list) in tried_combinations:
            continue  # Skip already tried combinations

        seed_phrase = " ".join(combination_list)
        print(f"Checking seed phrase: {seed_phrase}")

        # Derive Bitcoin address
        address = derive_address(seed_phrase)

        # Check balance asynchronously
        balance = await check_balance_async(address)
        if balance is not None:
            print(f"Address: {address}, Balance: {balance} satoshis")

        # Log tried combination
        log_tried_combinations(combination_list)

        # If balance is found, save the seed phrase and stop
        if balance and balance > 0:
            print(f"Bitcoin found! Seed phrase: {seed_phrase}")
            with open("found_seed_phrase.txt", "w") as f:
                f.write(seed_phrase)
            break

if __name__ == "__main__":
    asyncio.run(main())
