import itertools
import asyncio
from mnemonic import Mnemonic
from bip32 import BIP32
import hashlib
import ecdsa
from bit.network import NetworkAPI

# Define the word list
word_list = [
    "tower", "moon", "food", "neck", "hope", "number", "day", "this", "first",
    "find", "picture", "subject", "real", "only", "black",
    "life", "matter", "pyramid", "brave", "welcome", "world", "police",
    "camera", "survey", "flag", "rain", "virus", "model", "decide", "arrive",
    "party", "need", "history", "order", "stable", "coin", "digital", "define",
    "verify", "liberty", "public", "problem", "owner", "own", "spend", "common",
    "solution", "creek", "system", "news", "confirm", "transfer", "one", "inspire",
    "peace", "identify", "vote", "mask", "run", "double", "return", "trust",
    "clock", "purpose", "sing", "know", "gun", "later", "proof", "time", "agree",
    "neither", "state", "place", "second", "minute", "hour", "half", "color",
    "green", "blue", "future", "battle", "glass", "top", "face", "twelve",
    "country", 
    # "phrase", "puzzle", "seed"
]

# Initialize Mnemonic and BIP32
mnemo = Mnemonic("english")

# Function to derive the first Bitcoin address from a seed phrase
def derive_address(seed_phrase):
    seed = mnemo.to_seed(seed_phrase)
    root_key = BIP32.from_seed(seed)
    child_key = root_key.get_privkey_from_path("m/44'/0'/0'/0/0")

    sk = ecdsa.SigningKey.from_string(child_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Compressed public key
    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

    # Calculate the address
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key).digest())
    hashed_public_key = ripemd160.digest()
    
    address = b'\x00' + hashed_public_key  # Prepend 0x00 for mainnet
    checksum = hashlib.sha256(hashlib.sha256(address).digest()).digest()[:4]
    address += checksum
    
    return address.hex()

# Function to check the balance of a Bitcoin address asynchronously
async def check_balance_async(address):
    try:
        balance = await asyncio.to_thread(NetworkAPI.get_balance_testnet, address)
        return balance
    except Exception as e:
        print(f"Error checking balance for {address}: {e}")
        TimeoutError
        ConnectionRefusedError
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

# Generate all combinations of 12 words
async def main():
    tried_combinations = read_tried_combinations()

    for combination in itertools.combinations(word_list, 12):
        if tuple(combination) in tried_combinations:
            continue  # Skip already tried combinations

        seed_phrase = " ".join(combination)
        print(f"Checking seed phrase: {seed_phrase}")

        # Log tried combination
        log_tried_combinations(combination)

        # Derive Bitcoin address
        address = derive_address(seed_phrase)

        # Check balance asynchronously
        balance = await check_balance_async(address)
        if balance is not None:
            print(f"Address: {address}, Balance: {balance} satoshis")
        
        # If balance is found, save the seed phrase and stop
        if balance and balance > 0:
            print(f"Bitcoin found! Seed phrase: {seed_phrase}")
            with open("found_seed_phrase.txt", "w") as f:
                f.write(seed_phrase)
            break

if __name__ == "__main__":
    asyncio.run(main())
