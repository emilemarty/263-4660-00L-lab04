#!/usr/bin/env python3

import json
import random
import secrets
import socket
from string import ascii_letters

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50403

# Change this to REMOTE = False if you are running against a local instance of the server01
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "graded.aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server01, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())


# ===================================================================================
#    Write Your Solution Below
# ===================================================================================
def xor(x: bytes, y: bytes):
    if len(x) != len(y):
        raise ValueError("xor: bytes length mismatch")
    return bytes(a ^ b for a, b in zip(x, y))


def shift(i: int, msg: str):
    return random.randbytes(16).hex() + "00" * i + msg.encode().hex()


MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~"
]
# Pad all the messages to 32 bytes so that they are all at the same length
MESSAGES = [
    msg.ljust(32) for msg in MESSAGES
]

random = random.Random()
oracle_iv = run_command({"command": "encrypt", "msg": f"{0:032x}"})["iv"]
local_iv = bytes()

for m in MESSAGES:  # server uses one of the messages as a seed to generate IVs
    random.seed(m)
    local_iv = random.randbytes(16)
    if local_iv.hex() == oracle_iv:
        break

# server-side secret generation
print(''.join(secrets.choice(ascii_letters) for _ in range(32)))
print(''.join(secrets.choice(ascii_letters) for _ in range(32)).encode().hex())
# the secret is 32 ascii letters = 64 hex digits = 2 blocks


shifted = dict()
for i in range(15, -1, -1):
    msg = shift(i, "")  # Predicted IV is xored out in this function
    ctxt = run_command({"command": "encrypt", "msg": msg})["ctxt"]  # First block is E(K, 0)
    shifted.update({i: ctxt})

# Intuition: use the predictable IVs to guess letters from the secret, one by one, from left to right
guess = ""
for i in range(15, -1, -1):
    for c in ascii_letters:
        msg = shift(i, guess + c)
        ctxt = run_command({"command": "encrypt", "msg": msg})["ctxt"]
        cur_block = ctxt[:64]
        exp_block = shifted[i][:64]
        if cur_block == exp_block:  # Compare the first 2 blocks, if equal the guess was correct
            guess += c              # Add the letter to solution and continue to the next
            break
if len(guess) != 16:  # sanity check
    raise ValueError("guess = " + guess)
print(guess)
# At this point we have the first half of the secret
# Now we repeat the step above for the second half
for i in range(15, -1, -1):
    for c in ascii_letters:
        msg = shift(i, guess + c)
        ctxt = run_command({"command": "encrypt", "msg": msg})["ctxt"]
        cur_block = ctxt[:96]
        exp_block = shifted[i][:96]
        if cur_block == exp_block:  # Now we compare the first 3 blocks
            guess += c
            break
if len(guess) != 32:  # sanity check
    raise ValueError("guess = " + guess)
print(guess)
print(run_command({"command": "guess", "guess": guess})["flag"])
