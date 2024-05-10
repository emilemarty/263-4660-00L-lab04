#!/usr/bin/env python3

import json
import socket
import random

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50402

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

# Intuition: use the predictable IVs to determine which secret message is encrypted
for i in range(64):
    for m in MESSAGES:
        local_iv = random.randbytes(16)  # generate next IV
        output = run_command({"command": "encrypt", "msg": ""})
        C_0 = output["iv"]
        C_1 = output["ctxt"][0:32]
        if local_iv.hex() != C_0:  # sanity check
            raise ValueError("incorrect seed")

        local_iv = random.randbytes(16)  # generate next IV
        msg = xor(xor(m[0:16].encode(), bytes.fromhex(C_0)), local_iv)
        output = run_command({"command": "encrypt", "msg": msg.hex()})
        C_0_prime = output["iv"]
        C_1_prime = output["ctxt"][0:32]
        if local_iv.hex() != C_0_prime:  # sanity check
            raise ValueError("incorrect seed")

        if C_1 == C_1_prime:
            print(run_command({"command": "guess", "guess": m})["result"])
            break
    # only the secret message is changed over rounds, seed is reused
print(run_command({"command": "flag", "msg": ""})["flag"])
