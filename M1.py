#!/usr/bin/env python3

import json
import socket
from string import ascii_letters

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50401

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
    return bytes(a ^ b for a, b in zip(x, y))


BLOCK_SIZE = 16
# Intuition: we build the secret letter by letter, going from left to right
guess = ""
for i in range(BLOCK_SIZE + 1):
    for c in ascii_letters:
        c = f"{ord(c):02x}"
        msg = (f"{0:032x}"                  # P_1 = all 0s, so that we have C_1 = E(K, IV xor 0) = E(K, IV)
               + "00" * (BLOCK_SIZE - i)
               + guess + c                  # P_2 = our guess so far, plus the next character, pre-padded with 0s
               + "00" * (BLOCK_SIZE - i))   # P_3 = the first i letters of the secret, pre-padded with 0s
        ctxt = run_command({"command": "encrypt", "msg": msg})["result"]
        ctxt_blocks = [ctxt[i:i + 2 * BLOCK_SIZE] for i in range(0, len(ctxt), 2 * BLOCK_SIZE)]
        C_1 = ctxt_blocks[1]    # C_1 = E(K, IV) as seen above
        C_3 = ctxt_blocks[3]    # C_3 = E(K, IV xor G_i xor S_i) where S_i is the first i letters of the secret
        if C_1 == C_3:          # observe that if G_i == S_i then we have C_3 = E(K, IV xor 0) = C_1
            guess += c          # so we can check if our guess was correct, add it, and continue building
            break
solve = bytes.fromhex(guess).decode()
print("secret: \t" + solve)
flag = run_command({"command": "flag", "solve": solve})
try:
    print(flag["flag"])
except KeyError as e:
    print(flag["error"])
