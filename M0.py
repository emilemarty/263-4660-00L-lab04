#!/usr/bin/env python3

import json
import socket

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50400

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


secret = run_command({"command": "encrypt_secret"})["result"]
print(len(secret))  # Check the length of the secret

for i in range(10):  # Check that the counter is not incremented for string length < BLOCK_SIZE
    ptxt1 = 'a' * 15
    ptxt2 = 'b' * 14
    ctxt1 = run_command({"command": "encrypt", "msg": ptxt1})["result"]
    ctxt2 = run_command({"command": "encrypt", "msg": ptxt2})["result"]
    print("Call #" + str(i + 1) + ":\t" + ctxt1 + "\t" + ctxt2)

# Grab as much as possible from the first mask, without increasing the counter
ptxt = "a" * 15
R_0 = bytes.fromhex(run_command({"command": "encrypt", "msg": ptxt})["result"])
R_0 = xor(R_0, ptxt.encode()).hex()

# Request the secret, its length is slightly less than 2 blocks, so counter increases only by 1
secret = run_command({"command": "encrypt_secret"})["result"]
print("secret(" + str(len(secret)) + "):\t" + secret)

# Grab the second mask, up to the length of the secret
ptxt = "a" * 14
R_1 = bytes.fromhex(run_command({"command": "encrypt", "msg": ptxt})["result"])
R_1 = xor(R_1, ptxt.encode()).hex()
print("mask(" + str(len(R_0) + len(R_1)) + "):\t" + R_0 + "\t" + R_1)

# Do an exhaustive search for the missing byte
for i in range(256):
    guess = R_0 + f"{i:02x}" + R_1
    guess = xor(bytes.fromhex(secret), bytes.fromhex(guess))
    try:
        guess = guess.decode()[8:24]
        print("Guess #" + str(i + 1) + ":\t" + run_command({"command": "flag", "solve": guess})["flag"])
        break
    except (UnicodeDecodeError, KeyError) as e:
        print("Guess #" + str(i + 1) + ":\tWrong guess.")
