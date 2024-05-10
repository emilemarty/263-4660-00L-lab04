#!/usr/bin/env python3

import json
import secrets
import socket

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50404

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


solves = 0
while solves < 42:
    # list the admin file IDs (only has 1, the secret file)
    admin_ids = run_command({"command": "list", "user": "admin"})["result"]
    print(admin_ids)
    secret_file_id = admin_ids[0]
    # want to call the get command which gives the secret file
    # for this we need to find the ciphertext which produces admin_id
    # use the get command as a padding oracle
    iv = ""
    ctxt = secrets.token_bytes(16).hex()
    for offset in range(15, -1, -1):
        for i in range(256):
            guess = iv + f"{i:02x}" + "00" * offset
            if len(guess) != 32:  # sanity check
                raise ValueError("Could not find a valid padding")
            msg = run_command({"command": "get", "user": "admin", "ctxt": guess + ctxt})["error"]
            if msg == "File not found!":
                # at this point the IV generates a valid padding
                if i % 2 == 1:  # flip the last bit, changing \x01 -> \x00
                    iv += f"{i - 1:02x}"
                else:
                    iv += f"{i + 1:02x}"
                break  # continue with the next byte
            else:
                continue  # invalid padding, try another guess
    # now we have an (iv, ctxt) pair that decrypts into an empty plaintext block (P_1 = 0)
    iv = xor(bytes.fromhex(iv),
             bytes.fromhex("01" + secret_file_id)).hex()  # xor the iv with the file id we want to access
    try:
        secret_file = run_command({"command": "get", "user": "admin", "ctxt": iv + ctxt})["result"]
        print(run_command({"command": "flag", "solve": secret_file}))
        solves += 1
    except KeyError as _:
        continue
