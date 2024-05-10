#!/usr/bin/env python3

import json
import secrets
import socket

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50405

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


def pad(msg: bytes):
    """ Pad msg. """
    block_size = 16
    bit_padding_len = block_size - (len(msg) % block_size)
    bit_pading = b"\x00" * (bit_padding_len - 1) + b"\x01"
    return bit_pading + msg


secret_file = f"{secrets.randbelow(10000)}: don't forget that this is your secret AC login code.".encode() + b" " * 32
print(secret_file.hex())
secret_file = pad(secret_file)
ptxt_blocks = [secret_file[i:i + 16] for i in range(0, len(secret_file), 16)]
print(ptxt_blocks)
# 000000000001________3a20646f6e27
# 7420666f726765742074686174207468
# 697320697320796f7572207365637265
# 74204143206c6f67696e20636f64652e
# 20202020202020202020202020202020
# 20202020202020202020202020202020
# 180 hex chars = 90 bytes = 5.625 blocks
# NB: random code changes total file length

nums = [i for i in range(10)]
for i, n in enumerate(nums[:1:-1]):
    print(i, n)

# note that the backup command still does:
# file = self.decrypt(user, ctxt)
# even if the file is no longer used
# => can still use padding oracle
solves = 0
while solves < 3:
    # we just need to figure out the integer in the first part, check() can be called to confirm code
    ctxt_hashes = run_command({"command": "list"})["result"]
    print(ctxt_hashes)
    target_hash = ctxt_hashes[0]

    # use the backup command as a padding oracle
    ctxt = target_hash
    iv = ""
    for block_num, block in enumerate(ptxt_blocks[::-1]):
        print(block_num)
        iv = ""
        for offset in range(15, -1, -1):
            for i in range(256):
                guess = iv + f"{i:02x}" + "00" * offset
                if len(guess) != 32:  # sanity check
                    raise ValueError("Could not find a valid padding")
                try:
                    msg = run_command({"command": "backup", "user": "admin", "ctxt": guess + ctxt})["result"]
                    # at this point the IV generates a valid padding
                    if i % 2 == 1:  # flip the last bit, changing \x01 -> \x00
                        iv += f"{i - 1:02x}"
                    else:
                        iv += f"{i + 1:02x}"
                    break  # continue with the next byte
                except (KeyError, ValueError, TypeError):
                    continue
        if block_num != 5:
            iv = xor(bytes.fromhex(iv), block).hex()  # xor the iv with the current plaintext block to produce
            ctxt = iv
    # now we have an (iv, ctxt) pair that decrypts into an empty plaintext block (P_1 = 0)
    for i in range(10000):
        file = pad(f"{i}: don't forget that this is your secret AC login code.".encode() + b" " * 32)
        guess = xor(bytes.fromhex(iv), file[:16]).hex()  # xor the iv with a possible file start
        try:
            file_found = run_command({"command": "check", "ctxt_hash": target_hash, "ctxt_start": guess})["result"]
            print(i, file_found)
            if file_found:
                print(run_command({"command": "flag", "solve": file.hex()}))
                solves += 1
                break
        except:
            break

