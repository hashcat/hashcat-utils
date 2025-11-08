# /*
# * Author.......: Dustin Heywood <dustin.heywood@gmail.com> (EvilMog)
# * Used C code stolen from .......: Jens Steube <jens.steube@gmail.com>
# * Thus this code is under the same license
# * License.....: MIT
# *
# * Most of the C code taken from hashcat use for the python port
# */

import argparse
import base64
import hashlib
import binascii
import json
from Crypto.Cipher import DES
from Crypto.Hash import MD4
import re


def generate_ntlm_hash(password):
    """
    Generates the NTLM hash (MD4) for a given password.
    The password is first encoded in UTF-16LE.
    """
    # Encode the password in UTF-16LE
    password_bytes = password.encode('utf-16le')

    # Create an MD4 hash object
    md4_hash = MD4.new()

    # Update the hash object with the encoded password
    md4_hash.update(password_bytes)

    # Return the hexadecimal digest of the hash
    return md4_hash.hexdigest()


def f_ntlm_des(key_7_bytes_hex):
    key_bytes = bytes.fromhex(key_7_bytes_hex)
    key = []
    key.append(key_bytes[0])
    key.append((key_bytes[0] << 7 | key_bytes[1] >> 1) & 0xFF)
    key.append((key_bytes[1] << 6 | key_bytes[2] >> 2) & 0xFF)
    key.append((key_bytes[2] << 5 | key_bytes[3] >> 3) & 0xFF)
    key.append((key_bytes[3] << 4 | key_bytes[4] >> 4) & 0xFF)
    key.append((key_bytes[4] << 3 | key_bytes[5] >> 5) & 0xFF)
    key.append((key_bytes[5] << 2 | key_bytes[6] >> 6) & 0xFF)
    key.append((key_bytes[6] << 1) & 0xFF)

    for i in range(8):
        # Ensure odd parity for each byte
        b = key[i]
        parity = 0
        for bit in range(7):
            parity += (b >> bit) & 1
        if parity % 2 == 0:
            key[i] |= 1  # set LSB to 1
        else:
            key[i] &= 0xFE  # set LSB to 0

    return ''.join(f'{b:02x}' for b in key)


def ntlm_to_des_keys(ntlm_hash):
    if len(ntlm_hash) != 32:
        raise ValueError("NTLM hash must be 32 hex characters")
    k1_hex = f_ntlm_des(ntlm_hash[0:14])
    k2_hex = f_ntlm_des(ntlm_hash[14:28])
    k3_hex = f_ntlm_des(ntlm_hash[28:32] + "000000000000")  # pad to 14 chars
    return k1_hex, k2_hex, k3_hex


def des_to_ntlm_slice(deskey_hex):
    deskey = bytes.fromhex(deskey_hex)
    bits = ''.join([f"{byte:08b}" for byte in deskey])
    stripped = ''.join([bits[i:i+7] for i in range(0, 64, 8)])
    ntlm_bytes = int(stripped, 2).to_bytes(7, 'big')
    return ntlm_bytes.hex()


def decode_and_validate_99(enc_99):
    if not enc_99.startswith("$99$"):
        raise ValueError("Invalid $99$ prefix")
    b64_data = enc_99[4:].strip().rstrip("=")
    b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
    raw = base64.b64decode(b64_data)
    if len(raw) != 26:
        raise ValueError(f"Expected 26 bytes, got {len(raw)}")
    return {
        "source": "$99$",
        "client_challenge": raw[0:8].hex(),
        "server_challenge": raw[0:8].hex(),
        "challenge": raw[0:8].hex(),
        "ct1": raw[8:16].hex(),
        "ct2": raw[16:24].hex(),
        "pt3": raw[24:26].hex(),
        "ct3": None,
        "k1": None,
        "k2": None,
        "pt1": None,
        "pt2": None,
    }


def des_encrypt_block(key8_hex, challenge_hex):
    if len(key8_hex) != 16 or len(challenge_hex) != 16:
        return None
    key_bytes = bytes.fromhex(key8_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    return cipher.encrypt(challenge_bytes).hex()


def recover_key_from_ct3(ct3_hex, challenge_hex, ess_hex=None):
    # Convert hex inputs to bytes
    ct3_bytes = bytes.fromhex(ct3_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)

    if len(ct3_bytes) != 8 or len(challenge_bytes) != 8:
        raise ValueError("ct3 and challenge must be 8 bytes (16 hex chars) each")

    # Convert bytes to integer representation
    ct3_val = int.from_bytes(ct3_bytes, 'big')
    challenge_val = int.from_bytes(challenge_bytes, 'big')

    # Handle ESS case using fast MD5 hash
    if ess_hex:
        ess_bytes = bytes.fromhex(ess_hex)
        if len(ess_bytes) != 24:
            raise ValueError("ESS must be 24 bytes (48 hex chars)")
        if ess_bytes[8:] == b'\x00' * 16:
            challenge_bytes = hashlib.md5(challenge_bytes + ess_bytes[:8]).digest()[:8]
            challenge_val = int.from_bytes(challenge_bytes, 'big')

    # **Optimized DES brute-force loop**
    found_key = None
    for i in range(0x10000):  # 16-bit key space
        # **Optimized 7-byte to 8-byte DES key transformation**
        nthash_bytes = [
            i & 0xFF,
            (i >> 8) & 0xFF,
            0, 0, 0, 0, 0
        ]
        key_bytes = bytes([
            nthash_bytes[0] | 1,
            ((nthash_bytes[0] << 7) | (nthash_bytes[1] >> 1)) & 0xFF | 1,
            ((nthash_bytes[1] << 6) | (nthash_bytes[2] >> 2)) & 0xFF | 1,
            ((nthash_bytes[2] << 5) | (nthash_bytes[3] >> 3)) & 0xFF | 1,
            ((nthash_bytes[3] << 4) | (nthash_bytes[4] >> 4)) & 0xFF | 1,
            ((nthash_bytes[4] << 3) | (nthash_bytes[5] >> 5)) & 0xFF | 1,
            ((nthash_bytes[5] << 2) | (nthash_bytes[6] >> 6)) & 0xFF | 1,
            ((nthash_bytes[6] << 1)) & 0xFF | 1
        ])

        # **Use PyCryptodome for fast DES encryption**
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted = cipher.encrypt(challenge_bytes)

        # **Fast integer comparison instead of byte-by-byte check**
        if int.from_bytes(encrypted, 'big') == ct3_val:
            found_key = i
            break

    if found_key is None:
        return None  # Key not found

    # **Return key in correct format (low-order byte first, as in C output)**
    return f"{found_key & 0xFF:02x}{(found_key >> 8) & 0xFF:02x}"


def parse_ntlmv1(ntlmv1_hash, key1=None, key2=None, show_pt3=True, json_mode=False):
    fields = ntlmv1_hash.strip().split(':')
    if len(fields) < 6:
        raise ValueError("Invalid NTLMv1 format")
    user, domain, lmresp, ntresp, challenge = fields[0], fields[2], fields[3], fields[4], fields[5]
    ct1, ct2, ct3 = ntresp[0:16], ntresp[16:32], ntresp[32:48]

    ess = None
    if lmresp[20:] == "0000000000000000000000000000":
        ess = lmresp
        m = hashlib.md5()
        m.update(binascii.unhexlify(challenge + lmresp[:16]))
        challenge = m.digest()[:8].hex()

    data = {
        "source": "ntlmv1",
        "username": user,
        "domain": domain,
        "client_challenge": fields[5],
        "server_challenge": challenge,
        "challenge": challenge,
        "lmresp": lmresp,
        "ntresp": ntresp,
        "ct1": ct1,
        "ct2": ct2,
        "ct3": ct3,
        "k1" : None,
        "k2" : None,
        "pt1": None,
        "pt2": None,
        "pt3": None,
        "ntlm": None
    }

    if key1 and len(key1) == 16:
        encrypted1 = des_encrypt_block(key1, challenge)
        if encrypted1 and encrypted1.lower() == ct1.lower():
            pt1 = des_to_ntlm_slice(key1)
            data["pt1"] = pt1

    if key2 and len(key2) == 16:
        encrypted2 = des_encrypt_block(key2, challenge)
        if encrypted2 and encrypted2.lower() == ct2.lower():
            pt2 = des_to_ntlm_slice(key2)
            data["pt2"] = pt2

    pt3 = recover_key_from_ct3(data["ct3"], data["client_challenge"], data["lmresp"])
    data["pt3"] = pt3

    if data["pt1"] and data["pt2"] and data["pt3"]:
        data["ntlm"] = data["pt1"] + data["pt2"] + data["pt3"]

    if not json_mode:
        print("\n[+] NTLMv1 Parsed:")
        for field in ["username", "domain", "challenge", "ct1", "ct2", "ct3" ,"pt1", "pt2", "pt3", "ntlm"]:
            print(f"{field.upper():>12}: {data.get(field)}")
    return data


def parse_mschapv2(mschapv2_input, key1=None, key2=None, json_mode=False):
    """
    Accepts:
      - $MSCHAPv2$<chal8Bhex>$<ntresp24Bhex>
      - $NETNTLM$... or $NETNTLMv1$... (treated the same)
      - Colon form: <user>::<domain>:<auth>:<peer>:<ntresp> → last two are challenge + NT response
    """
    s = mschapv2_input.strip()
    chal = None
    ntresp = None
    source = None

    m = re.search(r'\$(MSCHAPv2|NETNTLM|NETNTLMv1)\$([0-9A-Fa-f]{16})\$([0-9A-Fa-f]{48})', s)
    if m:
        source, chal, ntresp = m.group(1), m.group(2), m.group(3)

    elif ":" in s and "$" not in s:
        fields = s.split(":")
        if len(fields) >= 2:
            chal = fields[-2]
            ntresp = fields[-1]
            source = "colon"
        else:
            raise ValueError("Invalid colon format")

    else:
        raise ValueError("Unrecognized MSCHAPv2 format")

    ct1, ct2, ct3 = ntresp[0:16], ntresp[16:32], ntresp[32:48]

    data = {
        "source": source,
        "challenge": chal,
        "client_challenge": chal,
        "ct1": ct1,
        "ct2": ct2,
        "ct3": ct3,
        "k1" : None,
        "k2" : None,
        "pt1": None,
        "pt2": None,
        "pt3": None,
        "ntlm": None
    }

    if key1 and len(key1) == 16:
        encrypted1 = des_encrypt_block(key1, chal)
        if encrypted1 and encrypted1.lower() == ct1.lower():
            data["pt1"] = des_to_ntlm_slice(key1)

    if key2 and len(key2) == 16:
        encrypted2 = des_encrypt_block(key2, chal)
        if encrypted2 and encrypted2.lower() == ct2.lower():
            data["pt2"] = des_to_ntlm_slice(key2)

    data["pt3"] = recover_key_from_ct3(data["ct3"], chal)

    if data["pt1"] and data["pt2"] and data["pt3"]:
        data["ntlm"] = data["pt1"] + data["pt2"] + data["pt3"]

    if not json_mode:
        print("\n[+] MSCHAPv2 Parsed:")
        for field in ["challenge", "ct1", "ct2", "ct3", "pt1", "pt2", "pt3", "ntlm"]:
            print(f"{field.upper():>12}: {data.get(field)}")

    return data


def ntlmv1_to_99(parsed):
    try:
        challenge = bytes.fromhex(parsed["challenge"])
        ct1 = bytes.fromhex(parsed["ct1"])
        ct2 = bytes.fromhex(parsed["ct2"])
        pt3 = bytes.fromhex(parsed["pt3"])  # pt3 is already recovered via parse_ntlmv1()

        raw = challenge + ct1 + ct2 + pt3
        b64 = base64.b64encode(raw).decode().rstrip("=")
        return f"$99${b64}"
    except Exception as e:
        print(f"[-] Failed to convert to $99$: {e}")
        return None


def ntlmv1_to_mschapv2(parsed):
    """
    Build $MSCHAPv2$ line from a parsed NTLMv1 dict.
    Requires: parsed["challenge"], ["ct1"], ["ct2"], ["ct3"].
    """
    challenge = parsed.get("challenge")
    ct1 = parsed.get("ct1")
    ct2 = parsed.get("ct2")
    ct3 = parsed.get("ct3")

    if not (challenge and ct1 and ct2 and ct3):
        raise ValueError("Missing fields to build $MSCHAPv2$ (need challenge, ct1, ct2, ct3)")

    return f"$MSCHAPv2${challenge}${ct1}{ct2}{ct3}"


def main():
    parser = argparse.ArgumentParser(description="NTLMv1/$99$ parser with correct DES key handling and CT3 recovery.")
    parser.add_argument("--ntlmv1", help="NTLMv1 hash (Responder format)")
    parser.add_argument("--99", dest="hash_99", help="$99$ style base64 blob")
    parser.add_argument("--key1", help="16-char DES key hex for CT1")
    parser.add_argument("--key2", help="16-char DES key hex for CT2")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--to99", action="store_true", help="Convert NTLMv1 hash to $99$ format")
    parser.add_argument("--hashcat", action="store_true", help="Generate hashcat format strings for ct1/ct2")
    parser.add_argument("--nthash", help="32-char hex NTLM hash to compute DES keys and hashcat candidates")
    parser.add_argument("--mschapv2", help="MSCHAPv2 line in $MSCHAPv2$CHALLENGE$NTRESPONSE format")
    parser.add_argument("--to-mschapv2", action="store_true", help="Convert NTLMv1 hash to $MSCHAPv2$ format")
    parser.add_argument("--password", help="Convert password into des keys for --key1 and --key 2")

    args = parser.parse_args()

    if len(vars(args)) == 0 or all(v is None or v is False for v in vars(args).values()):
        parser.print_help()
        return

    output = {}

    # if password is given, and key1/key2 not explicitly set, derive them automatically

    if args.password and (not args.key1 or not args.key2):
       try:
            nthash = generate_ntlm_hash(args.password)
            if not args.nthash:
                args.nthash = nthash
            k1, k2, k3 = ntlm_to_des_keys(nthash)
            args.key1 = k1
            args.key2 = k2
       except Exception as e:
            print(f"[!] Failed to derive DES keys from NTLM hash: {e}")

    # If NTLM is given and key1/key2 not explicitly set, derive them automatically
    if args.nthash and (not args.key1 or not args.key2):
        try:
            k1, k2, k3 = ntlm_to_des_keys(args.nthash)
            if not args.key1:
                args.key1 = k1
            if not args.key2:
                args.key2 = k2
        except Exception as e:
            print(f"[!] Failed to derive DES keys from NTLM hash: {e}")

    if args.hash_99:
        data_99 = decode_and_validate_99(args.hash_99)

        if args.key1:
            encrypted1 = des_encrypt_block(args.key1, data_99["challenge"])
            if encrypted1 and encrypted1.lower() == data_99["ct1"].lower():
                data_99["k1"] = args.key1
                data_99["pt1"] = des_to_ntlm_slice(args.key1)

        if args.key2:
            encrypted2 = des_encrypt_block(args.key2, data_99["challenge"])
            if encrypted2 and encrypted2.lower() == data_99["ct2"].lower():
                data_99["k2"] = args.key2
                data_99["pt2"] = des_to_ntlm_slice(args.key2)

        # Optional: compute full NTLM hash if all parts are present
        if data_99.get("pt1") and data_99.get("pt2") and data_99.get("pt3"):
            data_99["ntlm"] = data_99["pt1"] + data_99["pt2"] + data_99["pt3"]

        output["$99$"] = data_99

        if not args.json:
            print("\n[+] $99$ Parsed:")
            for field in ["client_challenge", "ct1", "ct2", "ct3", "k1", "k2", "pt1", "pt2", "pt3", "ntlm"]:
                print(f"{field.upper():>20}: {data_99.get(field)}")

    if args.ntlmv1:
        output["ntlmv1"] = parse_ntlmv1(
            args.ntlmv1,
            key1=args.key1,
            key2=args.key2,
            json_mode=args.json
        )

    # Convert NTLMv1 -> $MSCHAPv2$
    if args.to_mschapv2:
        if not args.ntlmv1:
            print("[-] --to-mschapv2 requires --ntlmv1")
            return
        # Reuse already-parsed data if available; otherwise parse once here.
        parsed_ntlm = output.get("ntlmv1")
        if not parsed_ntlm:
            parsed_ntlm = parse_ntlmv1(
                args.ntlmv1,
                key1=args.key1,
                key2=args.key2,
                json_mode=True          # suppress prints; we'll control output below
            )
        mschapv2_str = ntlmv1_to_mschapv2(parsed_ntlm)
        if args.json:
            output["mschapv2"] = mschapv2_str
        else:
            print(mschapv2_str)
        # If you only want conversion output, you can `return` here.
        # Otherwise let the script continue to any other selected actions.

    if args.to99:
        if not args.ntlmv1:
            print("[-] --to99 requires --ntlmv1")
        else:
            # Force pt3 recovery during parse
            parsed = parse_ntlmv1(
                args.ntlmv1,
                key1=args.key1,
                key2=args.key2,
                show_pt3=True,
                json_mode=args.json
            )
            result = ntlmv1_to_99(parsed)
            if args.json:
                output = {
                    "ntlmv1": parsed,
                    "$99$": result
                }
                print(json.dumps(output, indent=2))
            else:
                print(f"[+] Converted to $99$:\n{result}")
        return  # Skip rest of the logic

    if args.mschapv2:
        try:
            output["mschapv2"] = parse_mschapv2(
                args.mschapv2,
                args.key1,
                args.key2,
                json_mode=args.json
            )
        except Exception as e:
            print(f"[-] Failed to parse MSCHAPv2 input: {e}")
            return

    if args.hashcat:
        # prefer ntlmv1 -> $99$ -> mschapv2, use whichever was parsed
        ctx_key = next((k for k in ("ntlmv1", "$99$", "mschapv2") if k in output), None)

        if ctx_key is None:
            if not args.json:
                print("[-] No parsed context to build hashcat lines. Provide --ntlmv1 / --99 / --mschapv2.")
        else:
            ctx = output[ctx_key]
            ct1 = ctx.get("ct1")
            ct2 = ctx.get("ct2")
            challenge = ctx.get("challenge")

            if ct1 and ct2 and challenge:
                if args.json:
                    # attach to the same object we parsed (uniform for ntlmv1/$99$/mschapv2)
                    ctx["hash1"] = f"{ct1}:{challenge}"
                    ctx["hash2"] = f"{ct2}:{challenge}"
                else:
                    print("\nTo crack with hashcat create a file with the following contents:")
                    print(f"{ct1}:{challenge}")
                    print(f"{ct2}:{challenge}\n")
                    print(f"echo \"{ct1}:{challenge}\" >> 14000.hash")
                    print(f"echo \"{ct2}:{challenge}\" >> 14000.hash\n")
            else:
                if not args.json:
                    print("[-] Missing ct1/ct2/challenge in context; cannot build hashcat lines.")

    if args.json:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
