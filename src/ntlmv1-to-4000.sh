#!/usr/bin/env bash
#
# MIT License (Same as Hashcat)
#
# Copyright Dustin Heywood(EvilMog®, 27 October 2026)
#
# ntlmv1-to-4000.sh — turn NTLMv1/ESS Responder captures into hashcat -m 4000
# (hash recipe) inputs for the direct DES-key route, ESS detected per line.
#
# All crypto (str_to_key spread, ESS MD5 challenge, DES) happens inside the
# hx recipe. This wrapper is pure field surgery — no DES, no MD5, no deps.
#
# Usage:  ./ntlmv1-to-4000.sh capture.txt [outdir]
#         cat capture.txt | ./ntlmv1-to-4000.sh - [outdir]
# Accepts bare hashlines OR raw Responder logs ([SMB] ... Hash : <line>).
#
# Emits, into outdir (default .):
#   ct12.plain  ct3.plain   non-ESS:  <ct>*<server_challenge>
#   ct12.ess    ct3.ess     ESS:      <ct>*<server_challenge>*<client_challenge>
# ct1/ct2 -> des() 8-byte DES key, DES_full ?1x8 (2^56, same as mode 14000)
# ct3     -> des_block() 7-byte key, only 2 unknown bytes ?b?b (2^16)
set -euo pipefail

in="${1:--}"; out="${2:-.}"; mkdir -p "$out"
: > "$out/ct12.noess.hash"; : > "$out/ct3.noess.hash"
: > "$out/ct12.ess.hash";   : > "$out/ct3.ess.hash"

# Pull valid NTLMv1 hashlines out of anything (logs or bare lines).
grep -oiE '[^ :]+::[^:]*:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{16}' \
     "${in/#-//dev/stdin}" |
awk -F: -v O="$out" '
{
  lm=tolower($4); nt=tolower($5); srv=tolower($6)
  ct1=substr(nt,1,16); ct2=substr(nt,17,16); ct3=substr(nt,33,16)
  cli=substr(lm,1,16)
  # ESS per ntlmv1-multi: trailing 28 hex of lmresp are zero
  ess = (substr(lm,21) == "0000000000000000000000000000")
  if (ess) {
    print ct1"*"srv"*"cli >> O"/ct12.ess.hash"
    print ct2"*"srv"*"cli >> O"/ct12.ess.hash"
    print ct3"*"srv"*"cli >> O"/ct3.ess.hash"
  } else {
    print ct1"*"srv >> O"/ct12.noess.hash"
    print ct2"*"srv >> O"/ct12.noess.hash"
    print ct3"*"srv >> O"/ct3.noess.hash"
  }
}'

# Drop empty files so the command block only shows what you actually have.
# (Only touches these four outputs — never the input capture.)
for f in ct12.noess.hash ct3.noess.hash ct12.ess.hash ct3.ess.hash; do
  [ -s "$out/$f" ] || rm -f "$out/$f"
done

HC="${HASHCAT:-./hashcat.bin}"
echo "# ---- hash files written to $out ----"; ls -1 "$out" | grep -E 'ct(12|3)\.(noess|ess)\.hash' | sed "s#^#$out/#"
echo
echo "# ---- run these (hashcat loads the .hash file; wordlist is the candidate) ----"
[ -s "$out/ct12.noess.hash" ] && cat <<EOF
# ct1/ct2  non-ESS  (NT half, 2^56)
$HC -m 4000 --hash-recipe 'des_block(pass, fromhex(salt))' \\
  -a 3 $out/ct12.noess.hash ?b?b?b?b?b?b?b
EOF
[ -s "$out/ct3.noess.hash" ] && cat <<EOF
# ct3      non-ESS  (2 unknown NT bytes, 2^16)
$HC -m 4000 --hash-recipe 'des_block(pass, fromhex(salt))' \\
  -a 3 $out/ct3.noess.hash ?b?b
EOF
[ -s "$out/ct12.ess.hash" ] && cat <<EOF
# ct1/ct2  ESS/SSP   (challenge derived in hx: md5(server . client)[:8])
$HC -m 4000 --hash-recipe 'des_block(pass, md5_bin(fromhex(salt) . fromhex(salt2)))' \\
  -a 3 $out/ct12.ess.hash ?b?b?b?b?b?b?b
EOF
[ -s "$out/ct3.ess.hash" ] && cat <<EOF
# ct3      ESS/SSP   (2^16)
$HC -m 4000 --hash-recipe 'des_block(pass, md5_bin(fromhex(salt) . fromhex(salt2)))' \\
  -a 3 $out/ct3.ess.hash ?b?b
EOF
echo "# reassemble: every part cracks straight to NT bytes —"
echo "# NT = ct1(7) . ct2(7) . ct3(2), no des_to_ntlm_slice needed."
