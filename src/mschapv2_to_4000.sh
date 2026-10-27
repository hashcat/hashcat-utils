#!/usr/bin/env bash
#
# MIT License (Same as Hashcat)
#
# Copyright Dustin Heywood(EvilMog®, 27 October 2026)
#
# mschapv2-to-4000.sh — turn MSCHAPv2 / NetNTLMv1 hashes into hashcat -m 4000
# (hash recipe) inputs for the direct DES route. Mirrors ntlmv1_nextgen.py's
# parse_mschapv2: the challenge field is used directly as the 8-byte DES block
# (no ESS/MD5, no SHA1 reduction — see note at bottom).
#
# All crypto (str_to_key spread, DES) happens inside the hx recipe.
# Pure field surgery — no DES, no deps.
#
# Usage:  ./mschapv2-to-4000.sh hashes.txt [outdir]
#         cat hashes.txt | ./mschapv2-to-4000.sh - [outdir]
# Accepts either input form (same as the tool):
#   $MSCHAPv2$<chal16>$<ntresp48>   (also $NETNTLM$ / $NETNTLMv1$)
#   <...>:<chal16>:<ntresp48>       (colon form, last two fields; no '$')
#
# Emits hashcat -m 4000 HASH files into outdir (default .):
#   mschap.ct12.hash   ct1/ct2 -> 7-byte NT half,  ?b x7  (2^56)
#   mschap.ct3.hash    ct3     -> 2 unknown bytes, ?b?b   (2^16)
# Both crack straight to NT bytes; recipe is des_block(pass, fromhex(salt)).
set -euo pipefail

in="${1:--}"; out="${2:-.}"; mkdir -p "$out"
: > "$out/mschap.ct12.hash"; : > "$out/mschap.ct3.hash"

awk -v O="$out" '
{
  chal=""; ntresp=""
  if (match($0, /\$(MSCHAPv2|NETNTLM|NETNTLMv1)\$[0-9A-Fa-f]{16}\$[0-9A-Fa-f]{48}/)) {
    split(substr($0,RSTART,RLENGTH), a, "$"); chal=a[3]; ntresp=a[4]   # $TYPE$chal$ntresp
  } else if ($0 ~ /:/ && $0 !~ /\$/) {
    n=split($0, f, ":"); chal=f[n-1]; ntresp=f[n]                      # last two colon fields
  }
  if (chal ~ /^[0-9A-Fa-f]{16}$/ && ntresp ~ /^[0-9A-Fa-f]{48}$/) {
    chal=tolower(chal); ntresp=tolower(ntresp)
    print substr(ntresp,1,16) "*" chal >> O"/mschap.ct12.hash"
    print substr(ntresp,17,16) "*" chal >> O"/mschap.ct12.hash"
    print substr(ntresp,33,16) "*" chal >> O"/mschap.ct3.hash"
  }
}' "${in/#-//dev/stdin}"

for f in mschap.ct12.hash mschap.ct3.hash; do
  [ -s "$out/$f" ] || rm -f "$out/$f"
done

HC="${HASHCAT:-./hashcat.bin}"
echo "# ---- hash files written to $out ----"; ls -1 "$out" | grep -E 'mschap\.ct(12|3)\.hash' | sed "s#^#$out/#"
echo
echo "# ---- run these (hashcat loads the .hash file; wordlist is the candidate) ----"
[ -s "$out/mschap.ct12.hash" ] && cat <<EOF
# ct1/ct2  (NT half, 2^56)
$HC -m 4000 --hash-recipe 'des_block(pass, fromhex(salt))' \\
  -a 3 $out/mschap.ct12.hash ?b?b?b?b?b?b?b
EOF
[ -s "$out/mschap.ct3.hash" ] && cat <<EOF
# ct3      (2 unknown NT bytes, 2^16)
$HC -m 4000 --hash-recipe 'des_block(pass, fromhex(salt))' \\
  -a 3 $out/mschap.ct3.hash ?b?b
EOF
echo "# reassemble: NT = ct1(7) . ct2(7) . ct3(2), straight from the cracked candidates."
