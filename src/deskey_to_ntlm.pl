#!/usr/bin/env perl

## Name........: deskey-to-ntlm.pl
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;

my $des_key = $ARGV[0] or die ("usage: $0 8-byte-key-in-hex\n");

my $des_key_bin = pack ("H16", $des_key);

my @des_keys = split "", $des_key_bin;

my @ntlm;

$ntlm[0] = (((ord ($des_keys[0]) << 0) & ~0x01) | (ord ($des_keys[1]) >> 7)) & 0xff;
$ntlm[1] = (((ord ($des_keys[1]) << 1) & ~0x03) | (ord ($des_keys[2]) >> 6)) & 0xff;
$ntlm[2] = (((ord ($des_keys[2]) << 2) & ~0x07) | (ord ($des_keys[3]) >> 5)) & 0xff;
$ntlm[3] = (((ord ($des_keys[3]) << 3) & ~0x0f) | (ord ($des_keys[4]) >> 4)) & 0xff;
$ntlm[4] = (((ord ($des_keys[4]) << 4) & ~0x1f) | (ord ($des_keys[5]) >> 3)) & 0xff;
$ntlm[5] = (((ord ($des_keys[5]) << 5) & ~0x3f) | (ord ($des_keys[6]) >> 2)) & 0xff;
$ntlm[6] = (((ord ($des_keys[6]) << 6) & ~0x7f) | (ord ($des_keys[7]) >> 1)) & 0xff;

printf "%02x%02x%02x%02x%02x%02x%02x\n",
  $ntlm[0],
  $ntlm[1],
  $ntlm[2],
  $ntlm[3],
  $ntlm[4],
  $ntlm[5],
  $ntlm[6];
