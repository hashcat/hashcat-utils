#!/usr/bin/env perl

## Name........: tmesis-dynamic
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;
use Fcntl;

# tmesis-dynamic will take 2 wordlists and produces a new one
#
# each word of wordlist 1 which matches a user-defined substring substitutes
# that substring with each word of wordlist 2
#
# content wordlist 1:
#
# isajack3935
# jackysch_5131
# HBjackas5
# mom1jackhopes
#
# content wordlist 2:
#
# 123456
# password
# jill
# hashcat
#
# produces candidates with key "jack":
#
# isa1234563935
# isapassword3935
# isajill3935
# isahashcat3935
# 123456ysch_5131
# passwordysch_5131
# jillysch_5131
# hashcatysch_5131
# HB123456as5
# HBpasswordas5
# HBjillas5
# HBhashcatas5
# mom1123456hopes
# mom1passwordhopes
# mom1jillhopes
# mom1hashcathopes

die "use: $0 substring wordlist1.txt wordlist2.txt\n" if scalar @ARGV != 3;

my ($substring, $wordlist1, $wordlist2) = @ARGV;

open (IN1, $wordlist1) or die;

while (my $word1 = <IN1>)
{
  chomp $word1;

  my @slices = split (/$substring/i, $word1);

  next if scalar @slices == 1;

  open (IN2, $wordlist2) or die;

  while (my $word2 = <IN2>)
  {
    chomp $word2;

    print join ($word2, @slices), "\n";
  }

  close (IN2);
}

close (IN1);
