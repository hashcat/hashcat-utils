#!/usr/bin/env perl

## Name........: tmesis-dynamic
## Autor.......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT

use strict;
use warnings;

# This program takes 2 wordlists:
#
# - A wordlist (search): Each word is matched against the other wordlist. Don't make this too big, it's cached in memory.
# - A wordlist (base): Prints what remains after above word was "subtracted". This is something like rockyou.txt or better
#
# There's high chances to create duplicates, you need to sort -u the result yourself
#
# Result is ideal for using in -a 1 combinator attack mode. You may want to do two attacks:
#
# - one for having the result on the left
# - one for having the result on the right
#
# content wordlist (base):
#
# isajack3935
# jackysch_5131
# HBjackas5
# mom1jackhopes
#
# content wordlist (search):
#
# jack
# jacky
#
# produces candidates:
#
# isa
# 3935
# ysch_5131
# HB
# as5
# mom1
# hopes
# sch_5131

die "use: $0 wordlist_base.txt wordlist_search.txt\n" if scalar @ARGV != 2;

my ($wordlist_base, $wordlist_search) = @ARGV;

my @searches;

open (IN, $wordlist_search) or die;

while (my $word = <IN>)
{
  chomp $word;

  push @searches, $word;
}

close (IN);

open (IN, $wordlist_base) or die;

while (my $word = <IN>)
{
  chomp $word;

  for my $search (@searches)
  {
    my $prev = 0;

    next if index ($word, $search, $prev) == -1;

    my $total_len = length $word;

    while ($prev < $total_len)
    {
      my $pos = index ($word, $search, $prev);

      if ($pos == -1)
      {
        my $slice = substr ($word, $prev);

        printf "%s\n", $slice;

        last;
      }

      my $len = $pos - $prev;

      if ($len == 0)
      {
        $prev = $pos + length $search;

        next;
      }

      my $slice = substr ($word, $prev, $len);

      printf "%s\n", $slice;

      $prev = $pos + length $search;
    }
  }
}

close (IN);


