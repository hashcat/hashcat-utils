#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "utils.c"

#define LOWER  (1 << 0)
#define UPPER  (1 << 1)
#define DIGIT  (1 << 2)
#define SYMBOL (1 << 3)
#define OTHER  (1 << 4)

/**
 * Name........: req-exclude
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s exc_mask < infile > outfile\n", argv[0]);
    fprintf (stderr, "  exc_mask is the mask of prohibited (at least one character of ANY) types\n");
    fprintf (stderr, "  type masks: add together the numbers, i.e. lower + upper = 3\n");
    fprintf (stderr, "     LOWER 1\n");
    fprintf (stderr, "     UPPER 2\n");
    fprintf (stderr, "     DIGIT 4\n");
    fprintf (stderr, "     SYMBOL 8 (0x20 to 0x7e NOT IN lower, upper, digit)\n");
    fprintf (stderr, "     OTHER (tab, high ASCII, etc.) 16\n");

    return (-1);
  }

  #ifdef _WINDOWS
  setmode (0, O_BINARY);
  #endif

  int exc_mask = atoi (argv[1]);

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    int cur_mask = 0;

    int p;

    for (p = 0; p < line_len; p++)
    {
           if ((line_buf[p] >=  'a') && (line_buf[p] <=  'z')) cur_mask |= LOWER;
      else if ((line_buf[p] >=  'A') && (line_buf[p] <=  'Z')) cur_mask |= UPPER;
      else if ((line_buf[p] >=  '0') && (line_buf[p] <=  '9')) cur_mask |= DIGIT;
      else if ((line_buf[p] >= 0x20) && (line_buf[p] <= 0x7e)) cur_mask |= SYMBOL;
      else cur_mask |= OTHER;
    }

    if (cur_mask & exc_mask) continue;

    puts (line_buf);
  }

  return 0;
}
