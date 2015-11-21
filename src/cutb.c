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

/**
 * Name........: cutb
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

int main (int argc, char *argv[])
{
  if ((argc != 2) && (argc != 3))
  {
    fprintf (stderr, "usage: %s offset [length] < infile > outfile\n", argv[0]);

    return (-1);
  }

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  int offset = atoi (argv[1]);

  int length = 1000;

  if (argc == 3)
  {
    length = atoi (argv[2]);
  }

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    char *ptr = line_buf;

    if (offset > 0)
    {
      ptr += offset;

      line_len -= offset;
    }
    else if (offset < 0)
    {
      ptr += line_len + offset;

      line_len += offset;
    }

    if (line_len > length) line_len = length;

    ptr[line_len] = 0;

    puts (ptr);
  }

  return 0;
}
