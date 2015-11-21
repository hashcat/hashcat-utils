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

#define LEN_MAX 32

#define SEGMENT_SIZE  (32 * 1024 * 1024)
#define SEGMENT_ALIGN ( 8 * 1024)

/**
 * Name........: combinator
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

static size_t read_segment (char *buf, FILE *fd)
{
  size_t read_sz = SEGMENT_SIZE - SEGMENT_ALIGN;

  size_t real_sz = fread (buf, 1, read_sz, fd);

  if (real_sz == 0) return (0);

  if (real_sz != read_sz)
  {
    if (buf[real_sz - 1] != '\n')
    {
      real_sz++;

      buf[real_sz - 1] = '\n';
    }

    return (real_sz);
  }

  size_t extra;

  for (extra = 0; extra < SEGMENT_ALIGN; extra++)
  {
    if (fread (buf + real_sz, 1, 1, fd) == 0) break;

    real_sz++;

    if (buf[real_sz - 1] == '\n') break;
  }

  return (real_sz);
}

static size_t get_line_len (char *pos, char *max)
{
  char *cur = pos;

  for (cur = pos; cur < max; cur++)
  {
    if (*cur == '\n') break;
  }

  size_t len = cur - pos;

  return (len);
}

static void add (char *ptr_out, char *ptr_in1, size_t len_in1, char *ptr_in2, size_t len_in2)
{
  memcpy (ptr_out, ptr_in1, len_in1);

  ptr_out += len_in1;

  memcpy (ptr_out, ptr_in2, len_in2);

  ptr_out += len_in2;

  *ptr_out = '\n';
}

int main (int argc, char *argv[])
{
  if (argc != 3)
  {
    fprintf (stderr, "usage: %s file1 file2\n", argv[0]);

    return (-1);
  }

  size_t sz_buf = SEGMENT_SIZE + SEGMENT_ALIGN;

  char *buf_in1 = (char *) malloc (sz_buf);
  char *buf_in2 = (char *) malloc (sz_buf);

  char *buf_out = (char *) malloc (sz_buf);

  char *ptr_out = buf_out;

  FILE *fd1;
  FILE *fd2;

  if ((fd1 = fopen (argv[1], "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", argv[1], strerror (errno));

    free (buf_in1);
    free (buf_in2);
    free (buf_out);

    return (-1);
  }

  if ((fd2 = fopen (argv[2], "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", argv[2], strerror (errno));

    free (buf_in1);
    free (buf_in2);
    free (buf_out);

    fclose (fd1);

    return (-1);
  }

  while (!feof (fd1))
  {
    size_t real_sz1 = read_segment (buf_in1, fd1);

    char *max_in1 = buf_in1 + real_sz1;

    char *ptr_in1;

    size_t len_in1;

    for (ptr_in1 = buf_in1; ptr_in1 < max_in1; ptr_in1 += len_in1 + 1)
    {
      len_in1 = get_line_len (ptr_in1, max_in1);

      size_t vir_in1 = len_in1;

      while (vir_in1)
      {
        if (ptr_in1[vir_in1 - 1] != '\r') break;

        vir_in1--;
      }

      if (vir_in1 > LEN_MAX) continue;

      while (!feof (fd2))
      {
        size_t real_sz2 = read_segment (buf_in2, fd2);

        char *max_in2 = buf_in2 + real_sz2;

        char *ptr_in2;

        size_t len_in2;

        for (ptr_in2 = buf_in2; ptr_in2 < max_in2; ptr_in2 += len_in2 + 1)
        {
          len_in2 = get_line_len (ptr_in2, max_in2);

          size_t vir_in2 = len_in2;

          while (vir_in2)
          {
            if (ptr_in2[vir_in2 - 1] != '\r') break;

            vir_in2--;
          }

          if (vir_in2 > LEN_MAX) continue;

          /**
           * add to output buffer
           */

          size_t len_out = ptr_out - buf_out;

          size_t len_add = vir_in1 + vir_in2 + 1;

          if ((len_out + len_add) < SEGMENT_SIZE)
          {
            add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2);

            ptr_out += len_add;
          }
          else
          {
            size_t len_out = ptr_out - buf_out;

            fwrite (buf_out, 1, len_out, stdout);

            ptr_out = buf_out;

            add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2);

            ptr_out += len_add;
          }
        }
      }

      rewind (fd2);
    }
  }

  size_t len_out = ptr_out - buf_out;

  fwrite (buf_out, 1, len_out, stdout);

  fclose (fd2);
  fclose (fd1);

  free (buf_out);

  free (buf_in2);
  free (buf_in1);

  return 0;
}
