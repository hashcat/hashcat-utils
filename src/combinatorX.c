/**
 * Name........: combinatorX
 * Author......: Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 * Version.....: 1.0
 * License.....: MIT
 *
 * Enhanced version of jsteube 'combinator3'
 * feat. lightweight dolphin macro :P
 */

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
#include <getopt.h>
#include <unistd.h>

#include "utils.c"

#define LEN_MAX 32

#define SEGMENT_SIZE  (32 * 1024 * 1024)
#define SEGMENT_ALIGN ( 8 * 1024)

// lightweight dolphin macro
#define MEMORY_FREE_ADD(a)      { freeList[freeListIdx++] = (void *)(a); }
#define MEMORY_FREE_ALL         { int t=freeListIdx; while (t-- > 0) if (freeList[t]!=NULL) { free (freeList[t]); freeList[t]=NULL; } if (freeList!=NULL) { free (freeList); freeList=NULL; } }

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

  size_t len = (size_t) (cur - pos);

  return (len);
}

static void add (char *ptr_out,
                 char *ptr_in1, size_t len_in1,
                 char *ptr_in2, size_t len_in2,
                 char *ptr_in3, size_t len_in3,
                 char *ptr_in4, size_t len_in4,
                 char *sepStart, size_t sepStart_len,
                 char *sep1, size_t sep1_len,
                 char *sep2, size_t sep2_len,
                 char *sep3, size_t sep3_len,
                 char *sepEnd, size_t sepEnd_len)
{
  if (sepStart_len != 0)
  {
    memcpy (ptr_out, sepStart, sepStart_len);
    ptr_out += sepStart_len;
  }

  memcpy (ptr_out, ptr_in1, len_in1);
  ptr_out += len_in1;

  if (sep1_len != 0)
  {
    memcpy (ptr_out, sep1, sep1_len);
    ptr_out += sep1_len;
  }

  memcpy (ptr_out, ptr_in2, len_in2);
  ptr_out += len_in2;

  if (sep2_len != 0)
  {
    memcpy (ptr_out, sep2, sep2_len);
    ptr_out += sep2_len;
  }

  memcpy (ptr_out, ptr_in3, len_in3);
  ptr_out += len_in3;

  if (sep3_len != 0)
  {
    memcpy (ptr_out, sep3, sep3_len);
    ptr_out += sep3_len;
  }

  memcpy (ptr_out, ptr_in4, len_in4);
  ptr_out += len_in4;

  if (sepEnd_len != 0)
  {
    memcpy (ptr_out, sepEnd, sepEnd_len);
    ptr_out += sepEnd_len;
  }

  *ptr_out = '\n';
}

static struct option long_options[] =
{
  {"file1",    required_argument, NULL, 0xf1},
  {"file2",    required_argument, NULL, 0xf2},
  {"file3",    required_argument, NULL, 0xf3},
  {"file4",    required_argument, NULL, 0xf4},
  {"sepStart", required_argument, NULL, 0xa0},
  {"sep1",     required_argument, NULL, 0xa1},
  {"sep2",     required_argument, NULL, 0xa2},
  {"sep3",     required_argument, NULL, 0xa3},
  {"sepEnd",   required_argument, NULL, 0xaf},
  {0, 0, 0, 0}
};

/**
 * add to output buffer
 */

#define ADD_TO_OUTPUT_BUFFER(buf_out,ptr_out,ptr_in1,vir_in1,ptr_in2,vir_in2,ptr_in3,vir_in3,ptr_in4,vir_in4,sepStart,sepStart_len,sep1,sep1_len,sep2,sep2_len,sep3,sep3_len,sepEnd,sepEnd_len) \
{ \
  size_t len_out = (size_t) (ptr_out - buf_out); \
  size_t len_add = sepStart_len + vir_in1 + sep1_len + vir_in2 + sep2_len + vir_in3 + sep3_len + vir_in4 + sepEnd_len + 1; \
\
  if ((len_out + len_add) < SEGMENT_SIZE) \
  { \
    add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sepEnd, sepEnd_len); \
    ptr_out += len_add; \
  } \
  else \
  { \
    fwrite (buf_out, 1, len_out, stdout); \
    ptr_out = buf_out; \
    add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sepEnd, sepEnd_len); \
    ptr_out += len_add; \
  } \
}

static void usage (char *p)
{
  fprintf (stdout,
    "Usage: %s [<options>]\n\n" \
    "Options:\n\n" \
    "  Argument   | Type        | Description                           | Option type | Example\n" \
    "  ----------------------------------------------------------------------------------------------\n"
    "  --file1    | Path        | Set file1 path                        | required    | --file1 wordlist1.txt\n" \
    "  --file2    | Path        | Set file2 path                        | required    | --file2 wordlist2.txt\n" \
    "  --file3    | Path        | Set file3 path                        | optional    | --file3 wordlist3.txt\n" \
    "  --file4    | Path        | Set file4 path                        | optional    | --file4 wordlist4.txt\n" \
    "\n" \
    "  --sepStart | Char/String | Set char/string at the beginning      | optional    | --sepStart '['\n" \
    "  --sep1     | Char/String | Set separator between file1 and file2 | optional    | --sep1 'a.'\n" \
    "  --sep2     | Char/String | Set separator between file2 and file3 | optional    | --sep2 'bc'\n" \
    "  --sep3     | Char/String | Set separator between file3 and file4 | optional    | --sep3 ',d'\n" \
    "  --sepEnd   | Char/String | Set char/string at the end            | optional    | --sepEnd ']'\n" \
    "\n\n" \
    "Example:\n\n" \
    "input files: 1 2 3 4\n" \
    "$ cat 1 2 3 4 | xargs\n" \
    "one two three four\n" \
    "$ ./combinatorX.bin --file1 1 --file2 2 --file3 3 --file4 4 --sep1 ' . ' --sep2 ' + ' --sep3 ' @ ' --sepStart \"['\" --sepEnd ',*]'\n"
    "['one . two + three @ four,*]\n\n", p);
}

int main (int argc, char *argv[])
{
  int opt = 0;
  int long_index = 0;
  int err = 0;

  char **freeList = malloc(15 * sizeof(char *));
  int freeListIdx = 0;

  char *f1 = NULL, *f2 = NULL, *f3 = NULL, *f4 = NULL;
  char *sepStart = NULL, *sep1 = NULL, *sep2 = NULL, *sep3 = NULL, *sepEnd = NULL;
  size_t sepStart_len = 0, sep1_len = 0, sep2_len = 0, sep3_len = 0, sepEnd_len = 0;

  while ((opt = getopt_long_only (argc, argv,"", long_options, &long_index )) != -1)
  {
    switch (opt)
    {
      case 0xa0:
        sepStart_len = strlen(optarg);
        sepStart = strdup(optarg);

        MEMORY_FREE_ADD(sepStart)
        break;

      case 0xa1:
        sep1_len = strlen(optarg);
        sep1 = strdup(optarg);

        MEMORY_FREE_ADD(sep1)
        break;

      case 0xa2:
        sep2_len = strlen(optarg);
        sep2 = strdup(optarg);

        MEMORY_FREE_ADD(sep2)
        break;

      case 0xa3:
        sep3_len = strlen(optarg);
        sep3 = strdup(optarg);

        MEMORY_FREE_ADD(sep3)
        break;

      case 0xaf:
        sepEnd_len = strlen(optarg);
        sepEnd = strdup(optarg);

        MEMORY_FREE_ADD(sepEnd)
        break;

      case 0xf1:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { f1 = strdup (optarg); MEMORY_FREE_ADD(f1) }
        else err++;
        break;

      case 0xf2:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { f2 = strdup (optarg); MEMORY_FREE_ADD(f2) }
        else err++;
        break;

      case 0xf3:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { f3 = strdup (optarg); MEMORY_FREE_ADD(f3) }
        else err++;
        break;

      case 0xf4:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { f4 = strdup (optarg); MEMORY_FREE_ADD(f4) }
        else err++;
        break;

      default:
        err++;
        break;
    }
  }

  if (err > 0)
  {
    fprintf (stderr, "! Invalid arguments ...\n");
    usage (argv[0]);

    MEMORY_FREE_ALL

    return -1;
  }

  if (f1 == NULL || f2 == NULL)
  {
    fprintf (stderr, "! file1 and/or file2 are not set ...\n");
    usage (argv[0]);

    MEMORY_FREE_ALL

    return -1;
  }

  if (f3 == NULL)
  {
    if (sep3)
    {
      fprintf (stderr, "! Cannot set --sep3 if file3 is not set ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (f4)
    {
      fprintf (stderr, "! Cannot set --file4 if file3 is not set ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }
  }

  size_t sz_buf = SEGMENT_SIZE + SEGMENT_ALIGN;

  char *buf_in1 = (char *) malloc (sz_buf);
  char *buf_in2 = (char *) malloc (sz_buf);
  char *buf_in3 = NULL;
  char *buf_in4 = NULL;

  MEMORY_FREE_ADD (buf_in1)
  MEMORY_FREE_ADD (buf_in2)

  if (f3 != NULL)
  {
    buf_in3 = (char *) malloc (sz_buf);

    MEMORY_FREE_ADD (buf_in3)
  }
  if (f4 != NULL)
  {
    buf_in4 = (char *) malloc (sz_buf);

    MEMORY_FREE_ADD (buf_in4)
  }

  char *buf_out = (char *) malloc (sz_buf);

  MEMORY_FREE_ADD (buf_out)

  char *ptr_out = buf_out;

  FILE *fd1 = NULL;
  FILE *fd2 = NULL;
  FILE *fd3 = NULL;
  FILE *fd4 = NULL;

  if ((fd1 = fopen (f1, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f1, strerror (errno));

    MEMORY_FREE_ALL

    return (-1);
  }

  if ((fd2 = fopen (f2, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f2, strerror (errno));

    fclose (fd1);

    MEMORY_FREE_ALL

    return (-1);
  }

  if (f3 && (fd3 = fopen (f3, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f3, strerror (errno));

    fclose (fd1);
    fclose (fd2);

    MEMORY_FREE_ALL

    return (-1);
  }

  if (f4 && (fd4 = fopen (f4, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f4, strerror (errno));

    fclose (fd1);
    fclose (fd2);
    fclose (fd3);

    MEMORY_FREE_ALL

    return (-1);
  }

  char *ptr_in1 = NULL;
  char *ptr_in2 = NULL;
  char *ptr_in3 = NULL;
  char *ptr_in4 = NULL;

  size_t vir_in1 = 0;
  size_t vir_in2 = 0;
  size_t vir_in3 = 0;
  size_t vir_in4 = 0;

  while (!feof (fd1))
  {
    size_t real_sz1 = read_segment (buf_in1, fd1);
    size_t len_in1 = 0;
    char *max_in1 = buf_in1 + real_sz1;

    for (ptr_in1 = buf_in1; ptr_in1 < max_in1; ptr_in1 += len_in1 + 1)
    {
      len_in1 = get_line_len (ptr_in1, max_in1);
      vir_in1 = len_in1;

      while (vir_in1)
      {
        if (ptr_in1[vir_in1 - 1] != '\r') break;
        vir_in1--;
      }

      if (vir_in1 > LEN_MAX) continue;

      while (!feof (fd2))
      {
        size_t real_sz2 = read_segment (buf_in2, fd2);
        size_t len_in2 = 0;
        char *max_in2 = buf_in2 + real_sz2;

        for (ptr_in2 = buf_in2; ptr_in2 < max_in2; ptr_in2 += len_in2 + 1)
        {
          len_in2 = get_line_len (ptr_in2, max_in2);
          vir_in2 = len_in2;

          while (vir_in2)
          {
            if (ptr_in2[vir_in2 - 1] != '\r') break;
            vir_in2--;
          }

          if (vir_in2 > LEN_MAX) continue;

          if (buf_in3)
          {
            while (!feof (fd3))
            {
              size_t real_sz3 = read_segment (buf_in3, fd3);
              size_t len_in3 = 0;
              char *max_in3 = buf_in3 + real_sz3;

              for (ptr_in3 = buf_in3; ptr_in3 < max_in3; ptr_in3 += len_in3 + 1)
              {
                len_in3 = get_line_len (ptr_in3, max_in3);
                vir_in3 = len_in3;

                while (vir_in3)
                {
                  if (ptr_in3[vir_in3 - 1] != '\r') break;
                  vir_in3--;
                }

                if (vir_in3 > LEN_MAX) continue;

                if (buf_in4)
                {
                  while (!feof (fd4))
                  {
                    size_t real_sz4 = read_segment (buf_in4, fd4);
                    size_t len_in4 = 0;
                    char *max_in4 = buf_in4 + real_sz4;

                    for (ptr_in4 = buf_in4; ptr_in4 < max_in4; ptr_in4 += len_in4 + 1)
                    {
                      len_in4 = get_line_len (ptr_in4, max_in4);
                      vir_in4 = len_in4;

                      while (vir_in4)
                      {
                        if (ptr_in4[vir_in4 - 1] != '\r') break;
                        vir_in4--;
                      }

                      if (vir_in4 > LEN_MAX) continue;

                      ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sepEnd, sepEnd_len)
                    }
                  }
                  rewind (fd4);
                }
                else
                {
                  ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sepEnd, sepEnd_len)
                }
              }
            }
            rewind (fd3);
          }
          else
          {
            ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sepEnd, sepEnd_len)
          }
        }
      }
      rewind (fd2);
    }
  }

  size_t len_out = (size_t) (ptr_out - buf_out);

  fwrite (buf_out, 1, len_out, stdout);

  if (fd4) fclose (fd4);
  if (fd3) fclose (fd3);
  fclose (fd2);
  fclose (fd1);

  MEMORY_FREE_ALL

  return 0;
}