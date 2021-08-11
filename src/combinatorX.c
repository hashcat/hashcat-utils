/**
 * Name........: combinatorX
 * Author......: Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 * Version.....: 1.1
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
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>

#include "utils.c"

#define LEN_MAX 64

#define SEGMENT_SIZE  (LEN_MAX * 1024 * 1024)
#define SEGMENT_ALIGN (8 * 1024)

// lightweight dolphin macro
#define MEMORY_FREE_ADD(a) { freeList[freeListIdx++] = (void *)(a); }
#define MEMORY_FREE_ALL    { int t=freeListIdx; while (t-- > 0) if (freeList[t]!=NULL) { free (freeList[t]); freeList[t]=NULL; } if (freeList!=NULL) { free (freeList); freeList=NULL; } }

bool end = false;
char *sessionName = NULL;
FILE *sfp = NULL;

void sigHandler (int sig)
{
  signal (sig, SIG_IGN);
  printf ("Saved checkpoint in '%s'. Use '--restore %s' to restore\n", sessionName, sessionName);
  end = true;
}

bool session_init (bool restore, int64_t *off_fd1, int64_t *off_fd2, int64_t *off_fd3, int64_t *off_fd4, int64_t *off_fd5, int64_t *off_vir_in1, int64_t *off_vir_in2, int64_t *off_vir_in3, int64_t *off_vir_in4, int64_t *off_vir_in5)
{
  char *mode = (restore) ? "r+" : "w+";

  if (!(sfp = fopen (sessionName, mode)))
  {
    fprintf (stderr, "! fopen(%s) failed (%d): %s\n", sessionName, errno, strerror (errno));
    return false;
  }

  rewind (sfp); // ...

  if (!restore)
  {
    // init session with all zero
    *off_fd1 = 0;
    *off_fd2 = 0;
    *off_fd3 = 0;
    *off_fd4 = 0;
    *off_fd5 = 0;

    *off_vir_in1 = 0;
    *off_vir_in2 = 0;
    *off_vir_in3 = 0;
    *off_vir_in4 = 0;
    *off_vir_in5 = 0;

    // write status
    fprintf (sfp, "%" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 "", *off_fd1, *off_fd2, *off_fd3, *off_fd4, *off_fd5, *off_vir_in1, *off_vir_in2, *off_vir_in3, *off_vir_in4, *off_vir_in5);
    fflush (sfp);

    if (ftruncate (fileno (sfp), ftell (sfp)) != 0)
    {
      fprintf (stderr, "! ftruncate() failed (%d): %s\n", errno, strerror (errno));
      fclose (sfp);
      return false;
    }

    fflush (sfp);
    return true;
  }

  // restore session
  if (fscanf (sfp, "%" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 "", off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5) != 10)
  {
    fprintf (stderr, "! fscanf() failed\n");
    fclose (sfp);
    return false;
  }

  fflush (sfp);
  return true;
}

/*
void session_print (long off_fd1, long off_fd2, long off_fd3, long off_fd4, long off_fd5, size_t off_vir_in1, size_t off_vir_in2, size_t off_vir_in3, size_t off_vir_in4, size_t off_vir_in5)
{
  printf ("Session data: %" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 ",%" PRIi64 "\n", off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5);
  fflush (stdout);
}
*/

bool session_update (int64_t off_fd1, int64_t off_fd2, int64_t off_fd3, int64_t off_fd4, int64_t off_fd5, int64_t off_vir_in1, int64_t off_vir_in2, int64_t off_vir_in3, int64_t off_vir_in4, int64_t off_vir_in5)
{
  rewind (sfp);
  fprintf (sfp, "%" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 " %" PRIi64 "", off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5);
  fflush (sfp);

  if (ftruncate (fileno (sfp), ftell (sfp)) != 0)
  {
    fprintf (stderr, "! ftruncate() failed (%d): %s\n", errno, strerror (errno));
    fclose (sfp);
    return false;
  }

  fflush (sfp);
  return true;
}

void session_destroy (void)
{
  fflush (sfp);
  fclose (sfp);
}

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
  char *cur = NULL;

  for (cur = pos; cur < max; cur++)
  {
    if (*cur == '\n') break;
  }

  size_t len = (size_t) (cur - pos);

  return (len);
}

static bool add (char *ptr_out,
                 char *ptr_in1, size_t len_in1,
                 char *ptr_in2, size_t len_in2,
                 char *ptr_in3, size_t len_in3,
                 char *ptr_in4, size_t len_in4,
                 char *ptr_in5, size_t len_in5,
                 char *sepStart, size_t sepStart_len,
                 char *sep1, size_t sep1_len,
                 char *sep2, size_t sep2_len,
                 char *sep3, size_t sep3_len,
                 char *sep4, size_t sep4_len,
                 char *sepEnd, size_t sepEnd_len, bool skipRep_isSet)
{
  if (skipRep_isSet)
  {
    char *out1 = ptr_in1;
    char *out2 = ptr_in2;
    char *out3 = ptr_in3;
    char *out4 = ptr_in4;
    char *out5 = ptr_in5;

    if (len_in2 == len_in1 && memcmp (out1, out2, len_in1) == 0) return false;

    if (len_in3 == len_in2 && memcmp (out3, out2, len_in2) == 0) return false;
    if (len_in3 == len_in1 && memcmp (out3, out1, len_in1) == 0) return false;

    if (len_in4 == len_in3 && memcmp (out4, out3, len_in3) == 0) return false;
    if (len_in4 == len_in2 && memcmp (out4, out2, len_in2) == 0) return false;
    if (len_in4 == len_in1 && memcmp (out4, out1, len_in1) == 0) return false;

    if (len_in5 == len_in4 && memcmp (out5, out4, len_in4) == 0) return false;
    if (len_in5 == len_in3 && memcmp (out5, out3, len_in3) == 0) return false;
    if (len_in5 == len_in2 && memcmp (out5, out2, len_in2) == 0) return false;
    if (len_in5 == len_in1 && memcmp (out5, out1, len_in1) == 0) return false;
  }

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

  if (sep4_len != 0)
  {
    memcpy (ptr_out, sep4, sep4_len);
    ptr_out += sep4_len;
  }

  memcpy (ptr_out, ptr_in5, len_in5);
  ptr_out += len_in5;

  if (sepEnd_len != 0)
  {
    memcpy (ptr_out, sepEnd, sepEnd_len);
    ptr_out += sepEnd_len;
  }

  *ptr_out = '\n';

  return true;
}

static struct option long_options[] =
{
  {"file1",    required_argument, NULL, 0xf1},
  {"file2",    required_argument, NULL, 0xf2},
  {"file3",    required_argument, NULL, 0xf3},
  {"file4",    required_argument, NULL, 0xf4},
  {"file5",    required_argument, NULL, 0xf5},
  {"sepStart", required_argument, NULL, 0xa0},
  {"sep1",     required_argument, NULL, 0xa1},
  {"sep2",     required_argument, NULL, 0xa2},
  {"sep3",     required_argument, NULL, 0xa3},
  {"sep4",     required_argument, NULL, 0xa4},
  {"sepEnd",   required_argument, NULL, 0xaf},
  {"skip",     required_argument, NULL, 0xb0},
  {"limit",    required_argument, NULL, 0xb1},
  {"session",  required_argument, NULL, 0xb2},
  {"restore",  required_argument, NULL, 0xb3},
  {"skip-rep",       no_argument, NULL, 0xb4},
  {0, 0, 0, 0}
};

#define EXIT_WITH_RET(_ret) \
{ \
  if (fd5) fclose (fd5); \
  if (fd4) fclose (fd4); \
  if (fd3) fclose (fd3); \
  fclose (fd2); \
  fclose (fd1); \
\
  MEMORY_FREE_ALL \
  return (_ret); \
}

/**
 * add to output buffer
 */

#define ADD_TO_OUTPUT_BUFFER(buf_out,ptr_out,ptr_in1,vir_in1,ptr_in2,vir_in2,ptr_in3,vir_in3,ptr_in4,vir_in4,ptr_in5,vir_in5,sepStart,sepStart_len,sep1,sep1_len,sep2,sep2_len,sep3,sep3_len,sep4,sep4_len,sepEnd,sepEnd_len) \
{ \
  size_t len_out = (size_t) (ptr_out - buf_out); \
  size_t len_add = sepStart_len + vir_in1 + sep1_len + vir_in2 + sep2_len + vir_in3 + sep3_len + vir_in4 + sep4_len + vir_in5 + sepEnd_len + 1; \
  bool ret = false; \
\
  if ((len_out + len_add) < SEGMENT_SIZE) \
  { \
    ret = add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len, skipRep_isSet); \
    if (ret) ptr_out += len_add; \
  } \
  else \
  { \
    if (skip_isSet) \
    { \
      if (skip <= 0) \
      { \
        fwrite (buf_out, 1, len_out, stdout); \
        fflush (stdout); \
        if (session_isSet || restore_isSet) \
        { \
          if (session_update (off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5) == false) \
          { \
            EXIT_WITH_RET(-1) \
          } \
        } \
        if (limit_isSet) limit--; \
        if ((end = (limit_isSet && limit <= 0))) break; \
      } \
      else \
      { \
        skip--; \
      } \
    } \
    else \
    { \
      if (restore_isSet) \
      { \
        restore_isSet = false; \
        session_isSet = true; \
      } \
      if (!restore_isSet) \
      { \
        fwrite (buf_out, 1, len_out, stdout); \
        fflush (stdout); \
        if (session_isSet) \
        { \
          if (session_update (off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5) == false) \
          { \
            EXIT_WITH_RET(-1) \
          } \
        } \
        if (limit_isSet) limit--; \
        if ((end = (limit_isSet && limit <= 0))) break; \
      } \
    } \
    ptr_out = buf_out; \
    ret = add (ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len, skipRep_isSet); \
    if (ret) ptr_out += len_add; \
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
    "  --file5    | Path        | Set file5 path                        | optional    | --file5 wordlist5.txt\n" \
    "\n" \
    "  --sepStart | Char/String | Set char/string at the beginning      | optional    | --sepStart '['\n" \
    "  --sep1     | Char/String | Set separator between file1 and file2 | optional    | --sep1 'a.'\n" \
    "  --sep2     | Char/String | Set separator between file2 and file3 | optional    | --sep2 'bc'\n" \
    "  --sep3     | Char/String | Set separator between file3 and file4 | optional    | --sep3 ',d'\n" \
    "  --sep4     | Char/String | Set separator between file4 and file5 | optional    | --sep4 'e.'\n" \
    "  --sepEnd   | Char/String | Set char/string at the end            | optional    | --sepEnd ']'\n" \
    "\n" \
    "  --skip     | Num         | Skip N segments                       | optional    | --skip 0\n" \
    "  --limit    | Num         | Exit after N segments                 | optional    | --limit 1\n" \
    "  --skip-rep |             | Skip sentences with repeated words    | optional    | --skip-rep\n" \
    "\n" \
    "  --session  | String      | Set session name                      | optional    | --session testSession\n" \
    "  --restore  | String      | Restore by session name               | optional    | --restore testSession\n" \
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
  int set = 0;

  char **freeList = malloc (17 * sizeof(char *));
  int freeListIdx = 0;

  char *f1 = NULL, *f2 = NULL, *f3 = NULL, *f4 = NULL, *f5 = NULL;
  char *sepStart = NULL, *sep1 = NULL, *sep2 = NULL, *sep3 = NULL, *sep4 = NULL, *sepEnd = NULL;
  size_t sepStart_len = 0, sep1_len = 0, sep2_len = 0, sep3_len = 0, sep4_len = 0, sepEnd_len = 0;

  unsigned long skip = 0;
  long limit = 0;
  bool limit_isSet = false;
  bool skip_isSet = false;
  bool session_isSet = false;
  bool restore_isSet = false;
  bool skipRep_isSet = false;

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

      case 0xa4:
        sep4_len = strlen(optarg);
        sep4 = strdup(optarg);

        MEMORY_FREE_ADD(sep4)
        break;

      case 0xaf:
        sepEnd_len = strlen(optarg);
        sepEnd = strdup(optarg);

        MEMORY_FREE_ADD(sepEnd)
        break;

      case 0xf1:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { set++; f1 = strdup (optarg); MEMORY_FREE_ADD(f1) }
        else err++;
        break;

      case 0xf2:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { set++; f2 = strdup (optarg); MEMORY_FREE_ADD(f2) }
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

      case 0xf5:
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { f5 = strdup (optarg); MEMORY_FREE_ADD(f5) }
        else err++;
        break;

      case 0xb0:
        skip_isSet = true;
        skip = strtoul (optarg, NULL, 10);
        break;

      case 0xb1:
        limit_isSet = true;
        limit = (long) strtoul (optarg, NULL, 10);
        if (limit <= 0) err++;
        break;

      case 0xb2:
        session_isSet = true;
        if (strlen (optarg) > 0)
        {
          if (access (optarg, R_OK) != 0)
          {
            sessionName = strdup (optarg);
            MEMORY_FREE_ADD(sessionName)
          }
          else
          {
            fprintf (stderr, "! session file already exists\n");
            err++;
          }
        }
        else
        {
          err++;
        }
        break;

      case 0xb3:
	restore_isSet = true;
        if (strlen (optarg) > 0)
        {
          if (access (optarg, R_OK) == 0)
          {
            sessionName = strdup (optarg);
            MEMORY_FREE_ADD(sessionName)
          }
          else
          {
            fprintf (stderr, "! session file does not exist\n");
            err++;
          }
        }
        else
        {
          err++;
        }
        break;

      case 0xb4:
        skipRep_isSet = true;
        break;

      default:
        err++;
        break;
    }
  }

  if (err > 0 || set != 2)
  {
    fprintf (stderr, "! %d error(s) found ...\n", err);
    usage (argv[0]);

    MEMORY_FREE_ALL

    return -1;
  }

  if (f3 == NULL)
  {
    if (sep3 || sep4)
    {
      fprintf (stderr, "! Cannot set --sep3 or --sep4 if file3 is not set ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (f4 || f5)
    {
      fprintf (stderr, "! Cannot set --file4 or --file5 if file3 is not set ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }
  }

  if (!strcmp (f1, f2))
  {
    fprintf (stderr, "! Cannot use the same file as input (f1 vs f2) ...\n");
    usage(argv[0]);

    MEMORY_FREE_ALL

    return -1;
  }

  if (f3 != NULL)
  {
    if (!strcmp (f1, f3))
    {
      fprintf (stderr, "! Cannot use the same file as input (f1 vs f3) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f2, f3))
    {
      fprintf (stderr, "! Cannot use the same file as input (f2 vs f3) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }
  }

  if (f4 != NULL)
  {
    if (!strcmp (f1, f4))
    {
      fprintf (stderr, "! Cannot use the same file as input (f1 vs f4) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f2, f4))
    {
      fprintf (stderr, "! Cannot use the same file as input (f2 vs f4) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f3, f4))
    {
      fprintf (stderr, "! Cannot use the same file as input (f3 vs f4) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }
  }

  if (f5 != NULL)
  {
    if (!strcmp (f1, f5))
    {
      fprintf (stderr, "! Cannot use the same file as input (f1 vs f5) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f2, f5))
    {
      fprintf (stderr, "! Cannot use the same file as input (f2 vs f5) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f3, f5))
    {
      fprintf (stderr, "! Cannot use the same file as input (f3 vs f5) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }

    if (!strcmp (f4, f5))
    {
      fprintf (stderr, "! Cannot use the same file as input (f4 vs f5) ...\n");
      usage(argv[0]);

      MEMORY_FREE_ALL

      return -1;
    }
  }

  if (session_isSet && restore_isSet)
  {
    fprintf (stderr, "! Cannot use --session and --restore together ...\n");
    usage(argv[0]);

    MEMORY_FREE_ALL

    return -1;
  }

  // setup signal handler if session/restore is enabled
  if (sessionName != NULL)
  {
    signal (SIGINT, sigHandler);
  }

  size_t sz_buf = SEGMENT_SIZE + SEGMENT_ALIGN;

  char *buf_in1 = (char *) malloc (sz_buf);
  char *buf_in2 = (char *) malloc (sz_buf);
  char *buf_in3 = NULL;
  char *buf_in4 = NULL;
  char *buf_in5 = NULL;

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
  if (f5 != NULL)
  {
    buf_in5 = (char *) malloc (sz_buf);

    MEMORY_FREE_ADD (buf_in5)
  }

  char *buf_out = (char *) malloc (sz_buf);

  MEMORY_FREE_ADD (buf_out)

  char *ptr_out = buf_out;

  FILE *fd1 = NULL;
  FILE *fd2 = NULL;
  FILE *fd3 = NULL;
  FILE *fd4 = NULL;
  FILE *fd5 = NULL;

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

  if (f5 && (fd5 = fopen (f5, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f5, strerror (errno));

    fclose (fd1);
    fclose (fd2);
    fclose (fd3);
    fclose (fd4);

    MEMORY_FREE_ALL

    return (-1);
  }

  char *ptr_in1 = NULL;
  char *ptr_in2 = NULL;
  char *ptr_in3 = NULL;
  char *ptr_in4 = NULL;
  char *ptr_in5 = NULL;

  size_t vir_in1 = 0;
  size_t vir_in2 = 0;
  size_t vir_in3 = 0;
  size_t vir_in4 = 0;
  size_t vir_in5 = 0;

  // session/restore
  int64_t off_fd1 = 0;
  int64_t off_fd2 = 0;
  int64_t off_fd3 = 0;
  int64_t off_fd4 = 0;
  int64_t off_fd5 = 0;

  int64_t off_vir_in1 = 0, off_vir_in1_init = -1;
  int64_t off_vir_in2 = 0, off_vir_in2_init = -1;
  int64_t off_vir_in3 = 0, off_vir_in3_init = -1;
  int64_t off_vir_in4 = 0, off_vir_in4_init = -1;
  int64_t off_vir_in5 = 0, off_vir_in5_init = -1;

  if (session_isSet || restore_isSet)
  {
    if (session_init (restore_isSet, &off_fd1, &off_fd2, &off_fd3, &off_fd4, &off_fd5, &off_vir_in1, &off_vir_in2, &off_vir_in3, &off_vir_in4, &off_vir_in5) == false)
    {
      if (fd5) fclose (fd5);
      if (fd4) fclose (fd4);
      if (fd3) fclose (fd3);
      fclose (fd2);
      fclose (fd1);

      MEMORY_FREE_ALL

      return (-1);
    }

    //session_print (off_fd1, off_fd2, off_fd3, off_fd4, off_fd5, off_vir_in1, off_vir_in2, off_vir_in3, off_vir_in4, off_vir_in5);

    if (restore_isSet)
    {
      // set restore point
      off_vir_in1_init = off_vir_in1;
      off_vir_in2_init = off_vir_in2;
      off_vir_in3_init = off_vir_in3;
      off_vir_in4_init = off_vir_in4;
      off_vir_in5_init = off_vir_in5;

      // initial set fd* file offsets
      if (off_fd1 > 0) fseek (fd1, off_fd1, SEEK_SET);
      if (off_fd2 > 0) fseek (fd2, off_fd2, SEEK_SET);
      if (off_fd3 > 0) fseek (fd3, off_fd3, SEEK_SET);
      if (off_fd4 > 0) fseek (fd4, off_fd4, SEEK_SET);
      if (off_fd5 > 0) fseek (fd5, off_fd5, SEEK_SET);

      // reset main counters
      off_fd1 = off_fd2 = off_fd3 = off_fd4 = off_fd5 = 0;
      off_vir_in1 = off_vir_in2 = off_vir_in3 = off_vir_in4 = off_vir_in5 = 0;
    }
  }

  while (!feof (fd1) && !end)
  {
    off_fd1 = ftell (fd1);

    size_t real_sz1 = read_segment (buf_in1, fd1);
    size_t len_in1 = 0;
    char *max_in1 = buf_in1 + real_sz1;

    for (ptr_in1 = buf_in1; ptr_in1 < max_in1 && !end; ptr_in1 += len_in1 + 1)
    {
      len_in1 = get_line_len (ptr_in1, max_in1);
      vir_in1 = len_in1;

      while (vir_in1)
      {
        if (ptr_in1[vir_in1 - 1] != '\r') break;
        vir_in1--;
      }

      if (vir_in1 > LEN_MAX) continue;

      // restore 1 if needed
      off_vir_in1 += vir_in1;
      if (restore_isSet && off_vir_in1_init >= 0 && off_vir_in1 < off_vir_in1_init) continue;
      off_vir_in1_init = -1;

      while (!feof (fd2) && !end)
      {
        off_fd2 = ftell (fd2);

        size_t real_sz2 = read_segment (buf_in2, fd2);
        size_t len_in2 = 0;
        char *max_in2 = buf_in2 + real_sz2;

        for (ptr_in2 = buf_in2; ptr_in2 < max_in2 && !end; ptr_in2 += len_in2 + 1)
        {
          len_in2 = get_line_len (ptr_in2, max_in2);
          vir_in2 = len_in2;

          while (vir_in2)
          {
            if (ptr_in2[vir_in2 - 1] != '\r') break;
            vir_in2--;
          }

          if (vir_in2 > LEN_MAX) continue;

          // restore 2 if needed
          off_vir_in2 += vir_in2;
          if (restore_isSet && off_vir_in2_init >= 0 && off_vir_in2 < off_vir_in2_init) continue;
          off_vir_in2_init = -1;

          if (buf_in3)
          {
            while (!feof (fd3) && !end)
            {
              off_fd3 = ftell (fd3);

              size_t real_sz3 = read_segment (buf_in3, fd3);
              size_t len_in3 = 0;
              char *max_in3 = buf_in3 + real_sz3;

              for (ptr_in3 = buf_in3; ptr_in3 < max_in3 && !end; ptr_in3 += len_in3 + 1)
              {
                len_in3 = get_line_len (ptr_in3, max_in3);
                vir_in3 = len_in3;

                while (vir_in3)
                {
                  if (ptr_in3[vir_in3 - 1] != '\r') break;
                  vir_in3--;
                }

                if (vir_in3 > LEN_MAX) continue;

                // restore 3 if needed
                off_vir_in3 += vir_in3;
                if (restore_isSet && off_vir_in3_init >= 0 && off_vir_in3 < off_vir_in3_init) continue;
                off_vir_in3_init = -1;

                if (buf_in4)
                {
                  while (!feof (fd4) && !end)
                  {
                    off_fd4 = ftell (fd4);

                    size_t real_sz4 = read_segment (buf_in4, fd4);
                    size_t len_in4 = 0;
                    char *max_in4 = buf_in4 + real_sz4;

                    for (ptr_in4 = buf_in4; ptr_in4 < max_in4 && !end; ptr_in4 += len_in4 + 1)
                    {
                      len_in4 = get_line_len (ptr_in4, max_in4);
                      vir_in4 = len_in4;

                      while (vir_in4)
                      {
                        if (ptr_in4[vir_in4 - 1] != '\r') break;
                        vir_in4--;
                      }

                      if (vir_in4 > LEN_MAX) continue;

                      // restore 4 if needed
                      off_vir_in4 += vir_in4;
                      if (restore_isSet && off_vir_in4_init >= 0 && off_vir_in4 < off_vir_in4_init) continue;
                      off_vir_in4_init = -1;

                      if (buf_in5)
                      {
                        while (!feof (fd5) && !end)
                        {
                          off_fd5 = ftell (fd5);

                          size_t real_sz5 = read_segment (buf_in5, fd5);
                          size_t len_in5 = 0;
                          char *max_in5 = buf_in5 + real_sz5;

                          for (ptr_in5 = buf_in5; ptr_in5 < max_in5 && !end; ptr_in5 += len_in5 + 1)
                          {
                            len_in5 = get_line_len (ptr_in5, max_in5);
                            vir_in5 = len_in5;

                            while (vir_in5)
                            {
                              if (ptr_in5[vir_in5 - 1] != '\r') break;
                              vir_in5--;
                            }

                            if (vir_in5 > LEN_MAX) continue;

                            // restore 5 if needed
                            off_vir_in5 += vir_in5;
                            if (restore_isSet && off_vir_in5_init >= 0 && off_vir_in5 < off_vir_in5_init) continue;
                            off_vir_in5_init = -1;

                            ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len)
                          }
                        }
                        rewind (fd5);

                        // reset cnt 5
                        off_vir_in5 = 0;
                      }
                      else
                      {
                        ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len)
                      }
                    }
                  }
                  rewind (fd4);

                  // reset cnt 4
                  off_vir_in4 = 0;
                }
                else
                {
                  ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len)
                }
              }
            }
            rewind (fd3);

            // reset cnt 3
            off_vir_in3 = 0;
          }
          else
          {
            ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in1, vir_in1, ptr_in2, vir_in2, ptr_in3, vir_in3, ptr_in4, vir_in4, ptr_in5, vir_in5, sepStart, sepStart_len, sep1, sep1_len, sep2, sep2_len, sep3, sep3_len, sep4, sep4_len, sepEnd, sepEnd_len)
          }
        }
      }
      rewind (fd2);

      // reset cnt 3
      off_vir_in2 = 0;
    }
  }

  if (!end)
  {
    size_t len_out = (size_t) (ptr_out - buf_out);

    fwrite (buf_out, 1, len_out, stdout);
  }

  EXIT_WITH_RET(0)
}
