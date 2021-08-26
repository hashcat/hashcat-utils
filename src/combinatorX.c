/**
 * Name........: combinatorX
 * Author......: Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 * Version.....: 1.2
 * Date........: Wed Aug 25 19:42:17 CEST 2021
 * License.....: MIT
 *
 * Enhanced version of unix-ninja 'combinator3'
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

#define PROG_VERSION "1.2"
#define PROG_RELEASE_DATE "Wed Aug 25 19:42:17 CEST 2021"

#define WORD_MAX_LEN  64
#define SEGMENT_SIZE  (WORD_MAX_LEN * 1024 * 1024)
#define SEGMENT_ALIGN (8 * 1024)

// lightweight dolphin macro
#define MEMORY_FREE_ADD(a) { freeList[freeListIdx++] = (void *)(a); }
#define MEMORY_FREE_ALL    { int t=freeListIdx; while (t-- > 0) if (freeList[t]!=NULL) { free (freeList[t]); freeList[t]=NULL; } if (freeList!=NULL) { free (freeList); freeList=NULL; } }
#define MEMORY_FREE_DEL(a) { for (int t=0;t<freeListIdx;t++) { if(freeList[t] && a==freeList[t]) { free(freeList[t]); freeList[t]=NULL; break; } } }

#ifdef DEBUG
static bool debug = false;
#endif

static bool end = false;
static bool end2 = false;

typedef struct cx_session
{
  FILE *sfp[3];
  char *f[8];
  FILE *fp[8];
  char *sep[7];
  uint64_t sep_len[7];
  char *sepStart;
  uint64_t sepStart_len;
  char *sepEnd;
  uint64_t sepEnd_len;
  int64_t off_fd[8];
  int64_t off_vir_in[8];
  uint64_t cur_rep[8];
  uint64_t lines[8];
  char *sessionName;
  char *sessionFiles;
  char *sessionSeparators;
  uint64_t skip, limit, max_skip, max_files;
  uint64_t maxRep;
  uint64_t maxLen;

} cx_session_t;

static char **freeList;
static int freeListIdx;
static cx_session_t main_ctx;

static uint8_t hex_convert (const uint8_t c)
{
  return (c & 15) + (c >> 6) * 9;
}

static uint8_t hex_to_u8 (const uint8_t hex[2])
{
  uint8_t v = 0;

  v |= ((uint8_t) hex_convert (hex[1]) << 0);
  v |= ((uint8_t) hex_convert (hex[0]) << 4);

  return (v);
}

static void u8_to_hex (const uint8_t v, uint8_t hex[2])
{
  const uint8_t tbl[0x10] =
  {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f',
  };

  hex[1] = tbl[v >>  0 & 15];
  hex[0] = tbl[v >>  4 & 15];
}

static uint64_t hex_decode (const uint8_t *in_buf, const uint64_t in_len, uint8_t *out_buf)
{
  for (uint64_t i = 0, j = 0; i < in_len; i += 2, j += 1)
  {
    out_buf[j] = hex_to_u8 (&in_buf[i]);
  }

  return in_len / 2;
}

static uint64_t hex_encode (const uint8_t *in_buf, const uint64_t in_len, uint8_t *out_buf)
{
  for (uint64_t i = 0, j = 0; i < in_len; i += 1, j += 2)
  {
    u8_to_hex (in_buf[i], &out_buf[j]);
  }

  return in_len * 2;
}

static void sigHandler (int sig)
{
  signal (sig, SIG_IGN);
  fprintf (stderr, "\nWaiting checkpoint to save session in '%s'. Use '--restore %s' to restore\n", main_ctx.sessionName, main_ctx.sessionName);
  sleep (2);
  end = true;
}

static bool session_init (bool session, bool restore)
{
  char *mode = (restore) ? "r+" : "w+";

  if (restore || session)
  {
    // session files
    unsigned int tmp_sf_maxLen;
    char tmp_sf[256];

    // .files
    tmp_sf_maxLen = sizeof (tmp_sf) - 1 - 7;
    if (strlen (main_ctx.sessionName) + 7 > tmp_sf_maxLen)
    {
      fprintf (stderr, "! Too long session name ...\n");
      return false;
    }

    if (!(main_ctx.sfp[0] = fopen (main_ctx.sessionName, mode)))
    {
      fprintf (stderr, "! fopen(%s) failed (%d): %s\n", main_ctx.sessionName, errno, strerror (errno));
      return false;
    }

    rewind (main_ctx.sfp[0]);

    // .files
    memset   (tmp_sf, 0, sizeof (tmp_sf));
    snprintf (tmp_sf, tmp_sf_maxLen, "%s.files", main_ctx.sessionName);

    main_ctx.sessionFiles = strdup (tmp_sf);
    MEMORY_FREE_ADD(main_ctx.sessionFiles)

    // .seps
    tmp_sf_maxLen++;
    memset   (tmp_sf, 0, sizeof (tmp_sf));
    snprintf (tmp_sf, tmp_sf_maxLen, "%s.seps", main_ctx.sessionName);

    main_ctx.sessionSeparators = strdup (tmp_sf);
    MEMORY_FREE_ADD(main_ctx.sessionSeparators)

    #ifdef DEBUG
    if (debug)
    {
      fprintf (stderr, "sessionFiles: %s\n", main_ctx.sessionFiles);
    }
    #endif

    if (!(main_ctx.sfp[1] = fopen (main_ctx.sessionFiles, mode)))
    {
      fprintf (stderr, "! fopen(%s) failed (%d): %s\n", main_ctx.sessionFiles, errno, strerror (errno));
      fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
      return false;
    }

    #ifdef DEBUG
    if (debug)
    {
      fprintf (stderr, "SessionFiles opened (mode: %s): %s\n", (restore) ? "restore" : "new", main_ctx.sessionFiles);
    }
    #endif

    if (!(main_ctx.sfp[2] = fopen (main_ctx.sessionSeparators, mode)))
    {
      fprintf (stderr, "! fopen(%s) failed (%d): %s\n", main_ctx.sessionSeparators, errno, strerror (errno));
      fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
      fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
      return false;
    }

    #ifdef DEBUG
    if (debug)
    {
      fprintf (stderr, "SessionSeps opened (mode: %s): %s\n", (restore) ? "restore" : "new", main_ctx.sessionSeparators);
    }
    #endif
  }

  if (!restore)
  {
    for (int i = 0; i < 8; i++) main_ctx.off_fd[i] = 0;
    for (int i = 0; i < 8; i++) main_ctx.off_vir_in[i] = 0;

    if (session)
    {
      fprintf (main_ctx.sfp[0], "%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "",
               main_ctx.off_fd[0], main_ctx.off_fd[1], main_ctx.off_fd[2], main_ctx.off_fd[3], main_ctx.off_fd[4], main_ctx.off_fd[5], main_ctx.off_fd[6], main_ctx.off_fd[7],
               main_ctx.skip, main_ctx.limit, main_ctx.maxRep, main_ctx.maxLen,
               main_ctx.off_vir_in[0], main_ctx.off_vir_in[1], main_ctx.off_vir_in[2], main_ctx.off_vir_in[3], main_ctx.off_vir_in[4], main_ctx.off_vir_in[5], main_ctx.off_vir_in[6], main_ctx.off_vir_in[7]);

      fflush (main_ctx.sfp[0]);

      if (ftruncate (fileno (main_ctx.sfp[0]), ftell (main_ctx.sfp[0])) != 0)
      {
        fprintf (stderr, "! ftruncate() failed (%d): %s\n", errno, strerror (errno));
        fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
        fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
        fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
        return false;
      }

      fflush (main_ctx.sfp[0]);

      fprintf (main_ctx.sfp[1], "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", main_ctx.f[0], main_ctx.f[1], main_ctx.f[2], main_ctx.f[3], main_ctx.f[4], main_ctx.f[5], main_ctx.f[6], main_ctx.f[7]);

      fflush (main_ctx.sfp[1]);
      fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
      MEMORY_FREE_DEL(main_ctx.sessionFiles)

      char f_sep[9][512];
      memset (f_sep, 0, sizeof (f_sep));

      for (int i = 0; i < 9; i++)
      {
        if (i == 0)
        {
          if (main_ctx.sepStart != NULL) hex_encode ((uint8_t *)main_ctx.sepStart, strlen(main_ctx.sepStart), (uint8_t *)f_sep[i]);
        }
        else if (i == 8)
        {
          if (main_ctx.sepEnd != NULL) hex_encode ((uint8_t *)main_ctx.sepEnd, strlen(main_ctx.sepEnd), (uint8_t *)f_sep[i]);
        }
        else
        {
          int sepId = i - 1;
          if (main_ctx.sep[sepId] != NULL) hex_encode ((uint8_t *)main_ctx.sep[sepId], strlen(main_ctx.sep[sepId]), (uint8_t *)f_sep[i]);
        }

        #ifdef DEBUG
        if (debug) fprintf (stderr, "Encoded separator %d: %s\n", i, f_sep[i]);
        #endif
      }

      fprintf (main_ctx.sfp[2], "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
               (strlen(f_sep[0]) > 0) ? f_sep[0] : NULL,
               (strlen(f_sep[1]) > 0) ? f_sep[1] : NULL,
               (strlen(f_sep[2]) > 0) ? f_sep[2] : NULL,
               (strlen(f_sep[3]) > 0) ? f_sep[3] : NULL,
               (strlen(f_sep[4]) > 0) ? f_sep[4] : NULL,
               (strlen(f_sep[5]) > 0) ? f_sep[5] : NULL,
               (strlen(f_sep[6]) > 0) ? f_sep[6] : NULL,
               (strlen(f_sep[7]) > 0) ? f_sep[7] : NULL,
               (strlen(f_sep[8]) > 0) ? f_sep[8] : NULL
      );

      fflush (main_ctx.sfp[2]);
      fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
      MEMORY_FREE_DEL(main_ctx.sessionSeparators)
    }

    return true;
  }
  else
  {
    if (fseek (main_ctx.sfp[0], 0L, SEEK_END) != 0)
    {
      fprintf (stderr, "! fseek() failed (%d): %s\n", errno, strerror (errno));
      fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
      fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
      fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
      return false;
    }

    int64_t s = ftell (main_ctx.sfp[0]);
    if (s > 3)
    {
      s -= 3;
      if (fseek (main_ctx.sfp[0], s, SEEK_SET) != 0)
      {
        fprintf (stderr, "! fseek() failed (%d): %s\n", errno, strerror (errno));
        fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
        fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
        fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
        return false;
      }
      char buf[4] = { 0 };
      fread (buf, 3, 1, main_ctx.sfp[0]);
      if (!strcmp(buf, "end"))
      {
        fprintf (stdout, "This session has already ended.\n");
        fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
        fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
        fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
        return false;
      }
    }
    rewind (main_ctx.sfp[0]);
  }

  int fscanf_ret = 0;

  char f_tmp[8][256];

  memset (f_tmp, 0, sizeof (f_tmp));

  fscanf_ret = fscanf (main_ctx.sfp[1], "%255s\n%255s\n%255s\n%255s\n%255s\n%255s\n%255s\n%255s\n", f_tmp[0], f_tmp[1], f_tmp[2], f_tmp[3], f_tmp[4], f_tmp[5], f_tmp[6], f_tmp[7]);
  if (fscanf_ret != 8)
  {
    fprintf (stderr, "! fscanf(sessionFiles) failed: %d/8\n", fscanf_ret);
    fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
    fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;
    fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
    return false;
  }

  fclose (main_ctx.sfp[1]); main_ctx.sfp[1] = NULL;

  for (int i = 0; i < 8; i++)
  {
    if (main_ctx.f[i]) MEMORY_FREE_DEL(main_ctx.f[i])

    if (f_tmp[i] == NULL || !strcmp(f_tmp[i], "(null)")) continue;

    main_ctx.f[i] = strdup (f_tmp[i]);
    MEMORY_FREE_ADD(main_ctx.f[i])
  }

  char f_sep[9][512];
  memset (f_sep, 0, sizeof (f_sep));

  fscanf_ret = fscanf (main_ctx.sfp[2], "%511s\n%511s\n%511s\n%511s\n%511s\n%511s\n%511s\n%511s\n%511s\n", f_sep[0], f_sep[1], f_sep[2], f_sep[3], f_sep[4], f_sep[5], f_sep[6], f_sep[7], f_sep[8]);
  for (int i = 0; i < 9; i++) fprintf (stderr, "sep[%d] = '%s'\n", i, f_sep[i]);

  if (fscanf_ret != 9)
  {
    fprintf (stderr, "! fscanf(sessionSeparators) failed: %d/9\n", fscanf_ret);
    fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
    fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;
    return false;
  }

  fclose (main_ctx.sfp[2]); main_ctx.sfp[2] = NULL;

  char f_sep_tmp[256];

  for (int i = 0; i < 9; i++)
  {
    memset (f_sep_tmp, 0, sizeof (f_sep_tmp));

    if (i == 0)
    {
      if (main_ctx.sepStart) MEMORY_FREE_DEL(main_ctx.sepStart)

      if (f_sep[i] == NULL || !strcmp(f_sep[i], "(null)")) continue;

      hex_decode ((uint8_t *)f_sep[i], strlen(f_sep[i]), (uint8_t *)f_sep_tmp);

      #ifdef DEBUG
      if (debug) fprintf (stderr, "Restore sepStart: '%s'\n", f_sep_tmp);
      #endif

      main_ctx.sepStart = strdup (f_sep_tmp);
      MEMORY_FREE_ADD(main_ctx.sepStart)
      main_ctx.sepStart_len = strlen(main_ctx.sepStart);
    }
    else if (i == 8)
    {
      if (main_ctx.sepEnd) MEMORY_FREE_DEL(main_ctx.sepEnd);

      if (f_sep[i] == NULL || !strcmp(f_sep[i], "(null)")) continue;

      hex_decode ((uint8_t *)f_sep[i], strlen(f_sep[i]), (uint8_t *)f_sep_tmp);

      #ifdef DEBUG
      if (debug) fprintf (stderr, "Restore sepEnd: '%s'\n", f_sep_tmp);
      #endif

      main_ctx.sepEnd = strdup (f_sep_tmp);
      MEMORY_FREE_ADD(main_ctx.sepEnd)
      main_ctx.sepEnd_len = strlen(main_ctx.sepEnd);
    }
    else
    {
      int sepId = i - 1;
      if (main_ctx.sep[sepId]) MEMORY_FREE_DEL(main_ctx.sep[sepId]);

      if (f_sep[i] == NULL || !strcmp(f_sep[i], "(null)")) continue;

      hex_decode ((uint8_t *)f_sep[i], strlen(f_sep[i]), (uint8_t *)f_sep_tmp);

      #ifdef DEBUG
      if (debug) fprintf (stderr, "Restore sep %d/%d: '%s'\n", sepId, i, f_sep_tmp);
      #endif

      main_ctx.sep[sepId] = strdup (f_sep_tmp);
      MEMORY_FREE_ADD(main_ctx.sep[sepId])
      main_ctx.sep_len[sepId] = strlen(main_ctx.sep[sepId]);
    }
  }

  // restore sessionData
  if (fscanf (main_ctx.sfp[0], "%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "",
              &main_ctx.off_fd[0], &main_ctx.off_fd[1], &main_ctx.off_fd[2], &main_ctx.off_fd[3], &main_ctx.off_fd[4], &main_ctx.off_fd[5], &main_ctx.off_fd[6], &main_ctx.off_fd[7],
              &main_ctx.skip, &main_ctx.limit, &main_ctx.maxRep, &main_ctx.maxLen,
              &main_ctx.off_vir_in[0], &main_ctx.off_vir_in[1], &main_ctx.off_vir_in[2], &main_ctx.off_vir_in[3], &main_ctx.off_vir_in[4], &main_ctx.off_vir_in[5], &main_ctx.off_vir_in[6], &main_ctx.off_vir_in[7]) != 20)
  {
    fprintf (stderr, "! fscanf(sessionData) failed\n");
    fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
    return false;
  }

  fflush (main_ctx.sfp[0]);

  return true;
}

#ifdef DEBUG
static void session_print (void)
{
  fprintf (stderr, "Session files: %s, %s, %s, %s, %s, %s, %s, %s\n", main_ctx.f[0], main_ctx.f[1], main_ctx.f[2], main_ctx.f[3], main_ctx.f[4], main_ctx.f[5], main_ctx.f[6], main_ctx.f[7]);
  fprintf (stderr, "Session data: %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
          main_ctx.off_fd[0], main_ctx.off_fd[1], main_ctx.off_fd[2], main_ctx.off_fd[3], main_ctx.off_fd[4], main_ctx.off_fd[5], main_ctx.off_fd[6], main_ctx.off_fd[7],
          main_ctx.skip, main_ctx.limit, main_ctx.maxRep, main_ctx.maxLen,
          main_ctx.off_vir_in[0], main_ctx.off_vir_in[1], main_ctx.off_vir_in[2], main_ctx.off_vir_in[3], main_ctx.off_vir_in[4], main_ctx.off_vir_in[5], main_ctx.off_vir_in[6], main_ctx.off_vir_in[7]);
}
#endif

static bool session_update (void)
{
  rewind (main_ctx.sfp[0]);

  #ifdef DEBUG
  if (debug)
  {
    session_print ();
  }
  #endif

  fprintf (main_ctx.sfp[0], "%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "",
           main_ctx.off_fd[0], main_ctx.off_fd[1], main_ctx.off_fd[2], main_ctx.off_fd[3], main_ctx.off_fd[4], main_ctx.off_fd[5], main_ctx.off_fd[6], main_ctx.off_fd[7],
           main_ctx.skip, main_ctx.limit, main_ctx.maxRep, main_ctx.maxLen,
           main_ctx.off_vir_in[0], main_ctx.off_vir_in[1], main_ctx.off_vir_in[2], main_ctx.off_vir_in[3], main_ctx.off_vir_in[4], main_ctx.off_vir_in[5], main_ctx.off_vir_in[6], main_ctx.off_vir_in[7]);

  fflush (main_ctx.sfp[0]);

  if (ftruncate (fileno (main_ctx.sfp[0]), ftell (main_ctx.sfp[0])) != 0)
  {
    fprintf (stderr, "! ftruncate() failed (%d): %s\n", errno, strerror (errno));
    fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;
    return false;
  }

  return true;
}

static void session_destroy (bool setEnd)
{
  if (setEnd) fprintf (main_ctx.sfp[0], " end");

  fflush (main_ctx.sfp[0]);
  fclose (main_ctx.sfp[0]); main_ctx.sfp[0] = NULL;

  main_ctx.sfp[0] = NULL;
  main_ctx.sfp[1] = NULL;

  #ifdef DEBUG
  if (debug)
  {
    fprintf (stderr, "Session closed.\n");
  }
  #endif
}

static uint64_t read_segment (char *buf, FILE *fd)
{
  uint64_t read_sz = SEGMENT_SIZE - SEGMENT_ALIGN;
  uint64_t real_sz = (uint64_t) fread (buf, 1, read_sz, fd);

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

  for (uint64_t extra = 0; extra < SEGMENT_ALIGN; extra++)
  {
    if (fread (buf + real_sz, 1, 1, fd) == 0) break;

    real_sz++;

    if (buf[real_sz - 1] == '\n') break;
  }

  return (real_sz);
}

static uint64_t get_line_len (char *pos, char *max)
{
  char *cur = NULL;

  for (cur = pos; cur < max; cur++)
  {
    if (*cur == '\n') break;
  }

  uint64_t len = (uint64_t) (cur - pos);

  return (len);
}

static bool add (char *ptr_out,
                 char *ptr_in[8], uint64_t len_in[8],
                 char *sepStart, uint64_t sepStart_len,
                 char *sep[7], uint64_t sep_len[7],
                 char *sepEnd, uint64_t sepEnd_len)
{
  if (sepStart_len != 0)
  {
    memcpy (ptr_out, sepStart, sepStart_len);
    ptr_out += sepStart_len;
  }

  for (int i = 0; i < 8; i++)
  {
    memcpy (ptr_out, ptr_in[i], len_in[i]);
    ptr_out += len_in[i];

    if (i == 8-1) break;

    if (sep_len[i] != 0)
    {
      memcpy (ptr_out, sep[i], sep_len[i]);
      ptr_out += sep_len[i];
    }
  }

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
  {"help",           no_argument, 0, 'h'},
  {"version",        no_argument, 0, 'v'},
  {"file1",    required_argument, 0, '1'},
  {"file2",    required_argument, 0, '2'},
  {"file3",    required_argument, 0, '3'},
  {"file4",    required_argument, 0, '4'},
  {"file5",    required_argument, 0, '5'},
  {"file6",    required_argument, 0, '6'},
  {"file7",    required_argument, 0, '7'},
  {"file8",    required_argument, 0, '8'},
  {"sepStart", required_argument, 0, 0xa0},
  {"sep1",     required_argument, 0, 0xa1},
  {"sep2",     required_argument, 0, 0xa2},
  {"sep3",     required_argument, 0, 0xa3},
  {"sep4",     required_argument, 0, 0xa4},
  {"sep5",     required_argument, 0, 0xa5},
  {"sep6",     required_argument, 0, 0xa6},
  {"sep7",     required_argument, 0, 0xa7},
  {"sepEnd",   required_argument, 0, 0xaf},
  {"sepFill",  required_argument, 0, 0xb0},
  {"skip",     required_argument, 0, 'S'},
  {"limit",    required_argument, 0, 'L'},
  {"session",  required_argument, 0, 's'},
  {"restore",  required_argument, 0, 'r'},
  {"max-rep",  required_argument, 0, 'm'},
  {"max-len",  required_argument, 0, 'l'},
#ifdef DEBUG
  {"debug",          no_argument, 0, 'd'},
#endif
  {0, 0, 0, 0}
};

#ifdef DEBUG
static const char *short_options = "1:2:3:4:5:6:7:8:S:L:s:r:m:l:hvd";
#else
static const char *short_options = "1:2:3:4:5:6:7:8:S:L:s:r:m:l:hv";
#endif

#define EXIT_WITH_RET(_ret) \
{ \
  if (main_ctx.sfp[0] != NULL) fclose (main_ctx.sfp[0]); \
\
  if (main_ctx.fp[0] != NULL) fclose (main_ctx.fp[0]); \
  if (main_ctx.fp[1] != NULL) fclose (main_ctx.fp[1]); \
  if (main_ctx.fp[2] != NULL) fclose (main_ctx.fp[2]); \
  if (main_ctx.fp[3] != NULL) fclose (main_ctx.fp[3]); \
  if (main_ctx.fp[4] != NULL) fclose (main_ctx.fp[4]); \
  if (main_ctx.fp[5] != NULL) fclose (main_ctx.fp[5]); \
  if (main_ctx.fp[6] != NULL) fclose (main_ctx.fp[6]); \
  if (main_ctx.fp[7] != NULL) fclose (main_ctx.fp[7]); \
\
  MEMORY_FREE_ALL \
  return (_ret); \
}

/**
 * add to output buffer
 */

#define ADD_TO_OUTPUT_BUFFER(buf_out,ptr_out,ptr_in,vir_in,sepStart,sepStart_len,sep,sep_len,sepEnd,sepEnd_len) \
{ \
  uint64_t len_out = (uint64_t) (ptr_out - buf_out); \
  uint64_t len_add = sepStart_len + vir_in[0] + sep_len[0] + vir_in[1] + sep_len[1] + vir_in[2] + sep_len[2] + vir_in[3] + sep_len[3] + vir_in[4] + sep_len[4] + vir_in[5] + sep_len[5] + vir_in[6] + sep_len[6] + vir_in[7] + sepEnd_len + 1; \
  bool ret = false, skipNow = false; \
\
  if ((len_out + len_add) >= SEGMENT_SIZE) \
  { \
    /*if (debug) fprintf (stderr, "Done with current memory segment.\n");*/ \
    fwrite (buf_out, 1, len_out, stdout); \
    fflush (stdout); \
    ptr_out = buf_out; \
\
    if (session_isSet || restore_isSet) \
    { \
      restore_isSet = false; \
      session_isSet = true; \
      /*if (debug) fprintf (stderr, "session update with current memory segment.\n");*/ \
      if (session_update() == false) \
      { \
        EXIT_WITH_RET(-1) \
      } \
    } \
  } \
\
  if (skip_isSet) \
  { \
    if (main_ctx.skip > 0) \
    { \
      main_ctx.skip--; \
      skipNow = true; \
      /*if (debug) fprintf (stderr, "Skipping sentence, remain to skip: %ld\n", main_ctx.skip);*/ \
\
      if ((session_isSet || restore_isSet) && (main_ctx.skip % (524287*32)) == 0) \
      { \
        /*if (debug) fprintf (stderr, "updating session.\n");*/ \
        restore_isSet = false; \
        session_isSet = true; \
        if (session_update() == false) \
        { \
          EXIT_WITH_RET(-1) \
        } \
      } \
    } \
  } \
\
  if (!skipNow) \
  { \
    ret = add (ptr_out, ptr_in, vir_in, sepStart, sepStart_len, sep, sep_len, sepEnd, sepEnd_len); \
\
    if (ret) \
    { \
      ptr_out += len_add; \
      if (limit_isSet) \
      { \
        main_ctx.limit--; \
        end2 = (limit_isSet && main_ctx.limit == 0) ? true : false; \
        if (end2) break; \
      } \
    } \
  } \
}

static void show_version (void)
{
  fprintf (stdout, "CombinatorX, version %s (%s)\n", PROG_VERSION, PROG_RELEASE_DATE);
}

static void usage (char *p)
{
  fprintf (stdout,
    "Usage: %s [<options>]\n\n" \
    "Options:\n\n" \
    "  Argument      | Type         | Description                              | Option type | Example\n" \
    "  -----------------------------------------------------------------------------------------------------------\n"
    "  --file1/-1    | Path         | Set file1 path                           | required    | --file1 wordlist1.txt\n" \
    "  --file2/-2    | Path         | Set file2 path                           | required    | --file2 wordlist2.txt\n" \
    "  --file3/-3    | Path         | Set file3 path                           | optional    | --file3 wordlist3.txt\n" \
    "  --file4/-4    | Path         | Set file4 path                           | optional    | --file4 wordlist4.txt\n" \
    "  --file5/-5    | Path         | Set file5 path                           | optional    | --file5 wordlist5.txt\n" \
    "  --file6/-6    | Path         | Set file6 path                           | optional    | --file6 wordlist6.txt\n" \
    "  --file7/-7    | Path         | Set file7 path                           | optional    | --file7 wordlist7.txt\n" \
    "  --file8/-8    | Path         | Set file8 path                           | optional    | --file8 wordlist8.txt\n" \
    "\n" \
    "  --sepStart    | Char/String  | Set char/string at the beginning         | optional    | --sepStart '['\n" \
    "  --sep1        | Char/String  | Set separator between file1 and file2    | optional    | --sep1 'a.'\n" \
    "  --sep2        | Char/String  | Set separator between file2 and file3    | optional    | --sep2 'bc'\n" \
    "  --sep3        | Char/String  | Set separator between file3 and file4    | optional    | --sep3 ',d'\n" \
    "  --sep4        | Char/String  | Set separator between file4 and file5    | optional    | --sep4 'e.'\n" \
    "  --sep5        | Char/String  | Set separator between file5 and file6    | optional    | --sep5 'f.g'\n" \
    "  --sep6        | Char/String  | Set separator between file6 and file7    | optional    | --sep6 'h-'\n" \
    "  --sep7        | Char/String  | Set separator between file7 and file8    | optional    | --sep7 '-j'\n" \
    "  --sepEnd      | Char/String  | Set char/string at the end               | optional    | --sepEnd ']'\n" \
    "  --sepFill     | Char/String  | Fill all unsetted separator buffers      | optional    | --sepFill '-'\n" \
    "\n" \
    "  --skip/-S     | Num          | Skip N sentences                         | optional    | --skip 0\n" \
    "  --limit/-L    | Num          | Exit after N sentences                   | optional    | --limit 1\n" \
    "  --max-rep/-m  | Num          | Skip sentences with > N repeated words   | optional    | --max-rep 1\n" \
    "  --max-len/-l  | Num          | Skip final sentences with len > N        | optional    | --max-len 30\n" \
    "\n" \
    "  --session/-s  | String       | Set session name                         | optional    | --session testSession\n" \
    "  --restore/-r  | String       | Restore by session name                  | optional    | --restore testSession\n" \
    "\n", p);

#ifdef DEBUG
  fprintf (stdout,
    "  --debug/-d    |              | Enable debug messages                    | optional    | --debug\n"
  );
#endif

  fprintf (stdout,
    "  --version/-v  |              | Show program version and exit            | optional    | --version\n"
    "  --help/-h     |              | Show this help                           | optional    | --help\n"
    "\n" \
    "Example:\n\n" \
    "input files: 1 2 3 4\n" \
    "$ cat 1 2 3 4 | xargs\n" \
    "one two three four\n" \
    "$ ./combinatorX.bin --file1 1 --file2 2 --file3 3 --file4 4 --sep1 ' . ' --sep2 ' + ' --sep3 ' @ ' --sepStart \"['\" --sepEnd ',*]'\n"
    "['one . two + three @ four,*]\n\n");
}

int main (int argc, char *argv[])
{
  int opt = 0;
  int long_index = 0;
  int err = 0;
  int set = 0;

  freeList = (char **) malloc (28 * sizeof(char *));
  freeListIdx = 0;

  char *sepFill = NULL;
  uint64_t sepFill_len = 0;
  uint64_t maxRepCheck = 0;

  bool limit_isSet = false;
  bool skip_isSet = false;
  bool session_isSet = false;
  bool restore_isSet = false;
  bool maxRep_isSet = false;
  bool maxLen_isSet = false;

  memset (&main_ctx, 0, sizeof (cx_session_t));

  for (int i = 0; i < 8; i++) main_ctx.fp[i] = NULL;

  for (int i = 0; i < 7; i++)
  {
    main_ctx.sep[i] = NULL;
    main_ctx.sep_len[i] = 0;
  }

  main_ctx.sfp[0] = NULL;
  main_ctx.sfp[1] = NULL;
  main_ctx.sfp[2] = NULL;

  while ((opt = getopt_long (argc, argv, short_options, long_options, &long_index)) != -1)
  {
    switch (opt)
    {
      case 0xa0:
        main_ctx.sepStart_len = strlen(optarg);
        main_ctx.sepStart = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sepStart)
        break;

      case 0xa1:
        main_ctx.sep_len[0] = strlen(optarg);
        main_ctx.sep[0] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[0])
        break;

      case 0xa2:
        main_ctx.sep_len[1] = strlen(optarg);
        main_ctx.sep[1] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[1])
        break;

      case 0xa3:
        main_ctx.sep_len[2] = strlen(optarg);
        main_ctx.sep[2] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[2])
        break;

      case 0xa4:
        main_ctx.sep_len[3] = strlen(optarg);
        main_ctx.sep[3] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[3])
        break;

      case 0xa5:
        main_ctx.sep_len[4] = strlen(optarg);
        main_ctx.sep[4] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[4])
        break;

      case 0xa6:
        main_ctx.sep_len[5] = strlen(optarg);
        main_ctx.sep[5] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[5])
        break;

      case 0xa7:
        main_ctx.sep_len[6] = strlen(optarg);
        main_ctx.sep[6] = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sep[6])
        break;

      case 0xaf:
        main_ctx.sepEnd_len = strlen(optarg);
        main_ctx.sepEnd = strdup(optarg);

        MEMORY_FREE_ADD(main_ctx.sepEnd)
        break;

      case 0xb0:
        sepFill_len = strlen(optarg);
        sepFill = strdup(optarg);

        MEMORY_FREE_ADD(sepFill)
        break;

      case '1':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[0] = strdup (optarg); set++; MEMORY_FREE_ADD(main_ctx.f[0]); }
        else err++;
        break;

      case '2':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[1] = strdup (optarg); set++; MEMORY_FREE_ADD(main_ctx.f[1]); }
        else err++;
        break;

      case '3':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[2] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[2]); }
        else err++;
        break;

      case '4':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[3] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[3]); }
        else err++;
        break;

      case '5':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[4] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[4]); }
        else err++;
        break;

      case '6':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[5] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[5]); }
        else err++;
        break;

      case '7':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[6] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[6]); }
        else err++;
        break;

      case '8':
        if (strlen (optarg) > 0 && access (optarg, F_OK) == 0) { main_ctx.f[7] = strdup (optarg); MEMORY_FREE_ADD(main_ctx.f[7]); }
        else err++;
        break;

      case 'S':
        skip_isSet = true;
        main_ctx.skip = strtoul (optarg, NULL, 10);
        if (main_ctx.skip == 0)
        {
          fprintf (stderr, "! Invalid skip argument: must be > 0\n");
          err++;
        }
        break;

      case 'L':
        limit_isSet = true;
        main_ctx.limit = strtoul (optarg, NULL, 10);
        if (main_ctx.limit == 0)
        {
          fprintf (stderr, "! Invalid limit argument: must be > 0\n");
          err++;
        }
        break;

      case 's':
        session_isSet = true;
        if (strlen (optarg) > 0)
        {
          if (access (optarg, R_OK) != 0)
          {
            main_ctx.sessionName = strdup (optarg);
            MEMORY_FREE_ADD(main_ctx.sessionName)
          }
          else
          {
            fprintf (stderr, "! session file already exists\n\n");
            err++;
          }
        }
        else
        {
          err++;
        }
        break;

      case 'r':
        restore_isSet = true;
        if (strlen (optarg) > 0)
        {
          if (access (optarg, R_OK) == 0)
          {
            main_ctx.sessionName = strdup (optarg);
            MEMORY_FREE_ADD(main_ctx.sessionName)
          }
          else
          {
            fprintf (stderr, "! session file does not exist\n\n");
            err++;
          }
        }
        else
        {
          err++;
        }
        break;

      case 'm':
        main_ctx.maxRep = strtoul (optarg, NULL, 10);
        if (main_ctx.maxRep > 0) maxRep_isSet = true;
        break;

      case 'l':
        main_ctx.maxLen = strtoul (optarg, NULL, 10);
        if (main_ctx.maxLen > 0) maxLen_isSet = true;
        break;

      #ifdef DEBUG
      case 'd':
        debug = true;
        break;
      #endif

      case 'v':
        show_version ();
        MEMORY_FREE_ALL
        return 0;

      case 'h':
        usage (argv[0]);
        MEMORY_FREE_ALL
        return 0;

      default:
        err++;
        break;
    }
  }

  if (restore_isSet == false)
  {
    if (err > 0 || set != 2)
    {
      fprintf (stderr, "! Detected invalid/missing argument(s) ...\n");
      usage (argv[0]);

      MEMORY_FREE_ALL
      return -1;
    }
  }

  // force using sequentials arguments to test wordlists

  for (int i = 0; i < 8; i++)
  {
    if (main_ctx.f[i] != NULL) continue;

    for (int j = i; j < 8; j++)
    {
      if (main_ctx.f[j] != NULL)
      {
        i++;
        j++;
        fprintf (stderr, "! Cannot set --file%d/-%d if --file%d/-%d is not set\n", j, j, i, i);
        usage (argv[0]);

        MEMORY_FREE_ALL
        return -1;
      }
    }
  }

  if (sepFill == NULL)
  {
    for (int i = 0; i < 7; i++)
    {
      if (main_ctx.sep[i] != NULL && main_ctx.f[i+1] == NULL)
      {
          i++;
          fprintf (stderr, "! Cannot set --sep%d if --file%d is not set\n", i, i+1);
          usage (argv[0]);

          MEMORY_FREE_ALL
          return -1;
      }
    }
  }

  for (int i = 0; i < 8; i++)
  {
    if (main_ctx.f[i] != NULL)
    {
      for (int j = i-1; j > 0; j--)
      {
        if (main_ctx.f[j] == NULL) continue;

        if (!strcmp (main_ctx.f[j], main_ctx.f[i]))
        {
          fprintf (stderr, "! Cannot use the same file as input (%s vs %s) ...\n", main_ctx.f[j], main_ctx.f[i]);
          usage (argv[0]);

          MEMORY_FREE_ALL
          return -1;
        }
      }

      maxRepCheck++;

      int sepId = i - 1;

      if (sepId >= 0)
      {
        if (sepFill && main_ctx.sep[sepId] == false)
        {
          main_ctx.sep_len[sepId] = sepFill_len;
          main_ctx.sep[sepId] = strdup(sepFill);

          MEMORY_FREE_ADD(main_ctx.sep[sepId])
        }
      }
    }
  }

  if (maxRep_isSet)
  {
    if (main_ctx.maxRep >= maxRepCheck)
    {
      fprintf (stderr, "! Invalid --maxRep value: cannot be greater than the number of input files opened\n");

      MEMORY_FREE_ALL
      return -1;
    }
  }

  if (maxLen_isSet)
  {
    if (main_ctx.maxLen < maxRepCheck)
    {
      fprintf (stderr, "! Invalid --maxLen value: cannot be smaller than the number of input files opened\n");

      MEMORY_FREE_ALL
      return -1;
    }
  }

  if (session_isSet && restore_isSet)
  {
    fprintf (stderr, "! Cannot use --session and --restore together ...\n");
    usage (argv[0]);

    MEMORY_FREE_ALL
    return -1;
  }

  // init session
  char *ptr_in[8];
  uint64_t vir_in[8];
  int64_t off_vir_in_init[8];
  uint64_t real_sz[8];
  uint64_t len_in[8];
  char *max_in[8];

  for (int i = 0; i < 8; i++)
  {
    ptr_in[i] = NULL;
    vir_in[i] = 0;
    off_vir_in_init[i] = 0;
    real_sz[i] = 0;
    len_in[i] = 0;
    max_in[i] = NULL;
  }

  memset (main_ctx.off_fd, 0, sizeof (main_ctx.off_fd));

  if (session_init (session_isSet, restore_isSet) == false)
  {
    MEMORY_FREE_ALL
    return -1;
  }

  if (restore_isSet)
  {
    if (main_ctx.limit > 0) limit_isSet = true;
    if (main_ctx.skip > 0) skip_isSet = true;
    if (main_ctx.maxRep > 0 && main_ctx.maxRep < maxRepCheck) maxRep_isSet = true;
    if (main_ctx.maxLen > 0 && main_ctx.maxLen >= maxRepCheck) maxLen_isSet = true;
  }

  #ifdef DEBUG
  if (debug)
  {
    session_print();
  }
  #endif

  // init session done

  // setup signal handler if session/restore is enabled
  if (main_ctx.sessionName != NULL)
  {
    signal (SIGINT, sigHandler);
  }

  uint64_t sz_buf = SEGMENT_SIZE + SEGMENT_ALIGN;

  char *buf_in[8];

  for (int i = 0; i < 8; i++)
  {
    buf_in[i] = NULL;

    if (main_ctx.f[i] != NULL)
    {
      buf_in[i] = (char *) malloc (sz_buf);

      MEMORY_FREE_ADD (buf_in[i])
    }
  }

  char *buf_out = (char *) malloc (sz_buf);

  MEMORY_FREE_ADD (buf_out)

  char *ptr_out = buf_out;

  main_ctx.max_skip = 1;
  main_ctx.max_files = 0;

  for (int i = 0; i < 8; i++)
  {
    if (main_ctx.f[i] && (main_ctx.fp[i] = fopen (main_ctx.f[i], "rb")) == NULL)
    {
      fprintf (stderr, "fopen(%s): %s\n", main_ctx.f[i], strerror (errno));

      for (; i > 0; i--) { fclose (main_ctx.fp[i]); main_ctx.fp[i] = NULL; }

      MEMORY_FREE_ALL
      if (main_ctx.sfp[0] != NULL) fclose (main_ctx.sfp[0]);
      return (-1);
    }

    if (main_ctx.f[i] != NULL)
    {
      main_ctx.lines[i] = 0;

      while(!feof(main_ctx.fp[i]))
      {
        if (fgetc(main_ctx.fp[i]) == '\n')
          main_ctx.lines[i]++;
      }

      rewind (main_ctx.fp[i]);

      main_ctx.max_skip *= main_ctx.lines[i];
      main_ctx.max_files++;
    }
  }

  #ifdef DEBUG
  if (debug) fprintf (stderr, "Max skip: %" PRIu64 "\n", main_ctx.max_skip);
  #endif

  if (main_ctx.skip > 0 && main_ctx.skip >= main_ctx.max_skip)
  {
    // argument or restore file
    fprintf (stderr, "! Invalid argument: skip (max detected: %" PRIu64 ")\n", main_ctx.max_skip-1);
    if (main_ctx.sfp[0] != NULL) fclose (main_ctx.sfp[0]);
    MEMORY_FREE_ALL
    return (-1);
  }

  if (restore_isSet)
  {
    for (int i = 0; i < 8; i++) off_vir_in_init[i] = main_ctx.off_vir_in[i];
    for (int i = 0; i < 8; i++) if (main_ctx.off_fd[i] > 0 && main_ctx.fp[i] != NULL) fseek (main_ctx.fp[i], main_ctx.off_fd[i], SEEK_SET);

    // reset main counters
    for (int i = 0; i < 8; i++) main_ctx.off_fd[i] = 0;
    for (int i = 0; i < 8; i++) main_ctx.off_vir_in[i] = 0;
  }

  while (!feof (main_ctx.fp[0]) && !end && !end2)
  {
    main_ctx.off_fd[0] = ftell (main_ctx.fp[0]);

    real_sz[0] = read_segment (buf_in[0], main_ctx.fp[0]);
    len_in[0] = 0;
    max_in[0] = buf_in[0] + real_sz[0];

    for (ptr_in[0] = buf_in[0]; ptr_in[0] < max_in[0] && !end; ptr_in[0] += len_in[0] + 1)
    {
      main_ctx.cur_rep[0] = 0;

      len_in[0] = get_line_len (ptr_in[0], max_in[0]);
      vir_in[0] = len_in[0];

      while (vir_in[0])
      {
        if (ptr_in[0][vir_in[0] - 1] != '\r') break;
        vir_in[0]--;
      }

      if (vir_in[0] > WORD_MAX_LEN) continue;
      if (maxLen_isSet && vir_in[0] > main_ctx.maxLen) continue;

      // restore 1 if needed
      main_ctx.off_vir_in[0] += vir_in[0];
      if (restore_isSet && off_vir_in_init[0] >= 0 && main_ctx.off_vir_in[0] < off_vir_in_init[0]) continue;
      off_vir_in_init[0] = -1;

      while (!feof (main_ctx.fp[1]) && !end && !end2)
      {
        main_ctx.off_fd[1] = ftell (main_ctx.fp[1]);

        real_sz[1] = read_segment (buf_in[1], main_ctx.fp[1]);
        len_in[1] = 0;
        max_in[1] = buf_in[1] + real_sz[1];

        for (ptr_in[1] = buf_in[1]; ptr_in[1] < max_in[1] && !end; ptr_in[1] += len_in[1] + 1)
        {
          main_ctx.cur_rep[1] = 0;

          len_in[1] = get_line_len (ptr_in[1], max_in[1]);
          vir_in[1] = len_in[1];

          while (vir_in[1])
          {
            if (ptr_in[1][vir_in[1] - 1] != '\r') break;
            vir_in[1]--;
          }

          if (vir_in[1] > WORD_MAX_LEN) continue;
          if (maxLen_isSet && (vir_in[0]+vir_in[1]) > main_ctx.maxLen) continue;

          // restore 2 if needed
          main_ctx.off_vir_in[1] += vir_in[1];
          if (restore_isSet && off_vir_in_init[1] >= 0 && main_ctx.off_vir_in[1] < off_vir_in_init[1]) continue;
          off_vir_in_init[1] = -1;

          if (maxRep_isSet)
          {
            if (vir_in[1] == vir_in[0] && memcmp (ptr_in[0], ptr_in[1], vir_in[0]) == 0)
            {
              ++main_ctx.cur_rep[1];
              if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]) >= main_ctx.maxRep) continue;
            }
          }

          if (buf_in[2])
          {
            while (!feof (main_ctx.fp[2]) && !end && !end2)
            {
              main_ctx.off_fd[2] = ftell (main_ctx.fp[2]);

              real_sz[2] = read_segment (buf_in[2], main_ctx.fp[2]);
              len_in[2] = 0;
              max_in[2] = buf_in[2] + real_sz[2];

              for (ptr_in[2] = buf_in[2]; ptr_in[2] < max_in[2] && !end; ptr_in[2] += len_in[2] + 1)
              {
                main_ctx.cur_rep[2] = 0;

                len_in[2] = get_line_len (ptr_in[2], max_in[2]);
                vir_in[2] = len_in[2];

                while (vir_in[2])
                {
                  if (ptr_in[2][vir_in[2] - 1] != '\r') break;
                  vir_in[2]--;
                }

                if (vir_in[2] > WORD_MAX_LEN) continue;
                if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]) > main_ctx.maxLen) continue;

                // restore 3 if needed
                main_ctx.off_vir_in[2] += vir_in[2];
                if (restore_isSet && off_vir_in_init[2] >= 0 && main_ctx.off_vir_in[2] < off_vir_in_init[2]) continue;
                off_vir_in_init[2] = -1;

                if (maxRep_isSet)
                {
                  if ((vir_in[2] == vir_in[1] && memcmp (ptr_in[2], ptr_in[1], vir_in[1]) == 0) ||
                      (vir_in[2] == vir_in[0] && memcmp (ptr_in[2], ptr_in[0], vir_in[0]) == 0))
                  {
                    ++main_ctx.cur_rep[2];
                    if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]) >= main_ctx.maxRep) continue;
                  }
                }

                if (buf_in[3])
                {
                  while (!feof (main_ctx.fp[3]) && !end && !end2)
                  {
                    main_ctx.off_fd[3] = ftell (main_ctx.fp[3]);

                    real_sz[3] = read_segment (buf_in[3], main_ctx.fp[3]);
                    len_in[3] = 0;
                    max_in[3] = buf_in[3] + real_sz[3];

                    for (ptr_in[3] = buf_in[3]; ptr_in[3] < max_in[3] && !end; ptr_in[3] += len_in[3] + 1)
                    {
                      main_ctx.cur_rep[3] = 0;

                      len_in[3] = get_line_len (ptr_in[3], max_in[3]);
                      vir_in[3] = len_in[3];

                      while (vir_in[3])
                      {
                        if (ptr_in[3][vir_in[3] - 1] != '\r') break;
                        vir_in[3]--;
                      }

                      if (vir_in[3] > WORD_MAX_LEN) continue;
                      if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]+vir_in[3]) > main_ctx.maxLen) continue;

                      // restore 4 if needed
                      main_ctx.off_vir_in[3] += vir_in[3];
                      if (restore_isSet && off_vir_in_init[3] >= 0 && main_ctx.off_vir_in[3] < off_vir_in_init[3]) continue;
                      off_vir_in_init[3] = -1;

                      if (maxRep_isSet)
                      {
                        if ((vir_in[3] == vir_in[2] && memcmp (ptr_in[3], ptr_in[2], vir_in[2]) == 0) ||
                            (vir_in[3] == vir_in[1] && memcmp (ptr_in[3], ptr_in[1], vir_in[1]) == 0) ||
                            (vir_in[3] == vir_in[0] && memcmp (ptr_in[3], ptr_in[0], vir_in[0]) == 0))
                        {
                          ++main_ctx.cur_rep[3];
                          if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]+main_ctx.cur_rep[3]) >= main_ctx.maxRep) continue;
                        }
                      }

                      if (buf_in[4])
                      {
                        while (!feof (main_ctx.fp[4]) && !end && !end2)
                        {
                          main_ctx.off_fd[4] = ftell (main_ctx.fp[4]);

                          real_sz[4] = read_segment (buf_in[4], main_ctx.fp[4]);
                          len_in[4] = 0;
                          max_in[4] = buf_in[4] + real_sz[4];

                          for (ptr_in[4] = buf_in[4]; ptr_in[4] < max_in[4] && !end; ptr_in[4] += len_in[4] + 1)
                          {
                            main_ctx.cur_rep[4] = 0;

                            len_in[4] = get_line_len (ptr_in[4], max_in[4]);
                            vir_in[4] = len_in[4];

                            while (vir_in[4])
                            {
                              if (ptr_in[4][vir_in[4] - 1] != '\r') break;
                              vir_in[4]--;
                            }

                            if (vir_in[4] > WORD_MAX_LEN) continue;
                            if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]+vir_in[3]+vir_in[4]) > main_ctx.maxLen) continue;

                            // restore 5 if needed
                            main_ctx.off_vir_in[4] += vir_in[4];
                            if (restore_isSet && off_vir_in_init[4] >= 0 && main_ctx.off_vir_in[4] < off_vir_in_init[4]) continue;
                            off_vir_in_init[4] = -1;

                            if (maxRep_isSet)
                            {
                              if ((vir_in[4] == vir_in[3] && memcmp (ptr_in[4], ptr_in[3], vir_in[3]) == 0) ||
                                  (vir_in[4] == vir_in[2] && memcmp (ptr_in[4], ptr_in[2], vir_in[2]) == 0) ||
                                  (vir_in[4] == vir_in[1] && memcmp (ptr_in[4], ptr_in[1], vir_in[1]) == 0) ||
                                  (vir_in[4] == vir_in[0] && memcmp (ptr_in[4], ptr_in[0], vir_in[0]) == 0))
                              {
                                ++main_ctx.cur_rep[4];
                                if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]+main_ctx.cur_rep[3]+main_ctx.cur_rep[4]) >= main_ctx.maxRep) continue;
                              }
                            }

                            if (buf_in[5])
                            {
                              while (!feof (main_ctx.fp[5]) && !end && !end2)
                              {
                                main_ctx.off_fd[5] = ftell (main_ctx.fp[5]);

                                real_sz[5] = read_segment (buf_in[5], main_ctx.fp[5]);
                                len_in[5] = 0;
                                max_in[5] = buf_in[5] + real_sz[5];

                                for (ptr_in[5] = buf_in[5]; ptr_in[5] < max_in[5] && !end; ptr_in[5] += len_in[5] + 1)
                                {
                                  main_ctx.cur_rep[5] = 0;

                                  len_in[5] = get_line_len (ptr_in[5], max_in[5]);
                                  vir_in[5] = len_in[5];

                                  while (vir_in[5])
                                  {
                                    if (ptr_in[5][vir_in[5] - 1] != '\r') break;
                                    vir_in[5]--;
                                  }

                                  if (vir_in[5] > WORD_MAX_LEN) continue;
                                  if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]+vir_in[3]+vir_in[4]+vir_in[5]) > main_ctx.maxLen) continue;

                                  // restore 6 if needed
                                  main_ctx.off_vir_in[5] += vir_in[5];
                                  if (restore_isSet && off_vir_in_init[5] >= 0 && main_ctx.off_vir_in[5] < off_vir_in_init[5]) continue;
                                  off_vir_in_init[5] = -1;

                                  if (maxRep_isSet)
                                  {
                                    if ((vir_in[5] == vir_in[4] && memcmp (ptr_in[5], ptr_in[4], vir_in[4]) == 0) ||
                                        (vir_in[5] == vir_in[3] && memcmp (ptr_in[5], ptr_in[3], vir_in[3]) == 0) ||
                                        (vir_in[5] == vir_in[2] && memcmp (ptr_in[5], ptr_in[2], vir_in[2]) == 0) ||
                                        (vir_in[5] == vir_in[1] && memcmp (ptr_in[5], ptr_in[1], vir_in[1]) == 0) ||
                                        (vir_in[5] == vir_in[0] && memcmp (ptr_in[5], ptr_in[0], vir_in[0]) == 0))
                                    {
                                      ++main_ctx.cur_rep[5];
                                      if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]+main_ctx.cur_rep[3]+main_ctx.cur_rep[4]+main_ctx.cur_rep[5]) >= main_ctx.maxRep) continue;
                                    }
                                  }

                                  if (buf_in[6])
                                  {
                                    while (!feof (main_ctx.fp[6]) && !end && !end2)
                                    {
                                      main_ctx.off_fd[6] = ftell (main_ctx.fp[6]);

                                      real_sz[6] = read_segment (buf_in[6], main_ctx.fp[6]);
                                      len_in[6] = 0;
                                      max_in[6] = buf_in[6] + real_sz[6];

                                      for (ptr_in[6] = buf_in[6]; ptr_in[6] < max_in[6] && !end; ptr_in[6] += len_in[6] + 1)
                                      {
                                        main_ctx.cur_rep[6] = 0;

                                        len_in[6] = get_line_len (ptr_in[6], max_in[6]);
                                        vir_in[6] = len_in[6];

                                        while (vir_in[6])
                                        {
                                          if (ptr_in[6][vir_in[6] - 1] != '\r') break;
                                          vir_in[6]--;
                                        }

                                        if (vir_in[6] > WORD_MAX_LEN) continue;
                                        if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]+vir_in[3]+vir_in[4]+vir_in[5]+vir_in[6]) > main_ctx.maxLen) continue;

                                        // restore 7 if needed
                                        main_ctx.off_vir_in[6] += vir_in[6];
                                        if (restore_isSet && off_vir_in_init[6] >= 0 && main_ctx.off_vir_in[6] < off_vir_in_init[6]) continue;
                                        off_vir_in_init[6] = -1;

                                        if (maxRep_isSet)
                                        {
                                          if ((vir_in[6] == vir_in[5] && memcmp (ptr_in[6], ptr_in[5], vir_in[5]) == 0) ||
                                              (vir_in[6] == vir_in[4] && memcmp (ptr_in[6], ptr_in[4], vir_in[4]) == 0) ||
                                              (vir_in[6] == vir_in[3] && memcmp (ptr_in[6], ptr_in[3], vir_in[3]) == 0) ||
                                              (vir_in[6] == vir_in[2] && memcmp (ptr_in[6], ptr_in[2], vir_in[2]) == 0) ||
                                              (vir_in[6] == vir_in[1] && memcmp (ptr_in[6], ptr_in[1], vir_in[1]) == 0) ||
                                              (vir_in[6] == vir_in[0] && memcmp (ptr_in[6], ptr_in[0], vir_in[0]) == 0))
                                          {
                                            ++main_ctx.cur_rep[6];
                                            if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]+main_ctx.cur_rep[3]+main_ctx.cur_rep[4]+main_ctx.cur_rep[5]+main_ctx.cur_rep[6]) >= main_ctx.maxRep) continue;
                                          }
                                        }

                                        if (buf_in[7])
                                        {
                                          while (!feof (main_ctx.fp[7]) && !end && !end2)
                                          {
                                            main_ctx.off_fd[7] = ftell (main_ctx.fp[7]);

                                            real_sz[7] = read_segment (buf_in[7], main_ctx.fp[7]);
                                            len_in[7] = 0;
                                            max_in[7] = buf_in[7] + real_sz[7];

                                            for (ptr_in[7] = buf_in[7]; ptr_in[7] < max_in[7] && !end; ptr_in[7] += len_in[7] + 1)
                                            {
                                              main_ctx.cur_rep[7] = 0;

                                              len_in[7] = get_line_len (ptr_in[7], max_in[7]);
                                              vir_in[7] = len_in[7];

                                              while (vir_in[7])
                                              {
                                                if (ptr_in[7][vir_in[7] - 1] != '\r') break;
                                                vir_in[7]--;
                                              }

                                              if (vir_in[7] > WORD_MAX_LEN) continue;
                                              if (maxLen_isSet && (vir_in[0]+vir_in[1]+vir_in[2]+vir_in[3]+vir_in[4]+vir_in[5]+vir_in[6]+vir_in[7]) > main_ctx.maxLen) continue;

                                              // restore 8 if needed
                                              main_ctx.off_vir_in[7] += vir_in[7];
                                              if (restore_isSet && off_vir_in_init[7] >= 0 && main_ctx.off_vir_in[7] < off_vir_in_init[7]) continue;
                                              off_vir_in_init[7] = -1;

                                              if (maxRep_isSet)
                                              {
                                                if ((vir_in[7] == vir_in[6] && memcmp (ptr_in[7], ptr_in[6], vir_in[6]) == 0) ||
                                                    (vir_in[7] == vir_in[5] && memcmp (ptr_in[7], ptr_in[5], vir_in[5]) == 0) ||
                                                    (vir_in[7] == vir_in[4] && memcmp (ptr_in[7], ptr_in[4], vir_in[4]) == 0) ||
                                                    (vir_in[7] == vir_in[3] && memcmp (ptr_in[7], ptr_in[3], vir_in[3]) == 0) ||
                                                    (vir_in[7] == vir_in[2] && memcmp (ptr_in[7], ptr_in[2], vir_in[2]) == 0) ||
                                                    (vir_in[7] == vir_in[1] && memcmp (ptr_in[7], ptr_in[1], vir_in[1]) == 0) ||
                                                    (vir_in[7] == vir_in[0] && memcmp (ptr_in[7], ptr_in[0], vir_in[0]) == 0))
                                                {
                                                  ++main_ctx.cur_rep[7];
                                                  if ((main_ctx.cur_rep[0]+main_ctx.cur_rep[1]+main_ctx.cur_rep[2]+main_ctx.cur_rep[3]+main_ctx.cur_rep[4]+main_ctx.cur_rep[5]+main_ctx.cur_rep[6]+main_ctx.cur_rep[7]) >= main_ctx.maxRep)
                                                  continue;
                                                }
                                              }

                                              ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                                            }
                                          }
                                          rewind (main_ctx.fp[7]);

                                          // reset cnt 8
                                          main_ctx.off_vir_in[7] = 0;
                                        }
                                        else
                                        {
                                          ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                                        }
                                      }
                                    }
                                    rewind (main_ctx.fp[6]);

                                    // reset cnt 7
                                    main_ctx.off_vir_in[6] = 0;
                                  }
                                  else
                                  {
                                    ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                                  }
                                }
                              }
                              rewind (main_ctx.fp[5]);

                              // reset cnt 6
                              main_ctx.off_vir_in[5] = 0;
                            }
                            else
                            {
                              ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                            }
                          }
                        }
                        rewind (main_ctx.fp[4]);

                        // reset cnt 5
                        main_ctx.off_vir_in[4] = 0;
                      }
                      else
                      {
                        ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                      }
                    }
                  }
                  rewind (main_ctx.fp[3]);

                  // reset cnt 4
                  main_ctx.off_vir_in[3] = 0;
                }
                else
                {
                  ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
                }
              }
            }
            rewind (main_ctx.fp[2]);

            // reset cnt 3
            main_ctx.off_vir_in[2] = 0;
          }
          else
          {
            ADD_TO_OUTPUT_BUFFER(buf_out, ptr_out, ptr_in, vir_in, main_ctx.sepStart, main_ctx.sepStart_len, main_ctx.sep, main_ctx.sep_len, main_ctx.sepEnd, main_ctx.sepEnd_len)
          }
        }
      }
      rewind (main_ctx.fp[1]);

      // reset cnt 3
      main_ctx.off_vir_in[1] = 0;
    }
  }

  if (!end)
  {
    uint64_t len_out = (uint64_t) (ptr_out - buf_out);

    fwrite (buf_out, 1, len_out, stdout);
  }

  if (!end && (session_isSet || restore_isSet))
  {
    int r = 0;

    for (int i = 0; i < 7; i++) if (main_ctx.fp[i] && feof(main_ctx.fp[i])) r++;

    if (r > 0)
    {
      // reset first offset
      main_ctx.off_vir_in[0] = 0;

      if (session_update() == false)
      {
        EXIT_WITH_RET(-1)
      }

      session_destroy (true);
    }
  }

  EXIT_WITH_RET(0)
}
