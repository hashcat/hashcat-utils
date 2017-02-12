#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700
#define __USE_MINGW_ANSI_STDIO 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>

/**
 * Name........: keyspace
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define CHARSIZ         0x100

#define SP_HCSTAT       "hashcat.hcstat"
#define SP_PW_MIN       2
#define SP_PW_MAX       64
#define SP_ROOT_CNT     (SP_PW_MAX * CHARSIZ)
#define SP_MARKOV_CNT   (SP_PW_MAX * CHARSIZ * CHARSIZ)

#define OPTS_TYPE_PT_UNICODE        (1 <<  0)
#define OPTS_TYPE_ST_UNICODE        (1 << 10)

typedef struct
{
  uint8_t  key;
  uint64_t val;

} hcstat_table_t;

typedef struct
{
  uint8_t cs_buf[CHARSIZ];
  uint32_t cs_len;

} cs_t;

uint8_t hex_convert (const uint8_t c)
{
  return (uint8_t)((c & 15) + (c >> 6) * 9);
}

void mp_css_to_uniq_tbl (const int css_cnt, cs_t *css_buf, int uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  int css_pos;

  for (css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    uint8_t *cs_buf = css_buf[css_pos].cs_buf;
    uint32_t  cs_len = css_buf[css_pos].cs_len;

    int *uniq_tbl = uniq_tbls[css_pos];

    uint32_t cs_pos;

    for (cs_pos = 0; cs_pos < cs_len; cs_pos++)
    {
      const uint8_t c = cs_buf[cs_pos];

      uniq_tbl[c] = 1;
    }
  }
}

void mp_add_cs_buf (const uint32_t in_len, const uint8_t *in_buf, const int css_pos, cs_t *css_buf)
{
  cs_t *cs = &css_buf[css_pos];

  int *css_uniq = (int *) calloc (CHARSIZ, sizeof (int));

  uint32_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    const uint8_t u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    const uint8_t u = in_buf[i];

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  free (css_uniq);
}

void mp_expand (const int in_len, const uint8_t *in_buf, cs_t *mp_sys, cs_t *mp_usr, const int css_pos, const int hex_charset)
{
  int in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    const uint8_t p0 = in_buf[in_pos];

    if (p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      const uint8_t p1 = in_buf[in_pos];

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_len, mp_sys[0].cs_buf, css_pos, mp_usr);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_len, mp_sys[1].cs_buf, css_pos, mp_usr);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_len, mp_sys[2].cs_buf, css_pos, mp_usr);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_len, mp_sys[3].cs_buf, css_pos, mp_usr);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_len, mp_sys[4].cs_buf, css_pos, mp_usr);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_len, mp_sys[5].cs_buf, css_pos, mp_usr);
                  break;
        case '1': mp_add_cs_buf (mp_usr[0].cs_len, mp_usr[0].cs_buf, css_pos, mp_usr);
                  break;
        case '2': mp_add_cs_buf (mp_usr[1].cs_len, mp_usr[1].cs_buf, css_pos, mp_usr);
                  break;
        case '3': mp_add_cs_buf (mp_usr[2].cs_len, mp_usr[2].cs_buf, css_pos, mp_usr);
                  break;
        case '4': mp_add_cs_buf (mp_usr[3].cs_len, mp_usr[3].cs_buf, css_pos, mp_usr);
                  break;
        case '?': mp_add_cs_buf (1, &p1, css_pos, mp_usr);
                  break;
        default:  fprintf (stderr, "Syntax error: %s\n", in_buf);
                  exit (-1);
      }
    }
    else
    {
      if (hex_charset)
      {
        in_pos++;

        if (in_pos == in_len) break;

        const uint8_t p1 = in_buf[in_pos];

        const uint8_t chr = (uint8_t)(  hex_convert (p1) << 0
                                      | hex_convert (p0) << 4);

        mp_add_cs_buf (1, &chr, css_pos, mp_usr);
      }
      else
      {
        const uint8_t chr = p0;

        mp_add_cs_buf (1, &chr, css_pos, mp_usr);
      }
    }
  }
}

cs_t *mp_gen_css (const int in_len, const uint8_t *in_buf, cs_t *mp_sys, cs_t *mp_usr, int *css_cnt, const int hex_charset)
{
  cs_t *css_buf = (cs_t *) calloc (CHARSIZ, sizeof (cs_t));

  int in_pos;
  int css_pos;

  for (in_pos = 0, css_pos = 0; in_pos < in_len; in_pos++, css_pos++)
  {
    const uint8_t p0 = in_buf[in_pos];

    if (p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      const uint8_t p1 = in_buf[in_pos];

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_len, mp_sys[0].cs_buf, css_pos, css_buf);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_len, mp_sys[1].cs_buf, css_pos, css_buf);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_len, mp_sys[2].cs_buf, css_pos, css_buf);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_len, mp_sys[3].cs_buf, css_pos, css_buf);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_len, mp_sys[4].cs_buf, css_pos, css_buf);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_len, mp_sys[5].cs_buf, css_pos, css_buf);
                  break;
        case '1': mp_add_cs_buf (mp_usr[0].cs_len, mp_usr[0].cs_buf, css_pos, css_buf);
                  break;
        case '2': mp_add_cs_buf (mp_usr[1].cs_len, mp_usr[1].cs_buf, css_pos, css_buf);
                  break;
        case '3': mp_add_cs_buf (mp_usr[2].cs_len, mp_usr[2].cs_buf, css_pos, css_buf);
                  break;
        case '4': mp_add_cs_buf (mp_usr[3].cs_len, mp_usr[3].cs_buf, css_pos, css_buf);
                  break;
        case '?': mp_add_cs_buf (1, &p1, css_pos, css_buf);
                  break;
        default:  fprintf (stderr, "ERROR: syntax error: %s\n", in_buf);
                  exit (-1);
      }
    }
    else
    {
      if (hex_charset)
      {
        in_pos++;

        if (in_pos == in_len) break;

        const uint8_t p1 = in_buf[in_pos];

        const uint8_t chr = (uint8_t)(  hex_convert (p1) << 0
                                      | hex_convert (p0) << 4);

        mp_add_cs_buf (1, &chr, css_pos, css_buf);
      }
      else
      {
        const uint8_t chr = p0;

        mp_add_cs_buf (1, &chr, css_pos, css_buf);
      }
    }
  }

  *css_cnt = css_pos;

  return (css_buf);
}

void mp_setup_sys (cs_t *mp_sys)
{
  int pos;
  int chr;

  int donec[CHARSIZ];

  memset (donec, 0, sizeof (donec));

  for (pos = 0, chr =  'a'; chr <=  'z'; chr++) { donec[chr] = 1;
                                                  mp_sys[0].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[0].cs_len = pos; }

  for (pos = 0, chr =  'A'; chr <=  'Z'; chr++) { donec[chr] = 1;
                                                  mp_sys[1].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[1].cs_len = pos; }

  for (pos = 0, chr =  '0'; chr <=  '9'; chr++) { donec[chr] = 1;
                                                  mp_sys[2].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[2].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { if (donec[chr]) continue;
                                                  mp_sys[3].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[3].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { mp_sys[4].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[4].cs_len = pos; }

  for (pos = 0, chr = 0x00; chr <= 0xff; chr++) { mp_sys[5].cs_buf[pos++] = (uint8_t)chr;
                                                  mp_sys[5].cs_len = pos; }
}

void mp_setup_usr (cs_t *mp_sys, cs_t *mp_usr, const int in_len, const uint8_t *in_buf, const int css_pos, const int hex_charset)
{
  mp_expand (in_len, in_buf, mp_sys, mp_usr, css_pos, hex_charset);
}

uint64_t sp_get_sum (const int start, const int stop, const cs_t *root_css_buf)
{
  uint64_t sum = 1;

  int i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
}

int sp_comp_val (const void *p1, const void *p2)
{
  hcstat_table_t *b1 = (hcstat_table_t *) p1;
  hcstat_table_t *b2 = (hcstat_table_t *) p2;

  return b2->val - b1->val;
}

void sp_setup_tbl (const char *markov_hcstat, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf)
{
  /**
   * Initialize hcstats
   */

  uint64_t *root_stats_buf = (uint64_t *) calloc (SP_ROOT_CNT, sizeof (uint64_t));

  uint64_t *root_stats_ptr = root_stats_buf;

  int i;

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_stats_ptr += CHARSIZ;
  }

  uint64_t *markov_stats_buf = (uint64_t *) calloc (SP_MARKOV_CNT, sizeof (uint64_t));

  uint64_t *markov_stats_ptr = markov_stats_buf;

  for (i = 0; i < SP_PW_MAX; i++)
  {
    int j;

    for (j = 0; j < CHARSIZ; j++)
    {
      markov_stats_ptr += CHARSIZ;
    }
  }

  /**
   * Load hcstats File
   */

  FILE *fd = fopen (markov_hcstat, "rb");

  if (fd == NULL)
  {
    fprintf (stderr, "%s: %s\n", markov_hcstat, strerror (errno));

    exit (-1);
  }

  if (fread (root_stats_buf, sizeof (uint64_t), SP_ROOT_CNT, fd) != SP_ROOT_CNT)
  {
    fprintf (stderr, "%s: Could not load data\n", markov_hcstat);

    exit (-1);
  }

  if (fread (markov_stats_buf, sizeof (uint64_t), SP_MARKOV_CNT, fd) != SP_MARKOV_CNT)
  {
    fprintf (stderr, "%s: Could not load data\n", markov_hcstat);

    exit (-1);
  }

  fclose (fd);

  /**
   * Initialize tables
   */

  hcstat_table_t *root_table_ptr = root_table_buf;

  hcstat_table_t *root_table_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_table_buf_by_pos[i] = root_table_ptr;

    root_table_ptr += CHARSIZ;
  }

  hcstat_table_t *markov_table_ptr = markov_table_buf;

  hcstat_table_t *markov_table_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    int j;

    for (j = 0; j < CHARSIZ; j++)
    {
      markov_table_buf_by_key[i][j] = markov_table_ptr;

      markov_table_ptr += CHARSIZ;
    }
  }

  /**
   * Convert hcstat to tables
   */

  for (i = 0; i < SP_ROOT_CNT; i++)
  {
    const uint8_t key = (uint8_t)(i % CHARSIZ);

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    const uint8_t key = (uint8_t)(i % CHARSIZ);

    markov_table_buf[i].key = key;
    markov_table_buf[i].val = markov_stats_buf[i];
  }

  free (root_stats_buf);
  free (markov_stats_buf);

  /**
   * Finally sort them
   */

  for (i = 0; i < SP_PW_MAX; i++)
  {
    qsort (root_table_buf_by_pos[i], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
  }

  for (i = 0; i < SP_PW_MAX; i++)
  {
    int j;

    for (j = 0; j < CHARSIZ; j++)
    {
      qsort (markov_table_buf_by_key[i][j], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
    }
  }
}

void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, const uint32_t markov_threshold, int uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  int i;

  for (i = 0; i < SP_ROOT_CNT; i++)
  {
    const int pw_pos = i / CHARSIZ;

    cs_t *cs = &root_css_buf[pw_pos];

    if (cs->cs_len == markov_threshold) continue;

    const uint8_t key = root_table_buf[i].key;

    if (uniq_tbls[pw_pos][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    const int c = i / CHARSIZ;

    cs_t *cs = &markov_css_buf[c];

    if (cs->cs_len == markov_threshold) continue;

    const int pw_pos = c / CHARSIZ;

    const uint8_t key = markov_table_buf[i].key;

    if ((pw_pos + 1) < SP_PW_MAX) if (uniq_tbls[pw_pos + 1][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }
}

uint64_t keyspace (const int in_len, const uint8_t *in_buf, cs_t *mp_sys, cs_t *mp_usr, const char *markov_hcstat, const uint32_t markov_threshold, const int opts_type, const int hex_charset)
{
  int css_cnt = 0;

  cs_t *css_buf = mp_gen_css (in_len, in_buf, mp_sys, mp_usr, &css_cnt, hex_charset);

  if (opts_type & OPTS_TYPE_PT_UNICODE)
  {
    int css_cnt_unicode = css_cnt * 2;

    cs_t *css_buf_unicode = (cs_t *) calloc (css_cnt_unicode, sizeof (cs_t));

    int i;
    int j;

    for (i = 0, j = 0; i < css_cnt; i += 1, j += 2)
    {
      memcpy (&css_buf_unicode[j + 0], &css_buf[i], sizeof (cs_t));
      memset (&css_buf_unicode[j + 1],           0, sizeof (cs_t));

      css_buf_unicode[j + 1].cs_len = 1;
    }

    free (css_buf);

    css_buf = css_buf_unicode;
    css_cnt = css_cnt_unicode;
  }

  int uniq_tbls[SP_PW_MAX][CHARSIZ];

  memset (uniq_tbls, 0, sizeof (uniq_tbls));

  mp_css_to_uniq_tbl (css_cnt, css_buf, uniq_tbls);

  hcstat_table_t *root_table_buf   = (hcstat_table_t *) calloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
  hcstat_table_t *markov_table_buf = (hcstat_table_t *) calloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

  sp_setup_tbl (markov_hcstat, root_table_buf, markov_table_buf);

  cs_t *root_css_buf   = (cs_t *) calloc (SP_PW_MAX,           sizeof (cs_t));
  cs_t *markov_css_buf = (cs_t *) calloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

  sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, markov_threshold, uniq_tbls);

  int css_cnt_r;

  if (css_cnt < 6)
  {
    css_cnt_r = 1;
  }
  else if (css_cnt == 6)
  {
    css_cnt_r = 2;
  }
  else
  {
    if (opts_type & OPTS_TYPE_PT_UNICODE)
    {
      if (css_cnt == 8 || css_cnt == 10)
      {
        css_cnt_r = 2;
      }
      else
      {
        css_cnt_r = 4;
      }
    }
    else
    {
      if ((css_buf[0].cs_len * css_buf[1].cs_len * css_buf[2].cs_len) > 256)
      {
        css_cnt_r = 3;
      }
      else
      {
        css_cnt_r = 4;
      }
    }
  }

  const uint64_t sum = sp_get_sum (css_cnt_r, css_cnt, root_css_buf);

  free (root_css_buf);
  free (markov_css_buf);

  free (root_table_buf);
  free (markov_table_buf);

  free (css_buf);

  return sum;
}

void usage (char *program)
{
  const char *help_text[] = {
    "%s, keyspace utility for hashcat",
    "",
    "Usage: %s [options] mask",
    "",
    "=======",
    "Options",
    "=======",
    "",
    "  -m,  --hash-type=NUM           Hash-type",
    "       --hex-charset             Assume charset is given in hex",
    "       --markov-hcstat=FILE      Specify hcstat file to use, default is hashcat.hcstat",
    "  -t,  --markov-threshold=NUM    Threshold for markov-chains",
    "  -1,  --custom-charset1=CS      User-defined charsets",
    "  -2,  --custom-charset2=CS      Examples:",
    "  -3,  --custom-charset3=CS      --custom-charset3=?dabcdef : sets charset ?3 to 0123456789abcdef",
    "  -4,  --custom-charset4=CS      --custom-charset4=?l?u : sets charset ?4 to all lower and upper case letters",
    "  -h,  --help                    Print help",
    NULL
  };

  int i;

  for (i = 0; help_text[i] != NULL; i++)
  {
    fprintf (stderr, help_text[i], program, program);

    fprintf (stderr, "\n");
  }
}

int main (int argc, char *argv[])
{
  #define IDX_HASH_MODE         'm'
  #define IDX_HEX_CHARSET       0xff20
  #define IDX_MARKOV_THRESHOLD  't'
  #define IDX_MARKOV_HCSTAT     0xff24
  #define IDX_CUSTOM_CHARSET_1  '1'
  #define IDX_CUSTOM_CHARSET_2  '2'
  #define IDX_CUSTOM_CHARSET_3  '3'
  #define IDX_CUSTOM_CHARSET_4  '4'
  #define IDX_HELP              'h'

  int      hash_mode            = 0;
  int      hex_charset          = 0;
  int      markov_threshold     = CHARSIZ;
  char    *markov_hcstat        = SP_HCSTAT;
  char    *custom_charset_1     = NULL;
  char    *custom_charset_2     = NULL;
  char    *custom_charset_3     = NULL;
  char    *custom_charset_4     = NULL;

  char short_options[] = "hm:t:1:2:3:4:";

  struct option long_options[] =
  {
    {"hash-type",         required_argument, 0, IDX_HASH_MODE},
    {"hex-charset",       no_argument,       0, IDX_HEX_CHARSET},
    {"markov-threshold",  required_argument, 0, IDX_MARKOV_THRESHOLD},
    {"markov-hcstat",     required_argument, 0, IDX_MARKOV_HCSTAT},
    {"custom-charset1",   required_argument, 0, IDX_CUSTOM_CHARSET_1},
    {"custom-charset2",   required_argument, 0, IDX_CUSTOM_CHARSET_2},
    {"custom-charset3",   required_argument, 0, IDX_CUSTOM_CHARSET_3},
    {"custom-charset4",   required_argument, 0, IDX_CUSTOM_CHARSET_4},
    {"help",              no_argument,       0, IDX_HELP},

    {NULL, 0, 0, 0}
  };

  optind = 1;

  int option_index = 0;
  int help = 0;
  int c;

  while ((c = getopt_long (argc, argv, short_options, long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_HASH_MODE:         hash_mode         = atoi (optarg);  break;
      case IDX_HEX_CHARSET:       hex_charset       = 1;              break;
      case IDX_MARKOV_THRESHOLD:  markov_threshold  = atoi (optarg);  break;
      case IDX_MARKOV_HCSTAT:     markov_hcstat     = optarg;         break;
      case IDX_CUSTOM_CHARSET_1:  custom_charset_1  = optarg;         break;
      case IDX_CUSTOM_CHARSET_2:  custom_charset_2  = optarg;         break;
      case IDX_CUSTOM_CHARSET_3:  custom_charset_3  = optarg;         break;
      case IDX_CUSTOM_CHARSET_4:  custom_charset_4  = optarg;         break;
      case IDX_HELP:              help              = 1;              break;
    }
  }

  if (help == 1)
  {
    usage (argv[0]);

    exit (1);
  }

  if (optind < 1)
  {
    usage (argv[0]);

    return (-1);
  }

  char *mask = argv[optind];

  if (mask == NULL)
  {
    usage (argv[0]);


    return (-1);
  }

  int opts_type = 0;

  switch (hash_mode)
  {
    case   30:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case   40:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  130:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  131:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  132:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  133:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  140:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case  141:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1000:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1100:  opts_type |= OPTS_TYPE_PT_UNICODE;
                opts_type |= OPTS_TYPE_ST_UNICODE;  break;
    case 1430:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1440:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1441:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1730:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1731:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 1740:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 2100:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 5500:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 5600:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
    case 8000:  opts_type |= OPTS_TYPE_PT_UNICODE;  break;
  }

  cs_t mp_sys[6];
  cs_t mp_usr[4];

  memset (mp_sys, 0, sizeof (mp_sys));
  memset (mp_usr, 0, sizeof (mp_usr));

  mp_setup_sys (mp_sys);

  if (custom_charset_1) mp_setup_usr (mp_sys, mp_usr, strlen (custom_charset_1), (uint8_t *) custom_charset_1, 0, hex_charset);
  if (custom_charset_2) mp_setup_usr (mp_sys, mp_usr, strlen (custom_charset_2), (uint8_t *) custom_charset_2, 1, hex_charset);
  if (custom_charset_3) mp_setup_usr (mp_sys, mp_usr, strlen (custom_charset_3), (uint8_t *) custom_charset_3, 2, hex_charset);
  if (custom_charset_4) mp_setup_usr (mp_sys, mp_usr, strlen (custom_charset_4), (uint8_t *) custom_charset_4, 3, hex_charset);

  const uint64_t n = keyspace (strlen (mask), (uint8_t *) mask, mp_sys, mp_usr, markov_hcstat, markov_threshold, opts_type, hex_charset);

  printf ("%llu\n", (unsigned long long int) n);

  return 0;
}
