typedef unsigned int uint;

int super_chop (char *s, const int len_orig)
{
  int len = len_orig;

  char *p = s + len - 1;

  while (len)
  {
    if (*p != '\n') break;

    *p-- = 0;

    len--;
  }

  while (len)
  {
    if (*p != '\r') break;

    *p-- = 0;

    len--;
  }

  return len;
}

int fgetl (FILE *fd, const size_t sz, char *buf)
{
  if (feof (fd)) return -1;

  char *s = fgets (buf, sz - 1, fd);

  if (s == NULL) return -1;

  const int len = (const int) strlen (s);

  return super_chop (s, len);
}

#ifdef _WINDOWS

uint get_random_num (const uint min, const uint max)
{
  if (min == max) return (min);

  const uint low = max - min;

  if (low == 0) return (0);

  uint64_t r = rand () % low;

  r += min;

  if (r > 0xffffffff)
  {
    exit (-1);
  }

  return (uint) r;
}

#else

uint get_random_num (const uint min, const uint max)
{
  if (min == max) return (min);

  const uint low = max - min;

  if (low == 0) return (0);

  uint data;

  FILE *fp = fopen("/dev/urandom", "rb");

  if (fp == NULL) exit (1);

  if ((fread (&data, 1, sizeof (uint), fp)) != sizeof (uint))
  {
    exit (-1);
  }

  fclose (fp);

  uint64_t r = data % low;

  r += min;

  if (r > 0xffffffff)
  {
    exit (-1);
  }

  return (uint) r;
}

#endif
