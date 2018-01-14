#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#pragma pack(1)

/**
 * Name........: hccapx-deduper.c
 * Autor.......: Chris Lundquist
 * License.....: MIT
 */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// from pcap.h

#define HCCAPX_VERSION   4
#define HCCAPX_SIGNATURE 0x58504348 // HCPX

struct hccapx
{
  u32 signature;
  u32 version;
  u8  message_pair;
  u8  essid_len;
  u8  essid[32];
  u8  keyver;
  u8  keymic[16];
  u8  mac_ap[6];
  u8  nonce_ap[32];
  u8  mac_sta[6];
  u8  nonce_sta[32];
  u16 eapol_len;
  u8  eapol[256];

} __attribute__((packed));

typedef struct hccapx hccapx_t;

// functions

int comp_handshake(const void *p1, const void *p2)
{
  hccapx_t* e1 = (hccapx_t*) p1;
  hccapx_t* e2 = (hccapx_t*) p2;
  const int essid_diff = memcmp(&e1->essid, &e2->essid, 32);
  if (essid_diff != 0) return essid_diff;
  const int message_pair_diff = memcmp(&e1->message_pair, &e2->message_pair, 1);
  if (essid_diff != 0) return message_pair_diff;
}

int main (int argc, char *argv[])
{
  if ((argc != 3))
  {
    fprintf (stderr, "usage: %s input.hccapx output.hccapx\n", argv[0]);

    return -1;
  }

  char *in  = argv[1];
  char *out = argv[2];

  FILE *input = fopen (in, "rb");

  if (input == NULL)
  {
    fprintf (stderr, "%s: %s\n", in, strerror (errno));

    return -1;
  }

  fseek(input, 0L, SEEK_END);
  const int input_size = ftell(input);
  rewind(input);

  if (input_size % sizeof(hccapx_t) != 0)
  {
    fprintf (stderr, "%s: Possible corrupt input file\n", in);
    return -1;
  }

  const int num_handshakes = input_size / sizeof(hccapx_t);

  hccapx_t* handshakes = calloc(num_handshakes, sizeof(hccapx_t));

  const int nread1 = fread (handshakes, sizeof (hccapx_t), num_handshakes, input);

  printf("Read %d handshakes\n", num_handshakes);

  qsort(handshakes, num_handshakes, sizeof(hccapx_t), comp_handshake);
  FILE* output = fopen(out, "wb");
  fwrite(&handshakes[0], sizeof(hccapx_t), 1, output);
  hccapx_t last_written_handshake = handshakes[0];

  int written = 1;
  for(int i = 1; i < num_handshakes; i++) {
    if( comp_handshake(&last_written_handshake, &handshakes[i]) == 0)
      continue;

    fwrite(&handshakes[i], sizeof(hccapx_t), 1, output);
    last_written_handshake = handshakes[i];
    //printf("name: %s\n", handshakes[i].essid);
    //printf("handshake_pair: %d\n", handshakes[i].message_pair);
    written++;
  }
  printf("Filtered: %d handshakes\n", num_handshakes - written);
  printf("Wrote: %d handshakes\n", written);



  fclose(input);
  fclose(output);
  free(handshakes);

  return 0;
}
