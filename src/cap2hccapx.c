#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <search.h>
#include <errno.h>
#include <inttypes.h>

#if defined (_WIN32) || defined (_WIN64)
typedef unsigned int lsearch_cnt_t;
#else
typedef size_t lsearch_cnt_t;
#endif

#pragma pack(1)

/**
 * Name........: cap2hccapx.c
 * Autor.......: Jens Steube <jens.steube@gmail.com>, Philipp "philsmd" Schmidt <philsmd@hashcat.net>
 * License.....: MIT
 */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// from pcap.h

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define TCPDUMP_CIGAM 0xd4c3b2a1

#define TCPDUMP_DECODE_LEN 65535

#define DLT_NULL        0   /* BSD loopback encapsulation */
#define DLT_EN10MB      1   /* Ethernet (10Mb) */
#define DLT_EN3MB       2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3   /* Amateur Radio AX.25 */
#define DLT_PRONET      4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5   /* Chaos */
#define DLT_IEEE802     6   /* IEEE 802 Networks */
#define DLT_ARCNET      7   /* ARCNET, with BSD-style header */
#define DLT_SLIP        8   /* Serial Line IP */
#define DLT_PPP         9   /* Point-to-point Protocol */
#define DLT_FDDI        10  /* FDDI */
#define DLT_RAW         12  /* Raw headers (no link layer) */
#define DLT_RAW2        14
#define DLT_RAW3        101

#define DLT_IEEE802_11  105 /* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO 127

struct pcap_file_header {
  u32 magic;
  u16 version_major;
  u16 version_minor;
  u32 thiszone; /* gmt to local correction */
  u32 sigfigs;  /* accuracy of timestamps */
  u32 snaplen;  /* max length saved portion of each pkt */
  u32 linktype; /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
	u32 tv_sec;   /* timestamp seconds */
	u32 tv_usec;  /* timestamp microseconds */
  u32 caplen;   /* length of portion present */
  u32 len;      /* length this packet (off wire) */
};

typedef struct pcap_file_header pcap_file_header_t;
typedef struct pcap_pkthdr pcap_pkthdr_t;

// from linux/ieee80211.h

struct ieee80211_hdr_3addr {
  u16 frame_control;
  u16 duration_id;
  u8  addr1[6];
  u8  addr2[6];
  u8  addr3[6];
  u16 seq_ctrl;

} __attribute__((packed));

struct ieee80211_qos_hdr {
  u16 frame_control;
  u16 duration_id;
  u8  addr1[6];
  u8  addr2[6];
  u8  addr3[6];
  u16 seq_ctrl;
  u16 qos_ctrl;

} __attribute__((packed));

typedef struct ieee80211_hdr_3addr ieee80211_hdr_3addr_t;
typedef struct ieee80211_qos_hdr   ieee80211_qos_hdr_t;

struct ieee80211_llc_snap_header
{
  /* LLC part: */
  u8 dsap;          /**< Destination SAP ID */
  u8 ssap;          /**< Source SAP ID */
  u8 ctrl;          /**< Control information */

  /* SNAP part: */
  u8 oui[3];        /**< Organization code, usually 0 */
  u16 ethertype;    /**< Ethernet Type field */

} __attribute__((packed));

typedef struct ieee80211_llc_snap_header ieee80211_llc_snap_header_t;

#define IEEE80211_FCTL_FTYPE        0x000c
#define IEEE80211_FCTL_STYPE        0x00f0
#define IEEE80211_FCTL_TODS         0x0100
#define IEEE80211_FCTL_FROMDS       0x0200

#define IEEE80211_FTYPE_MGMT        0x0000
#define IEEE80211_FTYPE_DATA        0x0008

#define IEEE80211_STYPE_PROBE_REQ   0x0040
#define IEEE80211_STYPE_PROBE_RESP  0x0050
#define IEEE80211_STYPE_BEACON      0x0080
#define IEEE80211_STYPE_QOS_DATA    0x0080

#define IEEE80211_LLC_DSAP              0xAA
#define IEEE80211_LLC_SSAP              0xAA
#define IEEE80211_LLC_CTRL              0x03
#define IEEE80211_DOT1X_AUTHENTICATION  0x8E88

/* Management Frame Information Element Types */
#define MFIE_TYPE_SSID      0
#define MFIE_TYPE_RATES     1
#define MFIE_TYPE_FH_SET    2
#define MFIE_TYPE_DS_SET    3
#define MFIE_TYPE_CF_SET    4
#define MFIE_TYPE_TIM       5
#define MFIE_TYPE_IBSS_SET  6
#define MFIE_TYPE_CHALLENGE 16
#define MFIE_TYPE_ERP       42
#define MFIE_TYPE_RSN       48
#define MFIE_TYPE_RATES_EX  50
#define MFIE_TYPE_GENERIC   221

// from ks7010/eap_packet.h

#define WBIT(n) (1 << (n))

#define WPA_KEY_INFO_TYPE_MASK (WBIT(0) | WBIT(1) | WBIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 WBIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES WBIT(1)
#define WPA_KEY_INFO_KEY_TYPE WBIT(3) /* 1 = Pairwise, 0 = Group key */
#define WPA_KEY_INFO_KEY_INDEX_MASK (WBIT(4) | WBIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL WBIT(6)  /* pairwise */
#define WPA_KEY_INFO_TXRX WBIT(6) /* group */
#define WPA_KEY_INFO_ACK WBIT(7)
#define WPA_KEY_INFO_MIC WBIT(8)
#define WPA_KEY_INFO_SECURE WBIT(9)
#define WPA_KEY_INFO_ERROR WBIT(10)
#define WPA_KEY_INFO_REQUEST WBIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA WBIT(12) /* IEEE 802.11i/RSN only */

// radiotap header from http://www.radiotap.org/

struct ieee80211_radiotap_header
{
  u8  it_version;     /* set to 0 */
  u8  it_pad;
  u16 it_len;         /* entire length */
  u32 it_present;     /* fields present */

} __attribute__((packed));

typedef struct ieee80211_radiotap_header ieee80211_radiotap_header_t;

// own structs

struct auth_packet
{
  u8  version;
  u8  type;
  u16 length;
  u8  key_descriptor;
  u16 key_information;
  u16 key_length;
  u64 replay_counter;
  u8  wpa_key_nonce[32];
  u8  wpa_key_iv[16];
  u8  wpa_key_rsc[8];
  u8  wpa_key_id[8];
  u8  wpa_key_mic[16];
  u16 wpa_key_data_length;

} __attribute__((packed));

typedef struct auth_packet auth_packet_t;

#define MAX_ESSID_LEN 32

typedef struct
{
  u8   bssid[6];
  char essid[MAX_ESSID_LEN + 4];
  int  essid_len;

} essid_t;

#define EAPOL_TTL 2

#define EXC_PKT_NUM_1 1
#define EXC_PKT_NUM_2 2
#define EXC_PKT_NUM_3 3
#define EXC_PKT_NUM_4 4

#define BROADCAST_MAC "\xff\xff\xff\xff\xff\xff"

typedef struct
{
  int excpkt_num;

  u32 tv_sec;
  u32 tv_usec;

  u64 replay_counter;

  u8  mac_ap[6];
  u8  mac_sta[6];

  u8  nonce[32];

  u16 eapol_len;
  u8  eapol[256];

  u8  keyver;
  u8  keymic[16];

} excpkt_t;

// databases

#define DB_ESSID_MAX  1000
#define DB_EXCPKT_MAX 100000

essid_t      *essids = NULL;
lsearch_cnt_t essids_cnt = 0;

excpkt_t     *excpkts = NULL;
lsearch_cnt_t excpkts_cnt = 0;

// output

#define HCCAPX_SIGNATURE 0x58504348 // HCPX

struct hccapx
{
  u32 signature;
  u32 version;
  u8  authenticated;
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

u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

u8 hex_to_u8 (const u8 hex[2])
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}

int comp_excpkt (const void *p1, const void *p2)
{
  excpkt_t *e1 = (excpkt_t *) p1;
  excpkt_t *e2 = (excpkt_t *) p2;

  const int excpkt_diff = e1->excpkt_num - e2->excpkt_num;

  if (excpkt_diff != 0) return excpkt_diff;

  const int rc_nonce = memcmp (e1->nonce, e2->nonce, 32);

  if (rc_nonce != 0) return rc_nonce;

  const int rc_mac_ap = memcmp (e1->mac_ap, e2->mac_ap, 6);

  if (rc_mac_ap != 0) return rc_mac_ap;

  const int rc_mac_sta = memcmp (e1->mac_sta, e2->mac_sta, 6);

  if (rc_mac_sta != 0) return rc_mac_sta;

  if (e1->replay_counter < e2->replay_counter) return  1;
  if (e1->replay_counter > e2->replay_counter) return -1;

  return 0;
}

int comp_bssid (const void *p1, const void *p2)
{
  essid_t *e1 = (essid_t *) p1;
  essid_t *e2 = (essid_t *) p2;

  return memcmp (e1->bssid, e2->bssid, 6);
}

static void db_excpkt_add (excpkt_t *excpkt, const u32 tv_sec, const u32 tv_usec, const u8 mac_ap[6], const u8 mac_sta[6])
{
  if (essids_cnt == DB_EXCPKT_MAX)
  {
    fprintf (stderr, "Too many excpkt in dumpfile, aborting...\n");

    exit (-1);
  }

  excpkt->tv_sec  = tv_sec;
  excpkt->tv_usec = tv_usec;

  memcpy (excpkt->mac_ap,  mac_ap,  6);
  memcpy (excpkt->mac_sta, mac_sta, 6);

  lsearch (excpkt, excpkts, &excpkts_cnt, sizeof (excpkt_t), comp_excpkt);
}

static void db_essid_add (essid_t *essid, const u8 addr3[6])
{
  if (essids_cnt == DB_ESSID_MAX)
  {
    fprintf (stderr, "Too many essid in dumpfile, aborting...\n");

    exit (-1);
  }

  memcpy (essid->bssid, addr3, 6);

  lsearch (essid, essids, &essids_cnt, sizeof (essid_t), comp_bssid);
}

static int handle_llc (const ieee80211_llc_snap_header_t *ieee80211_llc_snap_header)
{
  if (ieee80211_llc_snap_header->dsap != IEEE80211_LLC_DSAP) return -1;
  if (ieee80211_llc_snap_header->ssap != IEEE80211_LLC_SSAP) return -1;
  if (ieee80211_llc_snap_header->ctrl != IEEE80211_LLC_CTRL) return -1;

  if (ieee80211_llc_snap_header->ethertype != IEEE80211_DOT1X_AUTHENTICATION) return -1;

  return 0;
}

static int handle_auth (const auth_packet_t *auth_packet, const int pkt_offset, const int pkt_size, excpkt_t *excpkt)
{
  const u16 ap_key_information      = __builtin_bswap16 (auth_packet->key_information);
  const u16 ap_length               = __builtin_bswap16 (auth_packet->length);
  const u16 ap_wpa_key_data_length  = __builtin_bswap16 (auth_packet->wpa_key_data_length);
  const u64 ap_replay_counter       = __builtin_bswap64 (auth_packet->replay_counter);

  if (ap_length == 0) return -1;

  // determine handshake exchange number

  int excpkt_num = 0;

  if (ap_key_information & WPA_KEY_INFO_ACK)
  {
    if (ap_key_information & WPA_KEY_INFO_INSTALL)
    {
      excpkt_num = EXC_PKT_NUM_3;
    }
    else
    {
      excpkt_num = EXC_PKT_NUM_1;
    }
  }
  else
  {
    if (ap_key_information & WPA_KEY_INFO_SECURE)
    {
      excpkt_num = EXC_PKT_NUM_4;
    }
    else
    {
      excpkt_num = EXC_PKT_NUM_2;
    }
  }

  // process packet based on handshake exchange number

  excpkt->excpkt_num = excpkt_num;

  memcpy (excpkt->nonce, auth_packet->wpa_key_nonce, 32);

  excpkt->replay_counter = ap_replay_counter;

  if (excpkt_num == EXC_PKT_NUM_1)
  {
    // nothing to do
  }
  else if (excpkt_num == EXC_PKT_NUM_2)
  {
    excpkt->eapol_len = sizeof (auth_packet_t) + ap_wpa_key_data_length;

    if ((pkt_offset + excpkt->eapol_len) > pkt_size) return -1;

    if ((sizeof (auth_packet_t) + ap_wpa_key_data_length) > sizeof (excpkt->eapol)) return -1;

    // we need to copy the auth_packet_t but have to clear the keymic
    auth_packet_t auth_packet_orig;

    memcpy (&auth_packet_orig, auth_packet, sizeof (auth_packet_t));

    memset (auth_packet_orig.wpa_key_mic, 0, 16);

    memcpy (excpkt->eapol, &auth_packet_orig, sizeof (auth_packet_t));
    memcpy (excpkt->eapol + sizeof (auth_packet_t), auth_packet + 1, ap_wpa_key_data_length);

    memcpy (excpkt->keymic, auth_packet->wpa_key_mic, 16);

    excpkt->keyver = ap_key_information & WPA_KEY_INFO_TYPE_MASK;
  }
  else if (excpkt_num == EXC_PKT_NUM_3)
  {
    // reduce by one

    excpkt->replay_counter--;
  }
  else if (excpkt_num == EXC_PKT_NUM_4)
  {
    return -1;
  }
  else
  {
    return -1;
  }

  return 0;
}

static int get_essid_from_user (char *s)
{
  essid_t essid;

  memset (&essid, 0, sizeof (essid_t));

  char *man_essid = s;
  char *man_bssid = strchr (man_essid, ':');

  if (man_bssid == NULL)
  {
    fprintf (stderr, "Invalid format (%s), should be: MyESSID:d110391a58ac\n", s);

    return -1;
  }

  *man_bssid = 0;

  man_bssid++;

  if (strlen (man_essid) >= 32)
  {
    fprintf (stderr, "Invalid format (%s), essid is too long\n", s);

    return -1;
  }

  if (strlen (man_bssid) != 12)
  {
    fprintf (stderr, "Invalid format (%s), bssid must have length 12\n", s);

    return -1;
  }

  strncpy (essid.essid, man_essid, 32);

  essid.essid_len = strlen (essid.essid);

  essid.bssid[0] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;
  essid.bssid[1] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;
  essid.bssid[2] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;
  essid.bssid[3] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;
  essid.bssid[4] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;
  essid.bssid[5] = hex_to_u8 ((u8 *) man_bssid); man_bssid += 2;

  lsearch (&essid, essids, &essids_cnt, sizeof (essid_t), comp_bssid);

  return 0;
}

static int get_essid_from_beacon (const u8 *packet, const pcap_pkthdr_t *header, u32 length_skip, essid_t *essid)
{
  if (length_skip > header->caplen) return -1;

  u32 length = header->caplen - length_skip;

  const u8 *beacon = packet + length_skip;

  const u8 *cur = beacon;
  const u8 *end = beacon + length;

  while (cur < end)
  {
    if ((cur + 2) >= end) break;

    u8 tagtype = *cur++;
    u8 taglen  = *cur++;

    if ((cur + taglen) >= end) break;

    if (tagtype == MFIE_TYPE_SSID)
    {
      if (taglen < MAX_ESSID_LEN)
      {
        memcpy (essid->essid, cur, taglen);

        essid->essid_len = taglen;

        return 0;
      }
    }

    cur += taglen;
  }

  return -1;
}

static void process_packet (const u8 *packet, const pcap_pkthdr_t *header)
{
  if (header->caplen < sizeof (ieee80211_hdr_3addr_t)) return;

  // our first header: ieee80211

  ieee80211_hdr_3addr_t *ieee80211_hdr_3addr = (ieee80211_hdr_3addr_t *) packet;

  const u16 frame_control = ieee80211_hdr_3addr->frame_control;

  if ((frame_control & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT)
  {
    if (memcmp (ieee80211_hdr_3addr->addr3, BROADCAST_MAC, 6) == 0) return;

    essid_t essid;

    memset (&essid, 0, sizeof (essid_t));

    int rc_beacon = -1;

    const int stype = frame_control & IEEE80211_FCTL_STYPE;

    if ((stype == IEEE80211_STYPE_BEACON) || (stype == IEEE80211_STYPE_PROBE_RESP))
    {
      u32 length_skip = sizeof (ieee80211_hdr_3addr_t) + sizeof (u64) + sizeof (u16) + sizeof (u16);

      rc_beacon = get_essid_from_beacon (packet, header, length_skip, &essid);
    }
    else if (stype == IEEE80211_STYPE_PROBE_REQ)
    {
      u32 length_skip = sizeof (ieee80211_hdr_3addr_t);

      rc_beacon = get_essid_from_beacon (packet, header, length_skip, &essid);
    }

    if (rc_beacon == -1) return;

    if (essid.essid_len == 0) return;

    // add the beacon to our database

    db_essid_add (&essid, ieee80211_hdr_3addr->addr3);
  }
  else if ((frame_control & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)
  {
    // process header: ieee80211

    int set = 0;

    if (frame_control & IEEE80211_FCTL_TODS)   set++;
    if (frame_control & IEEE80211_FCTL_FROMDS) set++;

    if (set != 1) return;

    // find offset to llc/snap header

    int llc_offset;

    if ((frame_control & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_QOS_DATA)
    {
      llc_offset = sizeof (ieee80211_qos_hdr_t);
    }
    else
    {
      llc_offset = sizeof (ieee80211_hdr_3addr_t);
    }

    // process header: the llc/snap header

    if (header->caplen < (llc_offset + sizeof (ieee80211_llc_snap_header_t))) return;

    const ieee80211_llc_snap_header_t *ieee80211_llc_snap_header = (ieee80211_llc_snap_header_t *) &packet[llc_offset];

    const int rc_llc = handle_llc (ieee80211_llc_snap_header);

    if (rc_llc == -1) return;

    // process header: the auth header

    const int auth_offset = llc_offset + sizeof (ieee80211_llc_snap_header_t);

    if (header->caplen < (auth_offset + sizeof (auth_packet_t))) return;

    const auth_packet_t *auth_packet = (auth_packet_t *) &packet[auth_offset];

    excpkt_t excpkt;

    memset (&excpkt, 0, sizeof (excpkt_t));

    const int rc_auth = handle_auth (auth_packet, auth_offset, header->caplen, &excpkt);

    if (rc_auth == -1) return;

    if ((excpkt.excpkt_num == EXC_PKT_NUM_1) || (excpkt.excpkt_num == EXC_PKT_NUM_3))
    {
      db_excpkt_add (&excpkt, header->tv_sec, header->tv_usec, ieee80211_hdr_3addr->addr2, ieee80211_hdr_3addr->addr1);
    }
    else if (excpkt.excpkt_num == EXC_PKT_NUM_2)
    {
      db_excpkt_add (&excpkt, header->tv_sec, header->tv_usec, ieee80211_hdr_3addr->addr1, ieee80211_hdr_3addr->addr2);
    }
  }
}

int main (int argc, char *argv[])
{
  if ((argc != 3) && (argc != 4) && (argc != 5))
  {
    fprintf (stderr, "usage: %s input.pcap output.hccapx [filter by essid] [additional network essid:bssid]\n", argv[0]);

    return -1;
  }

  char *in  = argv[1];
  char *out = argv[2];

  char *essid_filter = NULL;

  if (argc >= 4) essid_filter = argv[3];

  // database initializations

  essids = (essid_t *) calloc (DB_ESSID_MAX, sizeof (essid_t));
  essids_cnt = 0;

  excpkts = (excpkt_t *) calloc (DB_EXCPKT_MAX, sizeof (excpkt_t));
  excpkts_cnt = 0;

  // manual beacon

  if (argc >= 5)
  {
    const int rc = get_essid_from_user (argv[4]);

    if (rc == -1) return -1;
  }

  // start with pcap handling

  FILE *pcap = fopen (in, "rb");

  if (pcap == NULL)
  {
    fprintf (stderr, "%s: %s\n", in, strerror (errno));

    return -1;
  }

  // check pcap header

  pcap_file_header_t pcap_file_header;

  const int nread = fread (&pcap_file_header, sizeof (pcap_file_header_t), 1, pcap);

  if (nread != 1)
  {
    fprintf (stderr, "%s: Could not read pcap header\n", in);

    return -1;
  }

  int bitness = 0;

  if (pcap_file_header.magic == TCPDUMP_MAGIC)
  {
    bitness = 0;
  }
  else if (pcap_file_header.magic == TCPDUMP_CIGAM)
  {
    bitness = 1;
  }
  else
  {
    fprintf (stderr, "%s: Invalid pcap header\n", in);

    return 1;
  }

  if (bitness == 1)
  {
    pcap_file_header.magic          = __builtin_bswap32 (pcap_file_header.magic);
    pcap_file_header.version_major  = __builtin_bswap16 (pcap_file_header.version_major);
    pcap_file_header.version_minor  = __builtin_bswap16 (pcap_file_header.version_minor);
    pcap_file_header.thiszone       = __builtin_bswap32 (pcap_file_header.thiszone);
    pcap_file_header.sigfigs        = __builtin_bswap32 (pcap_file_header.sigfigs);
    pcap_file_header.snaplen        = __builtin_bswap32 (pcap_file_header.snaplen);
    pcap_file_header.linktype       = __builtin_bswap32 (pcap_file_header.linktype);
  }

  if ((pcap_file_header.linktype != DLT_IEEE802_11) && (pcap_file_header.linktype != DLT_IEEE802_11_RADIO))
  {
    fprintf (stderr, "%s: Unsupported linktype detected\n", in);

    return -1;
  }

  // walk the packets

  while (!feof (pcap))
  {
    pcap_pkthdr_t header;

    const int nread1 = fread (&header, sizeof (pcap_pkthdr_t), 1, pcap);

    if (nread1 != 1) continue;

    if (bitness == 1)
    {
      header.tv_sec   = __builtin_bswap32 (header.tv_sec);
      header.tv_usec  = __builtin_bswap32 (header.tv_usec);
      header.caplen   = __builtin_bswap32 (header.caplen);
      header.len      = __builtin_bswap32 (header.len);
    }

    u8 packet[TCPDUMP_DECODE_LEN];

    if (header.caplen >= TCPDUMP_DECODE_LEN)
    {
      fprintf (stderr, "%s: Oversized packet detected\n", in);

      return -1;
    }

    const u32 nread2 = fread (&packet, sizeof (u8), header.caplen, pcap);

    if (nread2 != header.caplen)
    {
      fprintf (stderr, "%s: Could not read pcap packet data\n", in);

      return -1;
    }

    u8 *packet_ptr = packet;

  	if (pcap_file_header.linktype == DLT_IEEE802_11_RADIO)
    {
      if (header.caplen < sizeof (ieee80211_radiotap_header_t))
      {
        fprintf (stderr, "%s: Could not read radiotap header\n", in);

        return -1;
      }

      ieee80211_radiotap_header_t *ieee80211_radiotap_header = (ieee80211_radiotap_header_t *) packet;

      if (ieee80211_radiotap_header->it_version != 0)
      {
        fprintf (stderr, "%s: Invalid radiotap header\n", in);

        return -1;
      }

      packet_ptr    += ieee80211_radiotap_header->it_len;
      header.caplen -= ieee80211_radiotap_header->it_len;
      header.len    -= ieee80211_radiotap_header->it_len;
    }

    process_packet (packet_ptr, &header);
  }

  fclose (pcap);

  // inform the user

  printf ("Networks detected: %d\n", (int) essids_cnt);
  printf ("\n");

  if (essids_cnt == 0) return 0;

  // prepare output files

  FILE *fp = fopen (out, "wb");

  if (fp == NULL)
  {
    fprintf (stderr, "%s: %s\n", out, strerror (errno));

    return -1;
  }

  int written = 0;

  // find matching packets

  for (lsearch_cnt_t essids_pos = 0; essids_pos < essids_cnt; essids_pos++)
  {
    const essid_t *essid = essids + essids_pos;

    if (essid_filter) if (strcmp (essid->essid, essid_filter)) continue;

    printf ("[*] BSSID=%02x:%02x:%02x:%02x:%02x:%02x ESSID=%s (Length: %d)\n",
      essid->bssid[0],
      essid->bssid[1],
      essid->bssid[2],
      essid->bssid[3],
      essid->bssid[4],
      essid->bssid[5],
      essid->essid,
      essid->essid_len);

    for (lsearch_cnt_t excpkt_ap_pos = 0; excpkt_ap_pos < excpkts_cnt; excpkt_ap_pos++)
    {
      const excpkt_t *excpkt_ap = excpkts + excpkt_ap_pos;

      if ((excpkt_ap->excpkt_num != EXC_PKT_NUM_1) && (excpkt_ap->excpkt_num != EXC_PKT_NUM_3)) continue;

      if (memcmp (essid->bssid, excpkt_ap->mac_ap, 6) != 0) continue;

      for (lsearch_cnt_t excpkt_sta_pos = 0; excpkt_sta_pos < excpkts_cnt; excpkt_sta_pos++)
      {
        const excpkt_t *excpkt_sta = excpkts + excpkt_sta_pos;

        if (excpkt_sta->excpkt_num != EXC_PKT_NUM_2) continue;

        if (memcmp (excpkt_ap->mac_ap,  excpkt_sta->mac_ap,  6) != 0) continue;
        if (memcmp (excpkt_ap->mac_sta, excpkt_sta->mac_sta, 6) != 0) continue;

        if (excpkt_ap->replay_counter != excpkt_sta->replay_counter) continue;

        if (excpkt_ap->excpkt_num == EXC_PKT_NUM_1)
        {
          if (excpkt_ap->tv_sec > excpkt_sta->tv_sec) continue;

          if ((excpkt_ap->tv_sec + EAPOL_TTL) < excpkt_sta->tv_sec) continue;
        }
        else
        {
          if (excpkt_sta->tv_sec > excpkt_ap->tv_sec) continue;

          if ((excpkt_sta->tv_sec + EAPOL_TTL) < excpkt_ap->tv_sec) continue;
        }

        const u8 authenticated = (excpkt_ap->excpkt_num == EXC_PKT_NUM_3);

        printf (" --> STA=%02x:%02x:%02x:%02x:%02x:%02x, Authenticated=%u, Replay Counter=%" PRIu64 "\n",
          excpkt_sta->mac_sta[0],
          excpkt_sta->mac_sta[1],
          excpkt_sta->mac_sta[2],
          excpkt_sta->mac_sta[3],
          excpkt_sta->mac_sta[4],
          excpkt_sta->mac_sta[5],
          authenticated,
          excpkt_sta->replay_counter);

        // finally, write hccapx

        hccapx_t hccapx;

        hccapx.signature = HCCAPX_SIGNATURE;
        hccapx.version = 3;

        hccapx.authenticated = authenticated;

        hccapx.essid_len = essid->essid_len;
        memcpy (&hccapx.essid, essid->essid, 32);

        hccapx.keyver = excpkt_sta->keyver;
        memcpy (&hccapx.keymic, excpkt_sta->keymic, 16);

        memcpy (&hccapx.mac_ap, excpkt_ap->mac_ap, 6);
        memcpy (&hccapx.nonce_ap, excpkt_ap->nonce, 32);

        memcpy (&hccapx.mac_sta, excpkt_sta->mac_sta, 6);
        memcpy (&hccapx.nonce_sta, excpkt_sta->nonce, 32);

        hccapx.eapol_len = excpkt_sta->eapol_len;
        memcpy (&hccapx.eapol, excpkt_sta->eapol, 256);

        fwrite (&hccapx, sizeof (hccapx_t), 1, fp);

        written++;
      }
    }
  }

  printf ("\n");
  printf ("Written %d WPA Handshakes to: %s\n", written, out);

  fclose (fp);

  // clean up

  free (excpkts);
  free (essids);

  return 0;
}
