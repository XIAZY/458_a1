/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void process_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  /* packet is an eth packet */
  printf("got an ip packet\n");

  /* sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet; */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Print out all packet header for debugging */
  print_hdrs(packet, len);

  /* check whether packet meets the minimum length first */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
  {
    printf("Error: IP packet does not satisfy the minimum header length requirement.\n");
    return;
  }

  /* check checksum */
  printf("Compute cksum function: %d\n", cksum(ip_header, sizeof(sr_ip_hdr_t)));
  if (cksum(ip_header, sizeof(sr_ip_hdr_t)))
  { /* checksum is not zero */
    printf("Wrong Checksum: Ip packet has error inside.\n");
    return;
  }

  /* check that if this packet is for me */
  /* check if destination is one of the interface */
  struct sr_if *dst_interface = get_interface_from_ip(sr, ip_header->ip_dst);
  if (dst_interface)
  {
    /* interface is not null, for me !!! */
    printf("IP packet for me!!\n");
    switch (ip_header->ip_p)
    {
    case ip_protocol_icmp:
    {
      /* if ICMP echo reuqest */
      printf("A ICMP packet.\n");

      /* check whether packet meets the minimum length first */
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
      {
        printf("Error: ICMP packet does not satisfy the minimum header length requirement.\n");
        return;
      }

      /* find ICMP header */
      /* Question: is the echo request header a sr_icmp_hdr_t? or t3? */
      sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /* check checksum */
      if (cksum(icmp_header, sizeof(sr_icmp_hdr_t)))
      { /* checksum is not zero */
        printf("Wrong Checksum: Ip packet has error inside.\n");
        return;
      }

      /* check if icmp type is echo reply(8) */
      if (icmp_header->icmp_type == icmp_type_echo_request)
      {
        sr_send_icmp_message(sr, packet, len);
      }
      else
      {
        printf("ICMP packet is not an echo request. Ignore.\n");
        return;
      }
      break;
    }
    case ip_protocol_tcp:
    {
      /* if TCP or UDP -> ICMP port unreachable */
      printf("A TCP packet.\n");
      sr_send_t3_icmp_msg(sr, packet, len, unreachable_port);
      return;
    }
    case ip_protocol_udp:
    {
      printf("A UDP packet.\n");
      sr_send_t3_icmp_msg(sr, packet, len, unreachable_port);
      return;
    }
    default:
    {
      printf("Not ICMP, TCP or UDP packet. Ignore.\n");
      return;
    }
    }
  }
  else
  {
    /* not my packet */
    printf("IP packet not for me!!\n");

    /* Modify IP header (TTL) */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    ip_header->ip_ttl--;

    /* Check TTL, if 0: time exceeded */
    if (ip_header->ip_ttl == 0)
    {
      sr_send_t3_icmp_msg(sr, packet, len, timeout);
      return;
    }

    /* Recompute checksum for ip packet */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    /* check routing table to forward the packet */
    struct sr_rt *rt_entry = get_longest_prefix_match(sr, ip_header->ip_dst);
    if (!rt_entry)
    {
      /* no match in rt: ICMP net unreachable */
      printf("No matched destination ip in routing table.\n");
      sr_send_t3_icmp_msg(sr, packet, len, unreachable_net);
      return;
    }

    /* find exit interface */
    struct sr_if *interface = sr_get_interface(sr, rt_entry->interface);
    if (!interface)
    {
      printf("process_ip_packet: no interface ?????\n");
      return;
    }

    /* if match call send packet: check arp cache
         * -> hit: send to next hop
         * -> miss: send arp request */
    send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
  }

  /*========================================================================*/
  /* sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) packet + sizeof(sr_ethernet_hdr_t);
   * if (ip_header->ip_p == ip_protocol_icmp) {
   * send_icmp_echo(sr, packet, len, (uint8_t) 0);
   * }
   */
}

void process_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *if_str)
{
  /* packet is an eth packet */
  /* validate the packet */
  printf("got an arp packet\n");

  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    printf("arp request is too short\n");
    return;
  }

  if (ntohs(arp_header->ar_pro) != ethertype_ip)
  {
    printf("arp request addr format is not ip\n");
    return;
  }

  if (ntohs(arp_header->ar_hrd) != arp_hrd_ethernet)
  {
    printf("arp request hardware type is not ethernet\n");
    return;
  }

  struct sr_if *interface = sr_get_interface(sr, if_str);
  if (interface->ip != arp_header->ar_tip)
  {
    printf("this arp request is not for us\n");
    return;
  }
  /* check arp entry */
  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, arp_header->ar_sip);
  if (entry) {
    free(entry);
  } else {
      /* add it to the arp table */
      struct sr_arpreq* arp_request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
      if(arp_request != NULL) {
        /* send out the packets */
        send_arp_request(sr, arp_request);
      }
  }

  if (ntohs(arp_header->ar_op) == arp_op_request)
  {
    process_arp_packet_request(sr, packet, len, interface);
  }
}

void process_arp_packet_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface)
{
  /* packet is a ethernet packet */
  printf("got an arp request\n");
  sr_ethernet_hdr_t* request_eth_hdr = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* request_arp_hdr = (sr_arp_hdr_t*) (packet + sizeof (sr_ethernet_hdr_t));

  uint8_t* reply_packet = malloc(len);
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) reply_packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(ethernet_header + sizeof(sr_ethernet_hdr_t));

  memcpy(ethernet_header, request_eth_hdr, len);

  /* construct the reply arp header */
  /* set hardware format to ethernet */
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  /* set protocal address format to ip */
  arp_header->ar_pro = htons(ethertype_ip);
  /* set len of addr to ether addr len */
  arp_header->ar_hln = ETHER_ADDR_LEN;
  /* set len of ip addr to be 32 bit */
  arp_header->ar_pln = sizeof(uint32_t);
  /* set op type to be arp reply */
  arp_header->ar_op = htons(arp_op_reply);
  /* set dest ip to to source ip of request */
  arp_header->ar_tip = request_arp_hdr->ar_sip;
  /* set source ip to be the ip of interface */
  arp_header->ar_sip = interface->ip;

  /* construct ethernet header */
  /* change dest host to source */
  memcpy(ethernet_header->ether_dhost, request_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  /* change src host to interface */
  memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);

  send_packet(sr, reply_packet, len, interface, arp_header->ar_tip);
  free(reply_packet);
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  /* fill in code here */

  printf("*** -> Received packet of length %d \n", len);

  /* check whether packet meets the minimum length first */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    printf("Error: The header length does not satisfy the minimum requirement.\n");
    return;
  }

  uint16_t eth_type = ethertype(packet);
  printf("Received packet with ethernet type %d \n", eth_type);
  if (eth_type == ethertype_ip)
  {
    process_ip_packet(sr, packet, len, interface);
  }
  else if (eth_type == ethertype_arp)
  {
    process_arp_packet(sr, packet, len, interface);
  }

} /* end sr_ForwardPacket */

/* packet is an ethernet packet */
void send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, uint32_t destination_ip)
{
  printf("send packet\n");
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, destination_ip);
  if (entry)
  {
    printf("found entry\n");
    /* cast packet to a ethernet header */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    /* set dest and source mac */
    memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface->name);
    free(entry);
  }
  else
  {
    printf("entry unfound\n");
    /* process arp */
    struct sr_arpreq *arpreq = sr_arpcache_queuereq(
        &sr->cache, destination_ip, packet, len, interface->name);
    process_arp_request(sr, arpreq);
  }
}

void send_icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t code)
{
  /* set ip header src and dst */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_rt *rt_entry = get_longest_prefix_match(sr, ip_header->ip_src);
  struct sr_if *interface = sr_get_interface(sr, rt_entry->interface);
  uint32_t dst = ip_header->ip_src;
  ip_header->ip_src = ip_header->ip_dst;
  ip_header->ip_dst = dst;
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4));
  icmp_header->icmp_code = code;
  icmp_header->icmp_type = icmp_type_echo_reply;
  send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
}

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         char *interface /* lent */)
{
  /* struct sr_arpcache *sr_cache = &sr->cache; //??
     * sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
     */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_rt *rt_entry = get_longest_prefix_match(sr, ip_hdr->ip_src);

  /* Checksum for ICMP. */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t received_checksum = icmp_hdr->icmp_sum;
  uint16_t actual_checksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_sum = received_checksum;
  if (received_checksum != actual_checksum)
  {
    perror("Error: The received checksum does not equal to the actual one.");
  }

  struct sr_if *dest_itf = NULL;
  struct sr_if *itf = sr->if_list;
  while (itf)
  {
    if (itf->ip == ip_hdr->ip_dst)
    {
      dest_itf = itf;
      break;
    }
    itf = itf->next;
  }

  /* If the IP packet is for interfaces of the router*/
  if (dest_itf->ip)
  {
    printf("The packet is for one of the interfaces of this router\n");
    uint8_t ip_p = ip_protocol(&ip_hdr->ip_p);
    switch (ip_p)
    {
    /* If the ip protocol is ICMP*/
    case ip_protocol_icmp:
    {
      printf("Packet is a ICMP echo request.\n");

      /* Check length reach the minimum length requirement of ICMP */
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_hdr->ip_hl * 4))
      {
        perror("Error: The header length does not satisfy the minimum requirement");
      }

      /* Checksum for ICMP. */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      uint16_t received_checksum = icmp_hdr->icmp_sum;
      uint16_t actual_checksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_sum = received_checksum;
      if (received_checksum != actual_checksum)
      {
        perror("Error: The received checksum does not equal to the actual one.");
      }

      /* If it's ICMP echo req, send echo reply */
      if (icmp_hdr->icmp_type == icmp_type_echo_reply)
      {
        struct sr_if *itf = sr_get_interface(sr, interface);
        send_packet(sr, packet, len, itf, rt_entry->gw.s_addr);
      }
      else
      {
        printf("The type of ICMP packet is unknown.\n");
      }

      /* If it's TCP / UDP, send ICMP port unreachable */
    }
    case ip_protocol_tcp:
    case ip_protocol_udp:
    {
      printf("Packet is a TCP/UDP message.\n");
      sr_send_t3_icmp_msg(sr, packet, len, icmp_type_unreachable);
    }
    }
    /* If the IP Packet is not for interfaces of the router. */
  }
}
