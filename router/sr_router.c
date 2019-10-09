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

void sr_init(struct sr_instance* sr)
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  switch(ethertype(packet)){
    case ethertype_ip: {
      printf("An IP Packet was received\n");
      handle_ip_packet(sr, packet, len, interface);
      break;
    }
    case ethertype_arp: {
      printf("An ARP Packet was received\n");
      handle_arp_packet(sr, packet, len, interface);
      break;
    }
  }

}

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_arpcache *sr_cache = &sr->cache;

  printf("*** -> Received IP packet of length %d \n",len);

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Check whether the length reach the minimum length requirment. */
  if (len < sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    perror("Error: The header length does not satisfy the minimum requirement");
  }

  /* Check whether the checksum are the same as requested. */
  uint16_t received_checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t actual_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  ip_hdr->ip_sum = received_checksum;
  if(received_checksum != actual_checksum) {
    perror("Error: The received checksum does not equal to the actual one.");
  }

  struct sr_if *target_iface = get_router_interface (ip_hdr->ip_dst, sr);

  /* If the IP packet is for interfaces of the router*/
  if (target_iface) {
    printf("The packet is for one of the interfaces of this router\n");
    uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr->ip_p); 
    switch(ip_p) {
      /* If the ip protocol is ICMP*/
      case ip_protocol_icmp: {
        printf("Packet is a ICMP echo request.\n");
              
        /* Check length reach the minimum length requirement of ICMP */
        if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_hdr->ip_hl * 4)) {
          perror("Error: The header length does not satisfy the minimum requirement");
        }


        /* Checksum for ICMP. */
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        uint16_t received_checksum = icmp_hdr->icmp_sum;
        uint16_t actual_checksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
        icmp_hdr->icmp_sum = received_checksum;
        if(received_checksum != actual_checksum) {
          perror("Error: The received checksum does not equal to the actual one.");
        }

        /* If it's ICMP echo req, send echo reply */
        if (icmp_hdr->icmp_type == icmp_echo_request) {
          send_echo_reply(sr, packet, len, interface);
        } else {
          printf("The type of ICMP packet is unknown.\n");
        }

      /* If it's TCP / UDP, send ICMP port unreachable */
      } 
      case ip_protocol_tcp:
      case ip_protocol_udp: {
        printf("Packet is a TCP/UDP message.\n");
        send_icmp_port_unreachable(sr, packet, len, interface);
      }
    }
  /* If the IP Packet is not for interfaces of the router. */
  } else {
    printf("If the IP Packet is not for interfaces of the router.\n");

    /* check routing table, and perform LPM */ 
    struct sr_rt* table_entry = get_longest_matching_prefix(sr, ip_hdr->ip_dst);
    if (table_entry) {
        /* find routing table indicated interface */
        struct sr_if* rt_out_interface = sr_get_interface(sr, table_entry->interface);
        /* check ARP cache */
        struct sr_arpentry * arp_entry = sr_arpcache_lookup (sr_cache, table_entry->gw.s_addr); 
        /* send frame to next hop*/
        if (arp_entry) {
            printf("There is a match in the ARP cache\n");
        }
    } else {
      
    }

  }
}


void send_echo_reply (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
}

void send_icmp_port_unreachable (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {

}

struct sr_rt * get_longest_matching_prefix (struct sr_instance* sr, uint32_t ip_dst) {
    struct sr_rt *routing_table = sr->routing_table;
    int len = 0; 
    struct sr_rt* rt_walker = 0;
    struct sr_rt* longest_prefix = 0;
    rt_walker = routing_table;
    while (rt_walker) {
        /* Compare the bitwise AND of target and the subnet mask with the bitwise AND of routing table entry and the subnet mask */
        if ((ip_dst & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
            if ((ip_dst & rt_walker->mask.s_addr) > len){
                len = ip_dst & rt_walker->mask.s_addr;
                longest_prefix = rt_walker;
            }
        }
        rt_walker = rt_walker->next; 
    }
    return longest_prefix;
}

/* end sr_ForwardPacket */

