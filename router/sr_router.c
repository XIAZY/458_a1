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
void process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
  /* packet is an eth packet */
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) packet + sizeof(sr_ethernet_hdr_t);
  if (ip_header->ip_p == ip_protocol_icmp) {
    send_icmp_echo(sr, packet, len, (uint8_t) 0);
  }
}
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
  if (ethertype(packet) == ethertype_ip) {
    process_ip_packet(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */


/* packet is an ethernet packet */
void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* interface, uint32_t destination_ip) {
  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, destination_ip);
  if (entry) {
    /* cast packet to a ethernet header */
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    /* set dest and source mac */
    memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface->name);
  } else {
    /* process arp */
    process_arp_request(sr, sr_arpcache_queuereq(
      &sr->cache, destination_ip, packet, len, interface->name
    ));
  }
}

void send_icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t code) { 
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

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct sr_arpcache *sr_cache = &sr->cache;
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
  printf("*** -> Received IP packet of length %d \n",len);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_rt *rt_entry = get_longest_prefix_match(sr, ip_hdr->ip_src);

  /* Check whether the length reach the minimum length requirment. */
  if (len < sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    perror("Error: The header length does not satisfy the minimum requirement");
  }

  /* Checksum for ICMP. */
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t received_checksum = icmp_hdr->icmp_sum;
  uint16_t actual_checksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_sum = received_checksum;
  if(received_checksum != actual_checksum) {
    perror("Error: The received checksum does not equal to the actual one.");
  }

  struct sr_if *dest_itf = NULL;
  struct sr_if* itf = sr->if_list;
  while (itf) {
    if (itf->ip == ip_hdr->ip_dst) {
      dest_itf = itf;
      break;
    }
    itf = itf->next;
  }

  /* If the IP packet is for interfaces of the router*/
  if (dest_itf->ip) {
    printf("The packet is for one of the interfaces of this router\n");
    uint8_t ip_p = ip_protocol(&ip_hdr->ip_p); 
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
        uint16_t actual_checksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_sum = received_checksum;
        if(received_checksum != actual_checksum) {
          perror("Error: The received checksum does not equal to the actual one.");
        }

        /* If it's ICMP echo req, send echo reply */
        if (icmp_hdr->icmp_type == icmp_type_echo_reply) {
          struct sr_if* itf = sr_get_interface(sr, interface);
          send_packet(sr, packet, len, itf, rt_entry->gw.s_addr);
        } else {
          printf("The type of ICMP packet is unknown.\n");
        }

      /* If it's TCP / UDP, send ICMP port unreachable */
      } 
      case ip_protocol_tcp:
      case ip_protocol_udp: {
        printf("Packet is a TCP/UDP message.\n");
        sr_send_unreachable_icmp_msg(sr, packet, len, icmp_type_unreachable);
      }
    }
  /* If the IP Packet is not for interfaces of the router. */
  } 
 //    else {
 //    printf("If the IP Packet is not for interfaces of the router.\n");

 //    /* check routing table, and perform LPM */ 
 //    struct sr_rt* table_entry = get_longest_matching_prefix(sr, ip_hdr->ip_dst);
 //    if (table_entry) {
 //        /* check ARP cache */
 //        struct sr_arpentry * arp_entry = sr_arpcache_lookup (sr_cache, table_entry->gw.s_addr); 
 //        /* send frame to next hop*/
 //        if (arp_entry) {
 //          printf("There is a match in the ARP cache\n");
 //        /* */ 
 //        } else {
 // /* TODO: to be continued */
 //        }
 //    } else {
 //      /* TODO: to be continued */

 //    }

 //  }
}