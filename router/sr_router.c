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

void send_icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                    uint8_t type, uint8_t code) { 
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
  icmp_header->icmp_type = type;
  send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
}