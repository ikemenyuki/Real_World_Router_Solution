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
#include <stdlib.h>
#include <string.h>


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
  uint8_t* packet/* lent */,
  unsigned int len,
  char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* check if the packet is for IP */
  if (ethertype(packet) == ethertype_ip) {
    handle_ip(sr, packet, len, interface);
  }

  /* check if the packet is for ARP */
  else if (ethertype(packet) == ethertype_arp) {

    /* verify the length of arp packet */
    unsigned int size_ehdr = sizeof(sr_ethernet_hdr_t);
    unsigned int size_arphdr = sizeof(sr_arp_hdr_t);
    if (len < size_arphdr + size_ehdr) return;

    /* if the packet is an arp request to router */
    sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(packet + size_ehdr);

    if (ntohs(arphdr->ar_op) == arp_op_reply) {
      handle_arp_reply(sr, packet, len, interface);
    }
    else if (ntohs(arphdr->ar_op) == arp_op_request) {
      handle_arp_request(sr, packet, len, interface);
    }
  }

}/* end sr_ForwardPacket */

int ip_packet_sanity_check(sr_ip_hdr_t* iphdr, unsigned int len) {

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    return 0;
  uint16_t old_cksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  if (old_cksum != cksum(iphdr, sizeof(sr_ip_hdr_t)))
    return 0;

  return 1;
}

/* check if ARP request is for one of its ips */
struct sr_if* check_packet_ip(uint32_t packet_ip, struct sr_instance* sr) {
  struct sr_if* if_walker = 0;

  /* -- REQUIRES -- */
  assert(packet_ip);
  assert(sr);

  if_walker = sr->if_list;

  while (if_walker)
  {
    if (if_walker->ip == packet_ip)
    {
      return if_walker;
    }
    if_walker = if_walker->next;
  }

  return NULL;
}

void handle_arp_reply(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  unsigned int len,
  char* inface/* lent */) {

  /* check if the arp reply is sent to the router */
  sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  if (!check_packet_ip(arphdr->ar_tip, sr))
    return;

  /* also check if packet's target ip is the same as the ip of interface */
  struct sr_if* interface = sr_get_interface(sr, inface);
  if (arphdr->ar_tip != interface->ip)
    return;

  /* get the MAC addr of host who replied to ARP request */
  struct sr_arpcache* sr_cache = &(sr->cache);

  /* look up the arp cache request in the cache
   * find the the req in the queue whose ip matches the arp src ip */

  struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, arphdr->ar_sip);

  /* return if not such req is found */
  if (!req) return;

  /* send out all the packets waiting for the MAC addr */
  struct sr_packet* waiting_pkt;
  for (waiting_pkt = req->packets; waiting_pkt != NULL; waiting_pkt = waiting_pkt->next) {
    sr_ethernet_hdr_t* ehdr_p = (sr_ethernet_hdr_t*)waiting_pkt->buf;
    memcpy(ehdr_p->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
    sr_send_packet(sr, waiting_pkt->buf, waiting_pkt->len, waiting_pkt->iface);
  }

  /* destroy the request in queue and return */
  sr_arpreq_destroy(sr_cache, req);
}

void handle_arp_request(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  unsigned int len,
  char* inface/* lent */) {

  /* check if the packet is for one of its ips */
  int size_ehdr = sizeof(sr_ethernet_hdr_t);
  sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(packet + size_ehdr);
  uint32_t p_ip = arphdr->ar_tip;
  if (!check_packet_ip(p_ip, sr))
    return;

  /* onstruct an ARP reply to the ARP request
   * update the necessary fields */
  struct sr_if* interface = sr_get_interface(sr, inface);

  /* check if the packet ip also matches interface's ip */
  if (p_ip != interface->ip)
    return;

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
  uint8_t old_ether_shost[ETHER_ADDR_LEN];
  memcpy(old_ether_shost, ehdr->ether_shost, ETHER_ADDR_LEN);
  unsigned char interface_addr[ETHER_ADDR_LEN];
  memcpy(interface_addr, interface->addr, ETHER_ADDR_LEN);
  uint32_t new_ar_tip = arphdr->ar_sip;
  uint32_t new_ar_sip = p_ip;

  /* update the packet's ethernet header */
  memcpy(ehdr->ether_dhost, old_ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, interface_addr, ETHER_ADDR_LEN);

  /* update the packet's ARP header */
  arphdr->ar_sip = new_ar_sip;
  arphdr->ar_tip = new_ar_tip;
  arphdr->ar_op = htons(arp_op_reply);
  memcpy(arphdr->ar_sha, ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(arphdr->ar_tha, ehdr->ether_dhost, ETHER_ADDR_LEN);

  /* send out the arp reply (modified packet) */
  sr_send_packet(sr, packet, len, inface);
}

struct sr_rt* rtable_lookup(struct sr_instance* sr,
  uint32_t dst_ip/* lent */
) {

  struct sr_rt* entry = sr->routing_table;

  /* do longest prefix matching here*/
  uint32_t cur_longest_subnetmask = 0;
  struct sr_rt* cur_LMP_entry = NULL;
  while (entry) {
    if ((dst_ip & entry->mask.s_addr) == entry->dest.s_addr) {
      if (entry->mask.s_addr > cur_longest_subnetmask) {
        cur_longest_subnetmask = entry->mask.s_addr;
        cur_LMP_entry = entry;
      }
    }
    entry = entry->next;
  }

  /* no match found*/
  if (cur_longest_subnetmask == 0)
    return NULL;
  return cur_LMP_entry;
}

void handle_icmp_requests(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  sr_ip_hdr_t* iphdr,
  char* interface/* lent */,
  unsigned int len,
  sr_icmp_t11_hdr_t* icmphdr
) {

  /* send out an echo reply */
  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
  uint8_t old_ether_shost[ETHER_ADDR_LEN];
  memcpy(old_ether_shost, ehdr->ether_shost, ETHER_ADDR_LEN);
  uint8_t old_ether_dhost[ETHER_ADDR_LEN];
  memcpy(old_ether_dhost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  uint32_t old_ip_src = iphdr->ip_src;
  uint32_t old_ip_dst = iphdr->ip_dst;

  /* update the corresponding fields in ip header */
  memcpy(ehdr->ether_dhost, old_ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, old_ether_dhost, ETHER_ADDR_LEN);
  iphdr->ip_src = old_ip_dst;
  iphdr->ip_dst = old_ip_src;
  iphdr->ip_ttl = 255;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

  /* update fields in icmp header */
  icmphdr->icmp_type = (uint8_t)0;
  icmphdr->icmp_code = (uint8_t)0;
  icmphdr->icmp_sum = 0;
  icmphdr->icmp_sum = cksum(icmphdr, sizeof(sr_icmp_t11_hdr_t));

  /* send out the icmp reply packet */
  sr_send_packet(sr, packet, len, interface);
}

void icmp_queue_packet(struct sr_instance* sr,
  struct sr_arpcache* cache,
  uint32_t next_hop_ip,
  uint8_t* packet/* lent */,
  unsigned int len,
  char* interface/* lent */) {

  struct sr_arpreq* req = sr_arpcache_queuereq(cache, next_hop_ip, packet, len, interface);
  handle_arpreq(sr, req);
}

void send_err_msg(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  sr_ip_hdr_t* original_iphdr,
  uint8_t type,
  uint8_t code) {

  /* lookup through next-hop addr in rable
   * only forward if there exists and entry in rtable */
  struct sr_rt* rt_entry = rtable_lookup(sr, original_iphdr->ip_src);
  uint32_t next_hop_ip = rt_entry->gw.s_addr;

  /* build a new error packet */
  uint8_t* tm_excd_err_pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));

  struct sr_if* iface = sr_get_interface(sr, rt_entry->interface);
  sr_ethernet_hdr_t* original_ehdr = (sr_ethernet_hdr_t*)packet;
  sr_ethernet_hdr_t* err_pkt_ehdr = (sr_ethernet_hdr_t*)tm_excd_err_pkt;
  memcpy(err_pkt_ehdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  err_pkt_ehdr->ether_type = original_ehdr->ether_type;

  sr_ip_hdr_t* err_pkt_iphdr = (sr_ip_hdr_t*)(tm_excd_err_pkt + sizeof(sr_ethernet_hdr_t));
  err_pkt_iphdr->ip_tos = original_iphdr->ip_tos;
  err_pkt_iphdr->ip_hl = original_iphdr->ip_hl;
  err_pkt_iphdr->ip_v = original_iphdr->ip_v;
  err_pkt_iphdr->ip_id = original_iphdr->ip_id;
  err_pkt_iphdr->ip_off = original_iphdr->ip_off;

  err_pkt_iphdr->ip_p = ip_protocol_icmp;
  err_pkt_iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  err_pkt_iphdr->ip_ttl = 255;
  err_pkt_iphdr->ip_dst = original_iphdr->ip_src;
  err_pkt_iphdr->ip_src = iface->ip;
  err_pkt_iphdr->ip_sum = 0;
  err_pkt_iphdr->ip_sum = cksum(err_pkt_iphdr, sizeof(sr_ip_hdr_t));

  sr_icmp_t11_hdr_t* err_pkt_icmphdr = (sr_icmp_t11_hdr_t*)(tm_excd_err_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_icmp_t11_hdr_t* original_icmphdr = (sr_icmp_t11_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  err_pkt_icmphdr->icmp_type = type;
  err_pkt_icmphdr->icmp_code = code;
  err_pkt_icmphdr->unused = original_icmphdr->unused;
  memcpy(err_pkt_icmphdr->data, original_iphdr, ICMP_DATA_SIZE);
  err_pkt_icmphdr->icmp_sum = 0;
  err_pkt_icmphdr->icmp_sum = cksum(err_pkt_icmphdr, sizeof(sr_icmp_t11_hdr_t));

  /* send ARP request to get the MAC addr of next-hop ip */
  icmp_queue_packet(sr, &(sr->cache), next_hop_ip, tm_excd_err_pkt,
    sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ip_hdr_t), rt_entry->interface);
}

void forward_packet_next_hop(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  sr_ip_hdr_t* iphdr,
  unsigned int len) {

  struct sr_rt* rt_entry = rtable_lookup(sr, iphdr->ip_dst);
  if (!rt_entry) {

    /* ip not in routing table */
    send_err_msg(sr, packet, iphdr, (uint8_t)3, (uint8_t)0);
    return;
  }

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
  struct sr_if* iface = sr_get_interface(sr, rt_entry->interface);
  memcpy(ehdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  iphdr->ip_ttl--;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

  /* look through the ARP cache*/
  struct sr_arpentry* cache_entry = sr_arpcache_lookup(&(sr->cache), iphdr->ip_dst);

  /* entry found in cache with ip dest addr */
  if (cache_entry) {
    memcpy(ehdr->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, rt_entry->interface);
    return;
  }

  /* append packet to arp queue */
  uint32_t next_hop_ip = rt_entry->gw.s_addr;
  icmp_queue_packet(sr, &(sr->cache), next_hop_ip, packet, len, rt_entry->interface);
}

void handle_ip(struct sr_instance* sr,
  uint8_t* packet/* lent */,
  unsigned int len,
  char* interface/* lent */) {

  sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  if (!ip_packet_sanity_check(iphdr, len)) return;

  /* check if the ip packet is destined to one of router's ip */
  struct sr_if* packet_inface = check_packet_ip(iphdr->ip_dst, sr);
  if (packet_inface != NULL) { /* destined to router */

    /* check if packet is ICMP */
    /* for 2b, it's TCP/UDP */
    if (iphdr->ip_p != ip_protocol_icmp) {

      /* send an ICMP Destination Port Unreachable message */
      send_err_msg(sr, packet, iphdr, (uint8_t)3, (uint8_t)3);
      return;
    }

    /* if packet isn't echo request, drop it */
    sr_icmp_t11_hdr_t* icmphdr = (sr_icmp_t11_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    if (icmphdr->icmp_type != (uint8_t)8) return;

    /* verify checksum of icmp packets */
    uint16_t old_icmp_cksum = icmphdr->icmp_sum;
    icmphdr->icmp_sum = 0;
    if (old_icmp_cksum != cksum(icmphdr, sizeof(sr_icmp_t11_hdr_t))) return;

    handle_icmp_requests(sr, packet, iphdr, interface, len, icmphdr);
  }

  else {
    if (iphdr->ip_ttl <= 1) {
      send_err_msg(sr, packet, iphdr, (uint8_t)11, (uint8_t)0);
    }
    else {
      forward_packet_next_hop(sr, packet, iphdr, len);
    }
  }
}