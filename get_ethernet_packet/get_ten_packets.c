#include <pcap.h>
#include <time.h>  
#include <arpa/inet.h>

// define the ethernet header
struct ether_header {
  u_int8_t ether_dmac[6];
  u_int8_t ether_smac[6];
  u_int16_t ether_type;
};


// callback function, just print out some info
void packet_callback(u_char* argument, 
  const struct pcap_pkthdr* header, const u_char* content) {
  static int count = 1;
  u_int16_t ethernet_type;
  struct ether_header* ether_protocol;

  printf("\n****************************\n");
  printf("The %d packet is captured length is %d.\n ", count, header->len);
  count++;

  printf("Time is: %s \n", ctime((const time_t*)&(header->ts.tv_sec)));

  ether_protocol = (struct ether_header*)content;
  ethernet_type = ntohs(ether_protocol->ether_type);

  printf("Ethernet type is 0x%04x\n", ethernet_type);
  switch(ethernet_type) {
    case 0x0800:
      printf("The network layer is IP protocol\n");
      break;
    case 0x0806:
      printf("The network layer is ARP protocol\n");
      break;
    default:
      break;
  }
  // get source mac address
  u_char* mac_string;
  mac_string = ether_protocol->ether_smac;
  printf("Source Mac is : %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1),
      *(mac_string+2),*(mac_string+3),*(mac_string+4),
      *(mac_string+5));

  // get dest mac address
  mac_string = ether_protocol->ether_dmac;
  printf("Dest Mac is : %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1),
      *(mac_string+2),*(mac_string+3),*(mac_string+4),
      *(mac_string+5));
}


int main(int argc, char *argv[]) {
  char error[256];

  struct pcap_pkthdr header; // the header of a packet
  pcap_t* pcap_handle;
  
  struct bpf_program bpf_filter;
  char bpf_string[] = "";
  const u_char* package_content;

  u_int32_t int_ip;
  u_int32_t int_mask;

  char *dev;

  dev = pcap_lookupdev(error);
  pcap_lookupnet(dev, &int_ip, &int_mask, error);

  // set dev as promiscuous mode
  pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 0, error);
  // compile filter string
  pcap_compile(pcap_handle, &bpf_filter, bpf_string, 0, int_ip);

  // set the rule
  pcap_setfilter(pcap_handle, &bpf_filter);

  int link_type = pcap_datalink(pcap_handle);
  printf("DataLink name is %s\n", pcap_datalink_val_to_name(link_type));
  // loop to get 1000 packets
  pcap_loop(pcap_handle, 1000, packet_callback, NULL);

  pcap_close(pcap_handle);
  return 0;
}

