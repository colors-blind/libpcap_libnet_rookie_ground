#include <pcap.h>

void packet_callback(u_char* argument, 
    const struct pcap_pkthdr* header, const u_char* content) {
  static int count = 1;
  printf("The %d packet is captured length is %d. \n ", count, header->len);
  count++;
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

  pcap_loop(pcap_handle, 10, packet_callback, NULL);

  pcap_close(pcap_handle);
  return 0;
}

