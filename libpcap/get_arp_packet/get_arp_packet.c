#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>

// define ethernet protocol header type
struct ether_header {
    u_int8_t ether_srchost[6];    // source MAC address
    u_int8_t ether_desthost[6];   // dest MAC address
    u_int16_t ether_type;         // ethernet type
};

struct in_addr {
    u_int32_t s_addr;
};

// define arp protocol header type
struct arp_header{
    u_int16_t arp_hardware_type;  // hardware_type
    u_int16_t arp_protocol_type;  // protocol address type
    u_int8_t  arp_hardware_length; // hardware_address length
    u_int8_t arp_protocol_length;  // protocol length
    u_int16_t arp_operation_code;  // arp operation code
    u_int8_t arp_source_ethernet_addr[6];  // source mac addr
    u_int8_t arp_source_ip_addr[4];  // souce IP address
    u_int8_t arp_dest_ethernet_addr[6];  // dest mac addr
    u_int8_t arp_dest_ip_addr[4];  // dest IP address
};

void
show_network_protocol(u_int16_t ethernet_type) {
    switch(ethernet_type) {
        case 0x0800:
            printf("The network layer is IP protocol\n");
            break;
        case 0x0806:
            printf("The network layer is ARP protocol\n");
            break;
        case 0x0835:
            printf("The network layer is RARP protocol\n");
            break;
        default:
            break;
    }
}

void
show_mac_addr(struct ether_header* ether_protocol, int is_src) {

    u_char* mac_string;

    if (is_src == 1) {
        mac_string = ether_protocol->ether_srchost;

        printf("Source MAC Addr is %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string,
            *(mac_string+1), *(mac_string+2), *(mac_string+3),
            *(mac_string+4), *(mac_string+5));
    } else {
        mac_string = ether_protocol->ether_desthost;

        printf("Dest MAC Addr is %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string,
            *(mac_string+1), *(mac_string+2), *(mac_string+3),
            *(mac_string+4), *(mac_string+5));
    }
}

void
show_arp_operation(u_int8_t operation_code) {
  switch(operation_code) {
    case 1:
      printf("ARP Request Operation\n");
      break;
    case 2:
      printf("ARP Reply Operation\n");
      break;
    case 3:
      printf("RARP Request Operation\n");
      break;
    case 4:
      printf("RARP Reply Operation\n");
      break;
    default:
      break;
  }
}

void
show_ip_addr(struct arp_header* ether_protocol) {

    u_char* ip_addr;
    
    ip_addr = ether_protocol->arp_source_ip_addr;

    printf("Source IP Addr is %d:%d:%d:%d\n", 
        *ip_addr ,*(ip_addr+1), *(ip_addr+2), *(ip_addr+3));

    ip_addr = ether_protocol->arp_dest_ip_addr;
    
    printf("Dest IP Addr is %d:%d:%d:%d\n", 
        *ip_addr ,*(ip_addr+1), *(ip_addr+2), *(ip_addr+3));

}

void 
arp_protocol_contnet_callback(u_char* argument,
                                   const struct pcap_pkthdr *header,
                                   const u_char* content) {

  struct arp_header* arp_protocol;

  u_short protocol_type;
  u_short hardware_type;
  u_short operation_code;

  struct in_addr source_ip;  // source IP
  struct in_addr dest_ip;    // destination IP

  u_char hardware_length;
  u_char protocal_length; 

  printf("---- ARP Protocol (Network Laryer) ---- \n");
  // 14 = 6 + 6 + 2
  arp_protocol = (struct arp_header*)(content + 14); // pass ethernet length 14 bytes

  hardware_type = ntohs(arp_protocol->arp_hardware_type);
  protocol_type = ntohs(arp_protocol->arp_protocol_type);
  operation_code = ntohs(arp_protocol->arp_operation_code);

  hardware_length = arp_protocol->arp_hardware_length;
  protocal_length = arp_protocol->arp_protocol_length;

  printf("ARP Hardware Type: %d\n", hardware_type);
  printf("ARP Protocol Type: 0x%x\n", protocol_type);

  printf("ARP Operation: %u\n", operation_code);

  show_arp_operation(operation_code);
  
  show_ip_addr(arp_protocol);

}


void
ether_protocol_callback(u_char* argument,
                        const struct pcap_pkthdr* header,
                        const u_char* content) {
    u_int16_t ethernet_type;
    struct ether_header* ether_protocol;

    static int count = 1;

    printf("\n*******************************\n");
    printf("The %d ARP packet is captured\n", count);

    // // convert the conetent into ether_header
    ether_protocol = (struct ether_header*)content;
    ethernet_type = ntohs(ether_protocol->ether_type);
    printf("Ethernet type is : 0x%04x \n", ethernet_type);

    show_network_protocol(ethernet_type);
    // print out source MAC and dest MAC
    show_mac_addr(ether_protocol, 1);
    show_mac_addr(ether_protocol, 0);
    
    switch (ethernet_type) {
      case 0x0806:
        arp_protocol_contnet_callback(argument,
            header, content);
        break;
      default:
        break;
    }

    printf("*******************************\n");
    count++;
}


int 
main(int argc, char const *argv[]) {

    char error[256];
    char* dev;

    dev = pcap_lookupdev(error);
    if (dev == NULL) {
        fprintf(stderr, "pcap_lookupdev error for: %s\n", error);
        exit(1);
    }

    fprintf(stderr, "network device is: %s \n", dev);

    u_int32_t net_ip;
    u_int32_t net_mask;
    int ret_code = -1;
    if ((ret_code = pcap_lookupnet(dev, &net_ip, &net_mask, error)) == -1) {
        fprintf(stderr, "pcap_lookupnet error for : %s \n", error);
        exit(1);
    }

    pcap_t* pcap_handle;  // pcap handle
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 0, error);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live error for : %s \n", error);
        exit(1);
    }

    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "arp";   // type of protocol want

    if ((ret_code = pcap_compile(pcap_handle, &bpf_filter, 
                                 bpf_filter_string, 0, net_ip)) == -1) {
        fprintf(stderr, "pcap_compile error for : %s \n", error);
        exit(1);
    }

    if ((ret_code = pcap_setfilter(pcap_handle, &bpf_filter)) == -1) {
        fprintf(stderr, "pcap_setfilter error for : %s \n", error);
        exit(1);
    }

    // if not ethernet type return
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
        exit(1);
    }

    // get packet forerver, -1 means forever
    pcap_loop(pcap_handle, -1, ether_protocol_callback, NULL);

    return 0;
}
