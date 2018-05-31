#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
  char* dev;
  char* net;
  char* mask;

  int ret;

  char error[256];
  uint32_t int_ip;
  uint32_t int_mask;

  struct in_addr addr;
  dev = pcap_lookupdev(error);

  printf("DEV: %s\n", dev);

  ret = pcap_lookupnet(dev, &int_ip, &int_mask, error);

  if (ret == -1) {
    printf("error for %s\n", error);
    exit(1);
  }

  addr.s_addr = int_ip;
  net = inet_ntoa(addr);

  printf("Net: %s \n", net);

  addr.s_addr = int_mask;
  mask = inet_ntoa(addr);

  printf("Mask : %s \n", mask);

  return 0;
}
