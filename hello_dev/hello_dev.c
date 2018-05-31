#include <pcap.h>

int main(int argc, char *argv[]) {
  char error[PCAP_ERRBUF_SIZE];
  char* dev;
  dev = pcap_lookupdev(error);
  if (dev == NULL) {
    fprintf(stderr, "error for %s\n", error);
  } else {
    fprintf(stderr, "dev is %s \n", dev);
  }
  return 0;
}
