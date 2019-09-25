#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("Source MAC : %X%X%X%X%X%X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]); 
    printf("Destination MAC : %X%X%X%X%X%X\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    if(packet[12]==8 && packet[13]==0){
    printf("Source IP : %X%X%X%X\n", packet[26], packet[27], packet[28], packet[29]);
    printf("Destination IP : %X%X%X%X\n", packet[30], packet[31], packet[32], packet[33]);
    printf("Source Port : %X%X\n", packet[34], packet[35]);
    printf("Destination Port : %X%X\n", packet[36], packet[37]);
  }

  }

  pcap_close(handle);
  return 0;
}
