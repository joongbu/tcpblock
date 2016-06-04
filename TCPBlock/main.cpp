#include "tcp_block.h"
int main(int args,uint16_t *argv[])

{

    const u_char *packet;
    char *dev;            /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    if(args >= 1){
        printf("===========================================\n");
        printf(" TCP BLOCK SERVER FIND.....\n");

    }




    dev  =  "eth0";
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Open the session in promiscuous mode */

    p_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (p_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }



    //finding packet data

    while(1)

    {
        pcap_next_ex(p_handle,&p_header,&packet);
        if(p_header->caplen !=0)
        {

            _packet_reading(packet);
        }





    }
    /* And close the session */

    pcap_close(p_handle);

    return(0);

}
