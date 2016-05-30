#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
void reading(pcap_t *handle, const u_char *packet, u_int16_t *port);
bool dataLen(libnet_ipv4_hdr * iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen);
struct tcp_data_hdr
{

    uint8_t *data;
};

struct Rst
{
    libnet_ethernet_hdr e;
    libnet_ipv4_hdr i;
    libnet_tcp_hdr t;
};

int main(int args,char *argv[])

{


    uint16_t *port;
    pcap_t *handle;            /* Session handle */
    struct pcap_pkthdr pcap_header;
    const u_char *packet;
    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */

    if(args >= 3){
        printf("===========================================\n");
        printf(" server ip : %s , port = %s\n",argv[1],argv[2]);
        printf("===========================================\n");
        port = (u_int16_t *)argv[2];
    }

    dev  =  pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);

    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }

    printf("chracter reading....\n");
    while(1)
    {
        packet = pcap_next(handle, &pcap_header);
        reading(handle, packet, port);
    }
    //Forward(packet)
    /* And close the session */

    pcap_close(handle);

    return(0);

}


void reading(pcap_t *handle, const u_char *packet, uint16_t *port) {

    libnet_ethernet_hdr *ethernet_header = (libnet_ethernet_hdr*) (packet);
    libnet_ipv4_hdr *ip_hdr = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
    if(ntohs(ip_hdr->ip_p) == IPPROTO_TCP) //0x06
    {



    int *tcp_DataLen;
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr)+ (ip_hdr->ip_hl*4));
    uint8_t flag = 0;
    tcp_data_hdr *tcp_data = (tcp_data_hdr *)(packet + sizeof(*ethernet_header) + (ip_hdr->ip_hl*4) + sizeof(*ip_hdr));
        //printf("data Len : %d\n", *tcp_DataLen);
        //printf("tcp_data : %s",tcp_data->data);
    if(dataLen(ip_hdr,tcp_hdr,&tcp_data->data,tcp_DataLen) == true)
    {
    if((tcp_data->data[0] = 0x67) && (tcp_data->data[1] = 0x65) && (tcp_data->data[2] == 0x74) && (tcp_data->data[3] = 0x20))
    {
        //ip change
        ip_hdr->ip_tos = 0x44;//no mean
        ip_hdr->ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
        ip_hdr->ip_ttl = 128;


            int flagAddLen = ((tcp_hdr->th_flags & (TH_SYN | TH_FIN))) ? 1:0;
            uint32_t newS = ntohl(tcp_hdr->th_seq);// + tcp_DataLen; // + flagAddLen;
            tcp_hdr->th_seq = htonl(newS);
            tcp_hdr->th_off = sizeof(tcp_hdr) / sizeof(uint32_t);
            tcp_hdr->th_flags = flag | TH_ACK ;
            tcp_hdr->th_win =0;


            //check sum
            tcp_hdr->th_sum = 0;
            ip_hdr->ip_sum = 0;

             pcap_sendpacket(handle,packet,sizeof(*packet));
        }
}


}






}


bool dataLen(libnet_ipv4_hdr *iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen)
{
    int tcpHdrLen = tcphdr->th_off * sizeof(u_int32_t);
    //printf("tcpHdrsize : %d\n", tcpHdrLen);
    u_int8_t *_tcpData = (uint8_t*)(tcphdr) + tcpHdrLen;
    //printf("tcp data : %s\n",_tcpData);
    int _tcpDataLen = ntohs(iphdr->ip_len) - sizeof(iphdr) - tcpHdrLen;

    if(_tcpDataLen > 0)
    {
        if(tcpData != NULL)
            *tcpData = _tcpData;
        if(tcpDataLen != NULL)
            *tcpDataLen = _tcpDataLen;
        return true;
    }
    return false;
}
bool forward_send(libnet_ethernet_hdr *read_ethernet,libnet_ipv4_hdr *read_ip,libnet_tcp_hdr *read_tcp)
{
    const u_char *packet;
    libnet_ethernet_hdr *ethernet = (libnet_ethernet_hdr *)(packet);
    libnet_ipv4_hdr *ip = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr));



}


