#ifndef TCP_BLOCK_H
#define TCP_BLOCK_H
#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
uint16_t *port;
void _packet_reading(const u_char *_packet);
bool dataLen(libnet_ipv4_hdr * iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen);
int tcpDataLen;
uint8_t *data;
void dump(u_int8_t *bytes, int length) {
    for(int i=0; i < length; i++) {
        if(i%16==0) printf("\n");
        printf("%02x ", bytes[i]);
    }


}
void _packet_reading(const u_char *_packet)
{

    libnet_ethernet_hdr *_ethernet = (libnet_ethernet_hdr *)(_packet);

    if(_ethernet->ether_type== htons(ETHERTYPE_IP))
    {

        libnet_ipv4_hdr *_ip = (libnet_ipv4_hdr *)(_packet + sizeof(libnet_ethernet_hdr));
        if(_ip->ip_p  == IPPROTO_TCP)
        {
            libnet_tcp_hdr *_tcp = (libnet_tcp_hdr *)(_packet + sizeof(libnet_ethernet_hdr) + (_ip->ip_hl*4));
           data = (u_int8_t *)(_packet +sizeof(libnet_ethernet_hdr) + (_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
           dataLen(_ip,_tcp,&data,&tcpDataLen);
           printf("data packet !!! \n");
           //dump(data,tcpDataLen);
        }
    }
    else
        printf("not protocol ip\n");

        printf("%s\n",data);
}

bool dataLen(libnet_ipv4_hdr *iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen)
{
    int tcpHdrLen = tcphdr->th_off * sizeof(u_int32_t);
    u_int8_t *_tcpData = (uint8_t*)(tcphdr) + tcpHdrLen;
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
bool forward(libnet_ethernet_hdr *copy_ethernet, libnet_ipv4_hdr *copy_ip, libnet_tcp_hdr *copy_tcp)
{
    const u_char *packet;
}

#endif // TCP_BLOCK_H
