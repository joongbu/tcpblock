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
bool _packet_reading(const u_char *_packet);
bool dataLen(libnet_ipv4_hdr * iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen);
bool forward_RST(const u_char *_packet);
pcap_t *p_handle;            /* Session handle */
struct pcap_pkthdr *p_header;
uint8_t *Data;
int tcpDataLen;

void dump(u_int8_t *bytes, int length) {
    for(int i=0; i < length; i++) {
        if(i%16==0) printf("\n");
        printf("%02x ", bytes[i]);
    }


}
bool _packet_reading(const u_char *_packet)
{

    libnet_ethernet_hdr *_ethernet = (libnet_ethernet_hdr *)(_packet);
    if(_ethernet->ether_type== htons(ETHERTYPE_IP))
    {

        libnet_ipv4_hdr *_ip = (libnet_ipv4_hdr *)(_packet + sizeof(libnet_ethernet_hdr));
        if(_ip->ip_p  == IPPROTO_TCP)
        {

            libnet_tcp_hdr *_tcp = (libnet_tcp_hdr *)(_packet + sizeof(libnet_ethernet_hdr) + (_ip->ip_hl*4));
            if(ntohs(_tcp->th_dport) == 1234)
            {

                dataLen(_ip,_tcp,&Data,&tcpDataLen);
                if(tcpDataLen != 0)
                {
                    if(Data[0] == 0x47 && Data[1] == 0x45 && Data[2] == 0x54 && Data[3] == 0x20) //GET
                    {
                        forward_RST(_packet);
                        return true;
                    }

                }
            }
        }
    }
    else
        return false;

}

bool dataLen(libnet_ipv4_hdr *iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen)
{
    int tcpHdrLen = tcphdr->th_off * sizeof(u_int32_t);
    u_int8_t *_tcpData = (uint8_t*)(tcphdr) + tcpHdrLen;
    int _tcpDataLen = ntohs(iphdr->ip_len) - sizeof(libnet_ipv4_hdr) - tcpHdrLen;

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

bool forward_RST(const u_char *_packet)
{
    libnet_ethernet_hdr *forward_ethernet = (libnet_ethernet_hdr *)(_packet);
    libnet_ipv4_hdr *forward_ip = (libnet_ipv4_hdr *)(_packet + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *forward_tcp = (libnet_tcp_hdr *)(_packet + sizeof(libnet_ethernet_hdr) + forward_ip->ip_hl*4);
    uint8_t *data = (u_int8_t *)(_packet + sizeof(libnet_ethernet_hdr) + forward_ip->ip_hl*4 + sizeof(libnet_tcp_hdr));
    u_char *buffer = (u_char *)malloc(sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr) + tcpDataLen);
    memcpy(buffer,forward_ethernet,sizeof(libnet_ethernet_hdr)); // ethernet buffer size copy
    forward_ip->ip_tos = 0x44;
    forward_ip->ip_len -= htons(tcpDataLen);
    forward_ip->ip_ttl = 255;
    memcpy(buffer + sizeof(libnet_ethernet_hdr) , forward_ip, (forward_ip->ip_hl*4));//ip header setting
    forward_tcp->th_seq += htonl(tcpDataLen);
    forward_tcp->th_off = sizeof(libnet_tcp_hdr) / sizeof(uint32_t);
    forward_tcp->th_flags = TH_RST | TH_ACK;
    forward_tcp->th_win = 0;
    memcpy(buffer + sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4), forward_tcp, sizeof(libnet_tcp_hdr));
    pcap_sendpacket(p_handle,buffer,sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
    dump((u_int8_t *)buffer,sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
}

#endif // TCP_BLOCK_H
