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
void dataLen(libnet_ipv4_hdr * iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen);
void forward(const u_char *_packet, uint8_t flag);
void backward(libnet_ethernet_hdr *_b_ethernet, libnet_ipv4_hdr *_b_ip, libnet_tcp_hdr *_b_tcp);
pcap_t *p_handle;            /* Session handle */
struct pcap_pkthdr *p_header;
uint8_t *Data;
int tcpDataLen;
bool F_RST = false, F_FIN = true, B_RST = false, B_FIN = true;

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
            if(ntohs(_tcp->th_dport) == 1234)
            {
                //u_int8_t *tcp_data = (u_int8_t *)(_packet + sizeof(libnet_ethernet_hdr) + (_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
                //Data = tcp_data;
                printf("%d",sizeof(tcp_data));


                dataLen(_ip,_tcp,&Data,&tcpDataLen);
                if(tcpDataLen != 0)
                {
                    if(Data[0] == 0x47 && Data[1] == 0x45 && Data[2] == 0x54 && Data[3] == 0x20) //GET
                    {
                        forward(_packet,TH_RST);
                        //forward(_packet,TH_FIN);


                    }

                }
            }
        }
    }

}

void dataLen(libnet_ipv4_hdr *iphdr, libnet_tcp_hdr *tcphdr, uint8_t **tcpData, int *tcpDataLen)
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
    }
}

void forward(const u_char *_packet, uint8_t flag)
{
    libnet_ethernet_hdr *forward_ethernet = (libnet_ethernet_hdr *)(_packet);
    libnet_ipv4_hdr *forward_ip = (libnet_ipv4_hdr *)(_packet + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *forward_tcp = (libnet_tcp_hdr *)(_packet + sizeof(libnet_ethernet_hdr) + forward_ip->ip_hl*4);
    uint8_t *data = (u_int8_t *)(_packet + sizeof(libnet_ethernet_hdr) + forward_ip->ip_hl*4 + sizeof(libnet_tcp_hdr));
    u_char *buffer = (u_char *)malloc(sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr) + tcpDataLen);
    memcpy(buffer,forward_ethernet,sizeof(libnet_ethernet_hdr)); // ethernet buffer size copy
    forward_ip->ip_tos = 0x44;
    forward_ip->ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + tcpDataLen);
    forward_ip->ip_ttl = 255;
    memcpy(buffer + sizeof(libnet_ethernet_hdr) , forward_ip, (forward_ip->ip_hl*4));//ip header setting
    forward_tcp->th_seq += htonl(tcpDataLen);
    forward_tcp->th_off = sizeof(libnet_tcp_hdr) / sizeof(uint32_t);
    forward_tcp->th_flags = htons(0);
    forward_tcp->th_flags = (flag | TH_ACK);
    forward_tcp->th_win = 0;
    memcpy(buffer + sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4), forward_tcp, sizeof(libnet_tcp_hdr));
    memcpy(buffer + sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr), Data, tcpDataLen);

    pcap_sendpacket(p_handle,buffer,sizeof(libnet_ethernet_hdr) + (forward_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
}


void backward(libnet_ethernet_hdr *_b_ethernet, libnet_ipv4_hdr *_b_ip, libnet_tcp_hdr *_b_tcp)
{
    libnet_ethernet_hdr *b_ethernet = _b_ethernet;
    libnet_ipv4_hdr *b_ip  = _b_ip;
    libnet_tcp_hdr *b_tcp = _b_tcp;
    u_char *buffer = (u_char *)malloc(sizeof(libnet_ethernet_hdr) + (b_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));
    memcpy(b_ethernet->ether_dhost,_b_ethernet->ether_shost,6);
    memcpy(b_ethernet->ether_shost,_b_ethernet->ether_dhost,6);
    memcpy(buffer,b_ethernet,sizeof(libnet_ethernet_hdr));
    b_ip->ip_dst = _b_ip->ip_src;
    b_ip->ip_src = _b_ip->ip_dst;
    b_ip->ip_tos = 0x44;
    b_ip->ip_len -= htons(tcpDataLen);
    b_ip->ip_ttl = 255;
    memcpy(buffer + sizeof(libnet_ethernet_hdr),b_ip,(b_ip->ip_hl*4));
    b_tcp->th_dport = _b_tcp->th_sport;
    b_tcp->th_sport = _b_tcp->th_dport;
    b_tcp->th_off = sizeof(libnet_tcp_hdr) / sizeof(uint32_t);
    if(B_RST == true)
        b_tcp->th_flags = (TH_RST | TH_ACK);
    else if(B_FIN == true)
        b_tcp->th_flags = (TH_FIN | TH_ACK);
    b_tcp->th_win = 0;
    memcpy(buffer + sizeof(libnet_ethernet_hdr) + (b_ip->ip_hl*4),b_ip,sizeof(libnet_tcp_hdr));
    pcap_sendpacket(p_handle,buffer,sizeof(libnet_ethernet_hdr) + (b_ip->ip_hl*4) + sizeof(libnet_tcp_hdr));



}
void backward_FIN(const u_char *_packet)
{


}


#endif // TCP_BLOCK_H
