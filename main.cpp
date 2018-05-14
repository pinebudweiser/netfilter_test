#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "data.h"

#define MAX_PACKET 0xFFFF
#define PROTOCOL_TCP	0x6
#define VERSION_IPV4	0x4
#define HTTP_PORT		80

typedef struct nfq_q_handle nfq_q_handle;
typedef struct nfgenmsg nfgenmsg;
typedef struct nfq_data nfq_data;
typedef struct nfq_handle nfq_handle;
typedef struct nfq_q_handle nfq_q_handle;
typedef struct nfqnl_msg_packet_hdr nfqnl_msg_packet_hdr;

int queue_processor(nfq_q_handle *CrtHandle, nfgenmsg *nfmsg,
                    nfq_data *packet_handler, void *data)
{
    int pktLen;
    int id;
    uint32_t statusTCP = NF_ACCEPT;
    uint8_t* packet;
    char* ptr_data;
    char* totototot;
    char test_data[1000];
    IP* ipHeader;
    TCP* tcpHeader;
    char site_name[1000];
    int data_size;
    nfqnl_msg_packet_hdr *packetHeader;

    packetHeader = nfq_get_msg_packet_hdr(packet_handler);
    if (packetHeader) {
        id = ntohl(packetHeader->packet_id);
    }
    pktLen = nfq_get_payload(packet_handler, &packet);
    ipHeader = (IP*)(packet);
    if(ipHeader->VER == VERSION_IPV4 &&
            ipHeader->ProtocolID == PROTOCOL_TCP)
    {
        tcpHeader = (TCP*)(packet+(ipHeader->IHL << 2));
        if (ntohs(tcpHeader->DstPort) == HTTP_PORT ||
                ntohs(tcpHeader->SrcPort) == HTTP_PORT)
        {
            data_size = ntohs(ipHeader->TotalLength) - (ipHeader->IHL << 2) + (tcpHeader->HeaderLength<<2);
            //printf("tcpHeader len : %d\n", tcpHeader->HeaderLength);
            ptr_data = (char*)(packet + (ipHeader->IHL << 2) + (tcpHeader->HeaderLength<<2));
            if(!strncmp(ptr_data,"GET",3))
            {
                strcpy(test_data, ptr_data);
                totototot = strstr(test_data, "Host: ");
                if(totototot == NULL)
                {
                    statusTCP = NF_DROP;
                }
                else
                {
                    sscanf(totototot, "Host: %s\r\n", site_name);
                    printf("site_name : %s\n", site_name);
                    if(!strcmp(site_name,"test.gilgil.net"))
                    {
                        statusTCP = NF_DROP;
                    }
                }
            }

        }
    }

    return nfq_set_verdict(CrtHandle, id, statusTCP, 0, NULL);
}

int main()
{
    nfq_handle* nfqOpenHandle;
    nfq_q_handle* nfqCrtHandle;
    int nfqDescriptor;
    int pk_len;
    uint8_t* packet;
    char buf[4096];

    nfqOpenHandle = nfq_open();
    if (!nfqOpenHandle)
    {
        printf("nfqHandle create failed.\n");
        return 1;
    }
    nfqCrtHandle = nfq_create_queue(nfqOpenHandle, 0, &queue_processor, NULL);
    if (!nfqCrtHandle)
    {
        printf("nfqQueue create failed.\n");
        return 1;
    }
    if (nfq_set_mode(nfqCrtHandle, NFQNL_COPY_PACKET, MAX_PACKET))
    {
        printf("nfqSetmode COPY_PACKET failed.\n");
        return 1;
    }
    nfqDescriptor = nfq_fd(nfqOpenHandle);
    if (!nfqDescriptor)
    {
        printf("nfqDescriptor create failed.\n");
        return 1;
    }
    while(true)
    {
        if((pk_len = recv(nfqDescriptor, buf, sizeof(buf), 0)) >= 0){
            nfq_handle_packet(nfqOpenHandle, buf, pk_len);
            continue;
        }
        if(pk_len < 0)
        {
            printf("[Err] Packet loss!\n");
            continue;
        }
    }
    nfq_destroy_queue(nfqCrtHandle);
    nfq_close(nfqOpenHandle);

    return 0;
}
