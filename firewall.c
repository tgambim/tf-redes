#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <signal.h>
#include "firewall.h"
#include "list.c"

uint8_t this_mac[6];
uint8_t bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
uint8_t src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

uint8_t router_ip[4] =	{10, 0, 0, 1};
uint8_t target_pc_ip[4] =	{10, 0, 0, 21};
uint8_t this_ip[4] =	{0, 0, 0, 0};

struct sockaddr_ll socket_address;
int sockfd;

list flowEntries = {
        .head = NULL,
        .tail = NULL,
        .size = 0
};

void createAndConfigureSocket(char ifName[]);

void watchPackets();
int isIpPacket(union eth_buffer packet);

void dumpNetworkPackets();
void updateFlowList(union eth_buffer packet, int size);
int findFlowEntry(void* listElement, void* searchElement);
void printFlowEntry(flow_entry* flowEntry);

void importBlackList();
int isBlackListed(uint8_t *ip);

void forwardPacket(union eth_buffer packet);


int main(int argc, char *argv[])
{
    char ifName[IFNAMSIZ];
    struct sigaction psa;
    int pid;
    /* Get interface name */
    if (argc > 1)
        strcpy(ifName, argv[1]);
    else
        strcpy(ifName, DEFAULT_IF);

    //configura o socket
    createAndConfigureSocket(ifName);

    importBlackList();

    watchPackets();
	return 0;
}

void createAndConfigureSocket(char ifName[]){
    struct ifreq if_idx, if_mac, ifopts;

    /* Open RAW socket */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
        perror("socket");

    /* Set interface to promiscuous mode */
    strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

    /* Get the index of the interface */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;

    /* Get the MAC address of the interface */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");
    memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

    /* End of configuration. Now we can send and receive data using raw sockets. */
}

void importBlackList(){
    /* TODO implement */
}

void watchPackets(){
    union eth_buffer buffer_u;
    int numbytes;

    while (1){
        numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);

        if (isIpPacket(buffer_u)){
            updateFlowList(buffer_u, numbytes);
            dumpNetworkPackets();

            if(!isBlackListed(buffer_u.cooked_data.payload.ip.src))
                forwardPacket(buffer_u);

            continue;
        }
    }
}

int isIpPacket(union eth_buffer packet){
    return packet.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP);
}

void updateFlowList(union eth_buffer packet, int size){
    flow_entry *listFoundEntry;
    flow_entry *flowEntry = malloc(sizeof(flow_entry));

    memcpy(flowEntry->src_ip, packet.cooked_data.payload.ip.src, sizeof(flowEntry->src_ip));
    memcpy(flowEntry->tgt_ip, packet.cooked_data.payload.ip.dst, sizeof(flowEntry->tgt_ip));

    flowEntry->ip_encapsulated_protocol = packet.cooked_data.payload.ip.proto;
    flowEntry->bytes = size;

    memcpy(flowEntry->protocol_name, IP_PROTOCOLS[packet.cooked_data.payload.ip.proto], strlen(IP_PROTOCOLS[packet.cooked_data.payload.ip.proto]));

    /* TODO handle tcp and udp inner protocols */
    flowEntry->src_port = 0;
    flowEntry->tgt_port = 0;

    listFoundEntry = (flow_entry*) findElement(findFlowEntry, flowEntry, &flowEntries);
    if(listFoundEntry != NULL){
        listFoundEntry->bytes += flowEntry->bytes;
    }else{
        pushElement(flowEntry, &flowEntries);
    }

}

int findFlowEntry(void* listElement, void* searchElement){
    flow_entry *flowListEntry = (flow_entry*) listElement, *flowSearchEntry=  (flow_entry*) searchElement; //cast params

    return memcmp(flowListEntry->src_ip, flowSearchEntry->src_ip, sizeof(flowListEntry->src_ip)) ==0 &&
            memcmp(flowListEntry->tgt_ip, flowSearchEntry->tgt_ip, sizeof(flowListEntry->tgt_ip)) ==0 &&
            flowListEntry->src_port == flowSearchEntry->src_port &&
            flowListEntry->tgt_port == flowSearchEntry->tgt_port;
}

void dumpNetworkPackets(){
    node* entryNode = flowEntries.head;
    flow_entry* flowEntry;

    printf("------------------------ Tabela de Fluxo ------------------------\n");
    while (entryNode!=NULL){
        flowEntry = (flow_entry*)entryNode->element;
        printFlowEntry(flowEntry);
        entryNode = entryNode->next_node;
    }
    printf("----------------------------------------------------------------\n");
}

void printFlowEntry(flow_entry* flowEntry){
    printf("<%d.%d.%d.%d:%d><%d.%d.%d.%d:%d><%s><%d>\n",
           flowEntry->src_ip[0], flowEntry->src_ip[1], flowEntry->src_ip[2], flowEntry->src_ip[3], flowEntry->src_port,
           flowEntry->tgt_ip[0], flowEntry->tgt_ip[1], flowEntry->tgt_ip[2], flowEntry->tgt_ip[3], flowEntry->tgt_port,
           flowEntry->protocol_name,
           flowEntry->bytes
    );
}

int isBlackListed(uint8_t *ip){
    /* TODO implement */
    return 0;
}

void forwardPacket(union eth_buffer packet){
    /* TODO implement */
}


void showArpPacket(union eth_buffer packet){
    printf("ARP packet received:\n");
    printf("----------------------------------------------------------------\n");
    printf("Hardware type: %d\n", ntohs(packet.cooked_data.payload.arp.hw_type));
    printf("Protocol type: %d\n", ntohs(packet.cooked_data.payload.arp.prot_type));
    printf("Hardware address length: %d\n", (packet.cooked_data.payload.arp.hlen));
    printf("Protocol address length: %d\n", (packet.cooked_data.payload.arp.plen));
    printf("Arp operation: %d\n", ntohs(packet.cooked_data.payload.arp.operation));
    printf("Source hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           (packet.cooked_data.payload.arp.src_hwaddr[0]),
           (packet.cooked_data.payload.arp.src_hwaddr[1]),
           (packet.cooked_data.payload.arp.src_hwaddr[2]),
           (packet.cooked_data.payload.arp.src_hwaddr[3]),
           (packet.cooked_data.payload.arp.src_hwaddr[4]),
           (packet.cooked_data.payload.arp.src_hwaddr[5]));
    printf("Source protocol address: %d.%d.%d.%d\n",
           (packet.cooked_data.payload.arp.src_paddr[0]),
           (packet.cooked_data.payload.arp.src_paddr[1]),
           (packet.cooked_data.payload.arp.src_paddr[2]),
           (packet.cooked_data.payload.arp.src_paddr[3]));
    printf("Target hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           (packet.cooked_data.payload.arp.tgt_hwaddr[0]),
           (packet.cooked_data.payload.arp.tgt_hwaddr[1]),
           (packet.cooked_data.payload.arp.tgt_hwaddr[2]),
           (packet.cooked_data.payload.arp.tgt_hwaddr[3]),
           (packet.cooked_data.payload.arp.tgt_hwaddr[4]),
           (packet.cooked_data.payload.arp.tgt_hwaddr[5]));
    printf("Target protocol address: %d.%d.%d.%d\n",
           (packet.cooked_data.payload.arp.tgt_paddr[0]),
           (packet.cooked_data.payload.arp.tgt_paddr[1]),
           (packet.cooked_data.payload.arp.tgt_paddr[2]),
           (packet.cooked_data.payload.arp.tgt_paddr[3]));
    printf("----------------------------------------------------------------\n\n\n");
}

void sendArpPacket(uint8_t sourceIp[], uint8_t targetIp[], enum ARP_OPERATION operation, uint8_t sourceMac[], uint8_t targetMac[]){
    union eth_buffer buffer_u;
    /* To send data (in this case we will cook an ARP packet and broadcast it =])... */

    /* fill the Ethernet frame header */
    memcpy(buffer_u.cooked_data.ethernet.dst_addr, targetMac, 6);
    memcpy(buffer_u.cooked_data.ethernet.src_addr, sourceMac, 6);
    buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

    /* fill payload data (incomplete ARP request example) */
    buffer_u.cooked_data.payload.arp.hw_type = htons(1);
    buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);
    buffer_u.cooked_data.payload.arp.hlen = 6;
    buffer_u.cooked_data.payload.arp.plen = 4;
    buffer_u.cooked_data.payload.arp.operation = htons(operation);
    memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, this_mac, 6);
    //memset(buffer_u.cooked_data.payload.arp.src_paddr, 0, 6);
    memcpy(buffer_u.cooked_data.payload.arp.src_paddr, sourceIp, 4);
    memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
    //memset(buffer_u.cooked_data.payload.arp.tgt_paddr, 0, 6);
    memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, targetIp, 4);

    /* Send it.. */
    memcpy(socket_address.sll_addr, targetMac, 6);
    if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0,
               (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
}

union eth_buffer getPacket(){
    union eth_buffer receivedPacket;
    recvfrom(sockfd, receivedPacket.raw_data, ETH_LEN, 0, NULL, NULL);
    return receivedPacket;
}
