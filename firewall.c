#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <signal.h>
#include "firewall.h"
#include "list.c"
#include <pthread.h>

mac this_mac;
mac router_mac =	{0x10, 0x10, 0x10, 0x10, 0x10, 0x11};

struct sockaddr_ll socket_address;
int sockfd;
pthread_t pidDisplayThread;
int running=1; //todos os loops infinitos dependem dessa variável, se zerada sai do loop

list flowEntries = {
        .head = NULL,
        .tail = NULL,
        .size = 0
};
list blacklist = {
        .head = NULL,
        .tail = NULL,
        .size = 0
};

void createAndConfigureSocket(char ifName[]);

void* watchPackets(void * params);
int isIpPacket(union eth_buffer packet);

void dumpNetworkPackets();
void updateFlowList(union eth_buffer packet, int size);
int findFlowEntry(void* listElement, void* searchElement);
void printFlowEntry(flow_entry* flowEntry);

int isBlackListed(uint8_t *ip);

void forwardPacket(union eth_buffer packet, int numBytes);

void blacklistMode();

void insertIpInBlacklist();
void removeIpInBlackList();
void printBlackList();
int compareIp(void* listElement, void* searchElement);

void killChildrenThreads(){
    running=0;
}

int main(int argc, char *argv[])
{
    char ifName[IFNAMSIZ];
    struct sigaction psa;
    char key;
    /* Get interface name */
    if (argc > 1)
        strcpy(ifName, argv[1]);
    else
        strcpy(ifName, DEFAULT_IF);

    psa.sa_handler = killChildrenThreads;
    sigaction(SIGINT, &psa, NULL);
    sigaction(SIGABRT, &psa, NULL);

    //configura o socket
    createAndConfigureSocket(ifName);


    pthread_create(&pidDisplayThread, NULL, watchPackets, NULL);

    while (running) {
        scanf("%c", &key);
        if(key=='b')
            blacklistMode();
    }

	return 0;
}

void blacklistMode(){
    char key;
    do{
        printBlackList();
        printf("\n0 - sair\n1 - inserir\n2 - remover\n3 - mostrar lista\n");
        scanf("%c", &key); //flush stdin
        scanf("%c", &key);
        if(key == '1'){
            insertIpInBlacklist();
        }else if(key == '2'){
            removeIpInBlackList();
        }else if(key == '3'){
            printBlackList();
        }
    }while (key!='0');
}

void printBlackList(){
    int i=0;
    node* curNode;
    uint8_t *curIp;
    curNode = blacklist.head;
    while (curNode!=NULL){
        curIp = (uint8_t*)curNode->element;
        printf("\n\n%d - %d.%d.%d.%d\n", i++, curIp[0],  curIp[1],  curIp[2],  curIp[3]);
        curNode = curNode->next_node;
    }
}

void insertIpInBlacklist(){
    int i = 0;
    uint8_t *curIp;
    char buffer[20];
    char *ptr;
    curIp = malloc(sizeof(ip));

    printf("Digite o ip (formato: 127.0.0.1):");
    scanf("%s", buffer);

    ptr = strtok(buffer, ".");
    while (ptr!=NULL && i<4){
        curIp[i++] = atoi(ptr);

        ptr = strtok(NULL, ".");
    };

    pushElement((void*)curIp, &blacklist);
}

void removeIpInBlackList(){
    int code, i=0;
    node* curNode = blacklist.head;

    printf("Digite o código do ip: ");
    scanf("%d", &code);

    while (curNode!=NULL){
        if(code == i++ ){
            removeElement(compareIp, curNode->element, &blacklist);
        }
        curNode = curNode->next_node;
    }
    printf("Removido com sucesso\n");
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

void *watchPackets(void * params){
    union eth_buffer buffer_u;
    int numbytes;

    while (1) {
        numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);

        if (isIpPacket(buffer_u)) {
            updateFlowList(buffer_u, numbytes);
            dumpNetworkPackets();

            if (!isBlackListed(buffer_u.cooked_data.payload.ip.src)){

                forwardPacket(buffer_u, numbytes);
            }

        }
    }
}

int isIpPacket(union eth_buffer packet){
    return packet.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP);
}

void updateFlowList(union eth_buffer packet, int size){
    union protocol_u *encapsulatedProtocol;
    flow_entry *listFoundEntry;
    flow_entry *flowEntry = malloc(sizeof(flow_entry));

    memcpy(flowEntry->src_ip, packet.cooked_data.payload.ip.src, sizeof(flowEntry->src_ip));
    memcpy(flowEntry->tgt_ip, packet.cooked_data.payload.ip.dst, sizeof(flowEntry->tgt_ip));

    flowEntry->ip_encapsulated_protocol = packet.cooked_data.payload.ip.proto;
    flowEntry->bytes = size;

    memcpy(flowEntry->protocol_name, IP_PROTOCOLS[packet.cooked_data.payload.ip.proto], strlen(IP_PROTOCOLS[packet.cooked_data.payload.ip.proto]));

    if(packet.cooked_data.payload.ip.proto == 6 || packet.cooked_data.payload.ip.proto == 17){
        encapsulatedProtocol = (union protocol_u *) (packet.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
    }
    if(packet.cooked_data.payload.ip.proto == 6){
        flowEntry->src_port = ntohs(encapsulatedProtocol->tcp.source);
        flowEntry->tgt_port = ntohs(encapsulatedProtocol->tcp.dest);
    }else if(packet.cooked_data.payload.ip.proto == 17){
        flowEntry->src_port = ntohs(encapsulatedProtocol->udp.source);
        flowEntry->tgt_port = ntohs(encapsulatedProtocol->udp.dest);
    }

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
            flowListEntry->ip_encapsulated_protocol == flowSearchEntry->ip_encapsulated_protocol &&
            flowListEntry->src_port == flowSearchEntry->src_port &&
            flowListEntry->tgt_port == flowSearchEntry->tgt_port;
}

int compareIp(void* listElement, void* searchElement){
    uint8_t *listIp = (uint8_t*) listElement; //cast params
    uint8_t *searchIp=  (uint8_t*) searchElement;

    return memcmp(listIp, searchIp, sizeof(ip)) ==0 ;
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

int isBlackListed(ip searchIp){
    if(findElement(compareIp, searchIp, &blacklist) != NULL)
        return 1;
    else
        return 0;
}

void forwardPacket(union eth_buffer packet, int numBytes){
    memcpy(packet.cooked_data.ethernet.dst_addr, router_mac, 6);
    memcpy(packet.cooked_data.ethernet.src_addr, this_mac, 6);

    if (sendto(sockfd, packet.raw_data, numBytes, 0,
               (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
}