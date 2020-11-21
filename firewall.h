#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"


const char* IP_PROTOCOLS[140] = {
        "HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GREs", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SwIPe", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "CFTP", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP", "IPTM", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25", "OS", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP", "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC", "Ethernet"};

enum ARP_OPERATION {ARP_REQUEST=1, ARP_REPLY=2};

struct flow_entry_s{
    uint8_t src_ip[4];
    uint8_t src_port;
    uint8_t tgt_ip[4];
    uint8_t tgt_port;
    uint8_t ip_encapsulated_protocol;
    char protocol_name[10];
    int bytes;
};
typedef struct flow_entry_s flow_entry;

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct arp_packet {
	uint16_t hw_type;		/* hardware type */
	uint16_t prot_type;		/* protocol type */
	uint8_t hlen;			/* hardware address length */
	uint8_t plen;			/* protocol address length */
	uint16_t operation;		/* ARP operation */
	uint8_t src_hwaddr[6];		/* source hardware address */
	uint8_t src_paddr[4];		/* source protocol address */
	uint8_t tgt_hwaddr[6];		/* target hardware address */
	uint8_t tgt_paddr[4];		/* target protocol address */
};

struct ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

union packet_u {
	struct arp_packet arp;
	struct ip_hdr ip;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	union packet_u payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};
