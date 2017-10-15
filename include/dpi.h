// "dpi.h"
#pragma once

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <enlace.h>
#include <dbConnector.h>
#include <logfile.h>

class DPI {
private:
	char* interfazCap = NULL;
	char* filtroCap = NULL;
	const u_char *paquete;
	pcap_t* descriptor;
	pcap_pkthdr cabecera;
	char error[PCAP_ERRBUF_SIZE];
	bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
    LogFile* _logger;
    stringstream _write2log;


        /* Ethernet addresses are 6 bytes */
	static const short ETHER_ADDR_LEN = 6;

	static const u_short SIZE_ETHERNET = 14;

        /* Ethernet header */
    struct sniff_ethernet {
            u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
            u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
            u_short ether_type; /* IP? ARP? RARP? etc */
    };

        /* IP header */
    struct sniff_ip {
            u_char ip_vhl;          /* version << 4 | header length >> 2 */
            u_char ip_tos;          /* type of service */
            u_short ip_len;         /* total length */
            u_short ip_id;          /* identification */
            u_short ip_off;         /* fragment offset field */
	static const u_int IP_RF = 0x8000;     /* reserved fragment flag */
//        #define IP_RF 0x8000            /* reserved fragment flag */
	static const u_int IP_DF = 0x4000;
//        #define IP_DF 0x4000            /* dont fragment flag */
	static const u_int IP_MF = 0x2000;
//        #define IP_MF 0x2000            /* more fragments flag */
	static const u_int IP_OFFMASK = 0x1fff;
//        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
            u_char ip_ttl;          /* time to live */
            u_char ip_p;            /* protocol */
            u_short ip_sum;         /* checksum */
            in_addr ip_src,ip_dst; /* source and dest address */
        };
        #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
        #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

        /* TCP header */
        typedef u_int tcp_seq;

        struct sniff_tcp {
            u_short th_sport;       /* source port */
            u_short th_dport;       /* destination port */
            tcp_seq th_seq;         /* sequence number */
            tcp_seq th_ack;         /* acknowledgement number */
            u_char th_offx2;        /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
            u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
            u_short th_win;         /* window */
            u_short th_sum;         /* checksum */
            u_short th_urp;         /* urgent pointer */
        };

        /* SSL Payload Header */
#pragma pack(1)
        struct sniff_ssl_H {
            u_char ssl_record_contentType;
            u_short ssl_record_version;
            u_short ssl_record_length;
            u_char ssl_handshake_type;
            u_char ssl_handshake_length[3];
            u_short ssl_handshake_version;
            u_char ssl_random[32];
            u_char ssl_handshake_session_id_length;
            u_short ssl_handshake_cipher_suites_length;
        };
#pragma pack()

        u_char *ssl_handshake_comp_methods_length;

#pragma pack(1)
        struct sniff_ssl_L {
            u_short ssl_handshake_extensions_length;
            u_short ssl_handshake_extension_type;
            u_short ssl_handshake_extension_len;
            u_short ssl_handshake_extension_renegotiation_info_type;
            u_short ssl_handshake_extension_renegotiation_info_length;
            u_char ssl_handshake_extension_renegotiation_length;
            u_short ssl_handshake_extensions_server_name;
            u_short ssl_handshake_extensions_server_name_len;
            u_short ssl_handshake_extensions_server_name_ind_list_len;
            u_char ssl_handshake_extensions_server_name_ind_type;
            u_short ssl_handshake_extensions_server_name_ind_len;
        };
#pragma pack()


protected:


public:
    DPI(const char *interfaz, const char *filtro);
	char* getInterfazCaptura();
//	void detectarTipoTrafico();
	bool comenzarCaptura();
	void parsePaquete(std::vector<Enlace*> *vecEnl, DBconnector *conector);
};
