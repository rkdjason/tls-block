#include <cstdio>
#include <string>
#include <map>

#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "tlshdr.h"

void usage() {
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

struct Key {
    Ip src_ip;
    uint16_t src_port;
    Ip dst_ip;
    uint16_t dst_port;
    bool operator<(const Key& r) const{
         return std::tie(src_ip, src_port, dst_ip, dst_port) < std::tie(r.src_ip, r.src_port, r.dst_ip, r.dst_port);
    }
};

struct ParsedData {
    std::string data;
    size_t total_len = 0;
    size_t current_len = 0;
};

std::map<Key, ParsedData> tls_buffer;

// https://github.com/lattera/freebsd/blob/master/lib/libc/string/strnstr.c
char *strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

// Retrieve MAC address of given interface
Mac get_mac(char *interface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Error: couldn't retrieve MAC address - socket() failed\n");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\x00';
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        fprintf(stderr, "Error: couldn't retrieve MAC address - ioctl() failed\n");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
static uint16_t compute_checksum(uint16_t *addr, uint32_t count) {
    uint32_t sum = 0;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += (*addr & 0xFF00);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum & 0xFFFF;
}

void compute_ip_checksum(struct IpHdr *ip_hdr){
    ip_hdr->checksum_ = 0;
    ip_hdr->checksum_ = compute_checksum(reinterpret_cast<uint16_t*>(ip_hdr), ip_hdr->ihl() << 2);
}

void compute_tcp_checksum(IpHdr *ip_hdr, TcpHdr *tcp_hdr, uint8_t *data, size_t data_len){
    uint32_t sum = 0;
    const uint16_t tcp_len = sizeof(TcpHdr) + data_len;

    // Pseudo header
    sum += (ip_hdr->src_ip_ >> 16) & 0xFFFF;
    sum += ip_hdr->src_ip_ & 0xFFFF;
    sum += (ip_hdr->dst_ip_ >> 16) & 0xFFFF;
    sum += ip_hdr->dst_ip_ & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // TCP header
    tcp_hdr->checksum_ = 0; // Initialize checksum to 0
    const uint16_t *tcp_ptr = reinterpret_cast<uint16_t*>(tcp_hdr);
    size_t tcp_words = sizeof(TcpHdr) / 2;

    for (size_t i = 0; i < tcp_words; i++) {
        sum += tcp_ptr[i];
    }

    // TCP payload (data)
    const uint16_t *data_ptr = reinterpret_cast<const uint16_t*>(data);
    size_t data_words = data_len / 2;

    for (size_t i = 0; i < data_words; i++) {
        sum += data_ptr[i];
    }

    // Handle odd-length data (pad last byte)
    if (data_len % 2) {
        sum += *(reinterpret_cast<const uint8_t*>(data) + data_len - 1);
    }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;

    tcp_hdr->checksum_ = static_cast<uint16_t>(sum);
}

std::string extract_sni(const uint8_t *tls_data, size_t tls_data_len) {
    size_t offset = sizeof(TlsRecordHdr) + sizeof(TlsHandshakeHdr);

    if (offset + 2 > tls_data_len) return ""; // Version
    offset += 2;

    if (offset + 32 > tls_data_len) return ""; // Random
    offset += 32;

    if (offset + 1 > tls_data_len) return ""; // Session ID length
    uint8_t session_id_len = tls_data[offset++];
    if (offset + session_id_len > tls_data_len) return "";
    offset += session_id_len;

    if (offset + 2 > tls_data_len) return ""; // Cipher suites length
    uint16_t cipher_suites_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
    offset += 2 + cipher_suites_len;

    if (offset + 1 > tls_data_len) return ""; // Compression methods length
    uint8_t compression_len = tls_data[offset++];
    offset += compression_len;

    if (offset + 2 > tls_data_len) return ""; // Extensions length
    uint16_t extensions_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
    offset += 2;

    // Parsing Extensions
    size_t extensions_end = offset + extensions_len;
    while (offset + 4 <= extensions_end && offset + 4 <= tls_data_len) {
        uint16_t ext_type = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
        uint16_t ext_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset + 2));
        offset += 4;

        if (ext_type == TLS_EXTENSION_SERVER_NAME && offset + ext_len <= tls_data_len) {
            // Parsing Server Name Extension
            size_t sni_offset = offset;
            if (sni_offset + 2 > tls_data_len) break;

            uint16_t server_name_list_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + sni_offset));
            sni_offset += 2;

            if (sni_offset + server_name_list_len > tls_data_len) break;

            while (sni_offset + 3 <= offset + ext_len && sni_offset + 3 <= tls_data_len) {
                uint8_t name_type = tls_data[sni_offset++];
                uint16_t name_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + sni_offset));
                sni_offset += 2;

                if (name_type == TLS_SERVER_NAME_TYPE_HOSTNAME && sni_offset + name_len <= tls_data_len) {
                    return std::string(reinterpret_cast<const char*>(tls_data + sni_offset), name_len);
                }
                sni_offset += name_len;
            }
        }
        offset += ext_len;
    }

    return "";
}

void forward_rst(pcap_t *pcap, const EthHdr *org_eth, const IpHdr *org_ip, const TcpHdr *org_tcp, int org_tcp_data_len, Mac my_mac){
    // Create packet
    uint8_t packet[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)] = {0};
    EthHdr *eth_hdr = reinterpret_cast<EthHdr*>(packet);
    IpHdr *ip_hdr = reinterpret_cast<IpHdr*>(packet + sizeof(EthHdr));
    TcpHdr *tcp_hdr = reinterpret_cast<TcpHdr*>(packet + sizeof(EthHdr) + sizeof(IpHdr));

    // Ethernet header
    eth_hdr->smac_ = my_mac;
    eth_hdr->dmac_ = org_eth->dmac_;
    eth_hdr->type_ = htons(EthHdr::Ip4);

    // IP header
    ip_hdr->version_ihl_ = 0x45;    // IPv4, 20byte
    ip_hdr->tos_ = 0;   // default
    ip_hdr->total_length_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_hdr->id_ = htons(rand());    // identification
    ip_hdr->flags_fragment_ = htons(IpHdr::DF); // dont fragment
    ip_hdr->ttl_ = org_ip->ttl_;
    ip_hdr->protocol_ = IpHdr::TCP;
    ip_hdr->src_ip_ = org_ip->src_ip_;
    ip_hdr->dst_ip_ = org_ip->dst_ip_;
    compute_ip_checksum(ip_hdr);

    // TCP header
    tcp_hdr->src_port_ = org_tcp->src_port_;
    tcp_hdr->dst_port_ = org_tcp->dst_port_;
    tcp_hdr->seq_num_ = htonl(ntohl(org_tcp->seq_num_) + org_tcp_data_len);  // seq + data_size
    tcp_hdr->ack_num_ = org_tcp->ack_num_;
    tcp_hdr->data_offset_reserved_ = 0x50;  // sizeof(TCP)
    tcp_hdr->flags_ = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->window_ = 0;   // ignored in RST packets
    tcp_hdr->urgent_ptr_ = 0;   // ignored without URG flag
    compute_tcp_checksum(ip_hdr, tcp_hdr, nullptr, 0);

    if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
        printf("Error: failed to send RST packet (%s)\n", pcap_geterr(pcap));
    }
    else {
        printf("    - Forward RST packet sent\n");
    }
}

void backward_rst(int raw_sock, const IpHdr *org_ip, const TcpHdr *org_tcp, int org_tcp_data_len){
    // Create packet
    uint8_t packet[sizeof(IpHdr) + sizeof(TcpHdr)] = {0};
    IpHdr *ip_hdr = reinterpret_cast<IpHdr*>(packet);
    TcpHdr *tcp_hdr = reinterpret_cast<TcpHdr*>(packet + sizeof(IpHdr));

    // IP header
    ip_hdr->version_ihl_ = 0x45;    // IPv4, 20byte
    ip_hdr->tos_ = 0;   // default
    ip_hdr->total_length_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_hdr->id_ = htons(rand());    // identification
    ip_hdr->flags_fragment_ = htons(IpHdr::DF); // dont fragment
    ip_hdr->ttl_ = 128;
    ip_hdr->protocol_ = IpHdr::TCP;
    ip_hdr->src_ip_ = org_ip->dst_ip_;
    ip_hdr->dst_ip_ = org_ip->src_ip_;
    compute_ip_checksum(ip_hdr);

    // TCP header
    tcp_hdr->src_port_ = org_tcp->dst_port_;
    tcp_hdr->dst_port_ = org_tcp->src_port_;
    tcp_hdr->seq_num_ = org_tcp->ack_num_;
    tcp_hdr->ack_num_ = htonl(ntohl(org_tcp->seq_num_) + org_tcp_data_len);  // seq + data_size
    tcp_hdr->data_offset_reserved_ = 0x50;  // sizeof(TCP)
    tcp_hdr->flags_ = TcpHdr::RST | TcpHdr::ACK;
    tcp_hdr->window_ = 0;   // ignored in RST packets
    tcp_hdr->urgent_ptr_ = 0;   // ignored without URG flag
    compute_tcp_checksum(ip_hdr, tcp_hdr, nullptr, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = org_ip->src_ip_;

    if (sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        printf("Error: failed to send RST packet\n");
    } else {
        printf("    - Backward RST packet sent\n");
    }
}

bool tls_block(char *dev, char *pattern){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "Error: couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);  // IPv4
    if (raw_sock < 0) {
        perror("Error: raw socket creation failed");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    Mac my_mac = get_mac(dev);
    struct pcap_pkthdr *header;
    const u_char *packet;

    printf("[+] TLS Block started - %s\n", pattern);
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const EthHdr *eth_hdr = reinterpret_cast<const EthHdr*>(packet);
        if (eth_hdr->type() != EthHdr::Ip4) continue;

        const IpHdr *ip_hdr = reinterpret_cast<const IpHdr*>(packet + sizeof(EthHdr));
        if (ip_hdr->protocol() != IpHdr::TCP) continue;

        const TcpHdr *tcp_hdr = reinterpret_cast<const TcpHdr*>(packet + sizeof(EthHdr) + ip_hdr->ihl() * 4);
        if (tcp_hdr->dst_port() != TcpHdr::Https) continue;

        int tcp_data_offset = sizeof(EthHdr) + ip_hdr->ihl() * 4 + tcp_hdr->offset() * 4;
        if (header->caplen <= tcp_data_offset) continue;
        int tcp_data_len = header->caplen - tcp_data_offset;
        const uint8_t *tcp_data = packet + tcp_data_offset;

        Key key = {
           ip_hdr->src_ip_, tcp_hdr->src_port(), ip_hdr->dst_ip_, tcp_hdr->dst_port()
        };

        if (tls_buffer.find(key) == tls_buffer.end()) {
            // If new TLS connection
            if (tcp_data_len < sizeof(TlsRecordHdr) + sizeof(TlsHandshakeHdr)) continue;

            const TlsRecordHdr *tls_record = reinterpret_cast<const TlsRecordHdr*>(tcp_data);
            if (!tls_record->is_tls() || tls_record->type() != TlsRecordHdr::Handshake) continue;

            const TlsHandshakeHdr *tls_handshake = reinterpret_cast<const TlsHandshakeHdr*>(tcp_data + sizeof(TlsRecordHdr));
            if (tls_handshake->type() != TlsHandshakeHdr::ClientHello) continue;

            if (tcp_data_len == tls_record->len() + sizeof(TlsRecordHdr)){
                // one packet
                if (extract_sni(tcp_data, tcp_data_len) == std::string(pattern)) {
                    printf("[!] Pattern \"%s\" detected\n", pattern);
                    backward_rst(raw_sock, ip_hdr, tcp_hdr, tcp_data_len);
                    forward_rst(pcap, eth_hdr, ip_hdr, tcp_hdr, tcp_data_len, my_mac);
                }
            }
            else{
                printf("[-] Reassembling segmented TLS record\n");
                ParsedData& buf = tls_buffer[key];

                buf.data.append(reinterpret_cast<const char*>(tcp_data), tcp_data_len);
                buf.total_len = tls_record->len() + sizeof(TlsRecordHdr);
                buf.current_len = tcp_data_len;
            }
        }
        else {
            // Already in tls_buffer
            ParsedData& buf = tls_buffer[key];

            buf.data.append(reinterpret_cast<const char*>(tcp_data), tcp_data_len);
            buf.current_len += tcp_data_len;
            if (buf.current_len < buf.total_len) continue;

            printf("[-] Successfully reassembled segmented TLS record\n");
            if (extract_sni(reinterpret_cast<const uint8_t*>(buf.data.data()), buf.current_len) == std::string(pattern)) {
                printf("[!] Pattern \"%s\" detected\n", pattern);
                backward_rst(raw_sock, ip_hdr, tcp_hdr, tcp_data_len);
                forward_rst(pcap, eth_hdr, ip_hdr, tcp_hdr, tcp_data_len, my_mac);
            }
            tls_buffer.erase(key);
        }
    }

    close(raw_sock);
    pcap_close(pcap);
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char *pattern = argv[2];

    if (!tls_block(dev, pattern)) {
        return EXIT_FAILURE;
    }

}
