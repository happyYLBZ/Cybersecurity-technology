#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
using namespace std;

#define BUFFER_SIZE 65536
#define ARP_HEADER_LEN 8

// 处理捕获的数据包
void process_packet(unsigned char* buffer, int size, const string& filter_ip, int filter_protocol) {
    // 解析以太网头部
    ethhdr* eth_header = (ethhdr*)buffer;
    uint16_t ethertype = ntohs(eth_header->h_proto);
    // IP报文
    if (ethertype == ETH_P_IP && filter_protocol != 2054) {
        // 解析IP头部
        iphdr* ip_header = (iphdr*)(buffer + sizeof(ethhdr));
        sockaddr_in source, dest;

        // 获取源IP地址和目的IP地址
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip_header->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip_header->daddr;

        // 判断是否过滤指定IP地址
        if (!filter_ip.empty() && filter_ip != inet_ntoa(source.sin_addr) && filter_ip != inet_ntoa(dest.sin_addr))
            return;

        // 判断是否过滤指定协议类型
        if (filter_protocol != -1 && ip_header->protocol != filter_protocol)
            return;

        // 打印源IP地址和目的IP地址
        cout << "Source IP: " << inet_ntoa(source.sin_addr) << endl;
        cout << "Destination IP: " << inet_ntoa(dest.sin_addr) << endl;

        // 判断协议类型并输出
        switch (ip_header->protocol) {
            tcphdr* tcp_header;
            udphdr* udp_header;
        case IPPROTO_TCP:
            cout << "Protocol: TCP" << endl;
            // 解析TCP头部
            tcp_header = (tcphdr*)(buffer + sizeof(ethhdr) + sizeof(iphdr));
            cout << "Source Port: " << ntohs(tcp_header->source) << endl;
            cout << "Destination Port: " << ntohs(tcp_header->dest) << endl;
            break;
        case IPPROTO_UDP:
            cout << "Protocol: UDP" << endl;
            // 解析UDP头部
            udp_header = (udphdr*)(buffer + sizeof(ethhdr) + sizeof(iphdr));
            cout << "Source Port: " << ntohs(udp_header->source) << endl;
            cout << "Destination Port: " << ntohs(udp_header->dest) << endl;
            break;
        case IPPROTO_ICMP:
            cout << "Protocol: ICMP" << endl;

            break;

        }
    }
    // ARP报文
    if (ethertype == ETH_P_ARP && filter_protocol != 0) {
        cout << "Protocol: ARP" << endl;
        // 解析ARP头部
        arphdr* arp_header = (arphdr*)(buffer + sizeof(ethhdr));


        // 源 IP 地址的偏移量
        int src_ip_offset = ARP_HEADER_LEN + 6;
        // 目标 IP 地址的偏移量
        int dst_ip_offset = ARP_HEADER_LEN + 16;

        // 提取源 IP 地址
        char src_ip_str[INET_ADDRSTRLEN];
        struct in_addr src_ip;
        memcpy(&src_ip, arp_header + src_ip_offset, sizeof(struct in_addr));
        inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);

        // 提取目标 IP 地址
        char dst_ip_str[INET_ADDRSTRLEN];
        struct in_addr dst_ip;
        memcpy(&dst_ip, arp_header + dst_ip_offset, sizeof(struct in_addr));
        inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

        // 将 IP 地址转换为字符串
        string src_ip_string(src_ip_str);
        string dst_ip_string(dst_ip_str);

        // 判断是否过滤指定IP地址
        if (!filter_ip.empty() && filter_ip != src_ip_string && filter_ip != dst_ip_string)
            return;

        // 打印硬件类型
        cout << "Hardware Type: " << ntohs(arp_header->ar_hrd) << endl;
        // 打印协议类型
        cout << "Protocol Type: " << ntohs(arp_header->ar_pro) << endl;
        // 打印硬件地址长度
        cout << "Hardware Length: " << static_cast<unsigned int>(arp_header->ar_hln) << endl;
        // 打印协议地址长度
        cout << "Protocol Length: " << static_cast<unsigned int>(arp_header->ar_pln) << endl;
        // 打印操作码
        cout << "Opcode: " << ntohs(arp_header->ar_op) << endl;

        // 打印源IP地址
        cout << "Source IP: " << src_ip_str << endl;
        // 打印目的IP地址
        cout << "Destination IP: " << dst_ip_str << endl;
    }

    // 打印物理地址
    cout << "Source MAC: ";
    for (int i = 0; i < 6; ++i) {
        printf("%02x", eth_header->h_source[i]);
        if (i < 5) cout << ":";
    }
    cout << endl;

    cout << "Destination MAC: ";
    for (int i = 0; i < 6; ++i) {
        printf("%02x", eth_header->h_dest[i]);
        if (i < 5) cout << ":";
    }
    cout << endl;

    cout << endl;
}

int main() {
    int raw_socket;
    unsigned char buffer[BUFFER_SIZE];

    string filter_ip;
    int filter_protocol = -1;

    // 获取过滤器IP地址
    cout << "Enter filter IP address (or leave empty for no filtering): ";
    getline(cin, filter_ip);

    // 获取过滤器协议类型
    cout << "Enter filter protocol (IP：0，ARP：2054，TCP: 6, UDP: 17, ICMP: 1, or leave empty for no filtering): ";
    string protocol_str;
    getline(cin, protocol_str);
    if (!protocol_str.empty()) {
        filter_protocol = stoi(protocol_str);
    }

    // 创建原始套接字
    raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }
    cout << "begin to capture!" << endl;
    while (1) {
        // 接收数据包
        int data_size = recv(raw_socket, buffer, BUFFER_SIZE, 0);
        if (data_size < 0) {
            perror("Failed to receive data");
            return 1;
        }

        // 处理接收到的数据包，仅当源IP地址匹配过滤器时
        process_packet(buffer, data_size, filter_ip, filter_protocol);
    }

    close(raw_socket);
    return 0;
}

