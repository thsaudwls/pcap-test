#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "./libnet/include/libnet/libnet-headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int ethernet_header(const u_char* packet) {
	struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
	printf("=========Ethernet Header=========\n");
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
	return 14;
}

int ip_header(const u_char* packet) {
	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet);
	uint32_t ip_src_ori = ntohl(ip_hdr->ip_src.s_addr);
	uint32_t ip_dst_ori = ntohl(ip_hdr->ip_dst.s_addr);
	printf("============IP Header============\n");
	printf("src ip : %d.%d.%d.%d\n", (ip_src_ori >> 24) & 0xFF, (ip_src_ori >> 16) & 0xFF, (ip_src_ori >> 8) & 0xFF, ip_src_ori & 0xFF);
	printf("dst ip : %d.%d.%d.%d\n", (ip_dst_ori >> 24) & 0xFF, (ip_dst_ori >> 16) & 0xFF, (ip_dst_ori >> 8) & 0xFF, ip_dst_ori & 0xFF);
	return ip_hdr->ip_hl * 4;
}

int tcp_header(const u_char* packet) {
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 34);
	printf("============TCP Header===========\n");
	printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
	printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));
	return tcp_hdr->th_off * 4;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//Ethernet Header의 src mac / dst mac
		int offset = ethernet_header(packet);
		// IP Header의 src ip / dst ip
		offset += ip_header(packet + offset);
		// TCP Header의 src port / dst port
		offset += tcp_header(packet + offset);
		// Payload(Data)의 hexadecimal value(최대 20바이트까지만)
		printf("=========Payload(Data)=========\n");
		for (int i = 0; i < 20; i++) {
			printf("%02x ", packet[offset + i]);
			if (i % 10 == 9) printf("\n");
		}
	}

	pcap_close(pcap);
}