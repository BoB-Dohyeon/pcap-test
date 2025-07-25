#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

struct Ethernet_Struct{
	// uint8_t eth_dst[6]; // divide this into 32bit and 16bit??
	// uint8_t eth_src[6]; // hardcoding
	uint16_t eth_dst1; // I initially constructed the struct as uint32_t, uint16_t, uint32_t, uint16_t
	uint16_t eth_dst2; // But, it looks like that first uint16_t get 32bit data
	uint16_t eth_dst3; // So, second uint32_t get 8~14 bit
	uint16_t eth_src1; // Why? it is padding?
	uint16_t eth_src2;
	uint16_t eth_src3;
	uint16_t eth_type;
};

struct IP_Struct {
	uint8_t Version_IHL;
	uint8_t TOS;
	uint16_t TotalLength;
	uint16_t Identification;
	uint16_t Flags_FragmentOffset;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t HeaderChecksum;
	uint32_t SourceAddress;
	uint32_t DestinAddress;
};

struct TCP_Struct {
	uint16_t SourcePort;
	uint16_t DestinationPort;
	uint32_t SequenceNumber;
	uint32_t AckNumber;
	uint8_t DataOffset_Reserved;
	uint8_t CWR_ECE_URG_ACK_PSH_RST_SYN_FIN;
	uint16_t Window;
	uint16_t Checksum;
	uint16_t UrgentPointer;
};

void print_for_ip(uint8_t end, uint32_t* data) {
	uint8_t *save = (uint8_t *)(data);
	for(uint8_t i = 0; i < end; i++){
		printf("%d.", (uint8_t)(*(save + i)));
	}
	printf("%d", *(save + end));
}

void print_for_eth1(uint16_t *data){
	uint8_t *save = (uint8_t *)(data);
	for(uint8_t i = 0; i < 2; i++){
		printf("%02x:", (uint8_t)(*(save + i)));
	}
}

void print_for_eth2(uint16_t *data){
	uint8_t *save = (uint8_t *)(data);
	printf("%02x:", (uint8_t)(*(save + 0)));
	printf("%02x", (uint8_t)(*(save + 1)));
}

void print_all(struct Ethernet_Struct *Eth_save, struct IP_Struct *IP_save, struct TCP_Struct *TCP_save, uint8_t *payload, uint32_t payload_size){
	printf("-------- Ethernet --------\n");
	printf("Source MAC Address : ");
	print_for_eth1(&Eth_save->eth_src1);
	print_for_eth1(&Eth_save->eth_src2);
	print_for_eth2(&Eth_save->eth_src3);
	puts("");
	printf("Destination MAC Address : ");
	print_for_eth1(&Eth_save->eth_dst1);
	print_for_eth1(&Eth_save->eth_dst2);
	print_for_eth2(&Eth_save->eth_dst3);
	puts("");

	printf("-------- IP --------\n");
	printf("Source IP : ");
	print_for_ip(3, &IP_save->SourceAddress);
	puts("");
	printf("Destination IP : ");
	print_for_ip(3, &IP_save->DestinAddress);
	puts("");

	printf("-------- TCP --------\n");
	printf("Source Port TCP : ");
	printf("%d", ntohs(TCP_save->SourcePort));
	puts("");
	printf("Destination Port TCP : ");
	printf("%d", ntohs(TCP_save->DestinationPort));
	puts("");

	printf("-------- payload(data) --------\n");
	for(uint8_t i = 0; i < 20; i++)
		if (i < payload_size)
			printf("%02x|", (uint8_t)(*(payload + i)));
	else
		break;
	puts("");
}

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

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	uint32_t debug_data = 0;

	while (true) {
		debug_data += 1;
		printf("================== number : %d ==================\n", debug_data);
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// save data
		struct Ethernet_Struct* Eth_save = (struct Ethernet_Struct *)packet;
		packet = packet + 14;
		struct IP_Struct* IP_save = (struct IP_Struct *)packet;


		if(IP_save->Protocol == 0x06) {
			uint32_t header_size = (IP_save->Version_IHL & 0x0F) * 4;
			packet = packet + header_size;
			struct TCP_Struct* TCP_save = (struct TCP_Struct *)packet;

			uint32_t data_size = ((TCP_save->DataOffset_Reserved & 0xF0)>>4) * 4;
			packet = packet + data_size;

			uint8_t *payload_addr = (uint8_t*)packet;

			uint32_t payload_size = ntohs(IP_save->TotalLength) - header_size - data_size;



			print_all(Eth_save, IP_save, TCP_save, payload_addr, payload_size);
		}
	}

	pcap_close(pcap);
}
