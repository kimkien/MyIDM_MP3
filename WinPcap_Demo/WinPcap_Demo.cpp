#include "pch.h"
#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdio.h>
#include <tchar.h>
#include <pcap.h>
#include <WinSock2.h>

#define CURL_STATICLIB
#include "curl/curl.h"
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;


//#include "dkstd_textfile.hpp"
#ifdef _DEBUG
#   pragma comment (lib, "curl/libcurl_a_debug.lib")
#else
#   pragma comment (lib, "curl/libcurl_a.lib")
#endif

char song[10];
int NumSong = 0;

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
	return written;
}

using namespace std;




/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and tcp and len >= 100";
	struct bpf_program fcode;
	pcap_dumper_t *dumpfile;


	/* Check command line */
	/*if (argc != 2)
	{
		printf("usage: %s filename", argv[0]);
		return -1;
	}
*/
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);


	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Open the dump file */
	dumpfile = pcap_dump_open(adhandle, "demo.txt");

	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	printf("\nlistening on %... Press Ctrl+C to stop...\n", d->description);

	/* At this point, we no longer need the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

	//openfile


	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *args,
	const struct pcap_pkthdr *header,
	const u_char *packet
)
{
	/* First, lets make sure we have an IP packet */
	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	/*if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		printf("Not an IP packet. Skipping...\n\n");
		return;
	}*/

	/* The total packet length, including all headers
	   and the data payload is stored in
	   header->len and header->caplen. Caplen is
	   the amount actually available, and len is the
	   total packet length even if it is larger
	   than what we currently have captured. If the snapshot
	   length set with pcap_open_live() is too small, you may
	   not have the whole packet. */
	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);

	/* Pointers to start point of various headers */
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	/* Header lengths in bytes */
	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length;
	int tcp_header_length;
	int payload_length;

	/* Find start of IP header */
	ip_header = packet + ethernet_header_length;
	/* The second-half of the first byte in ip_header
	   contains the IP header length (IHL). */
	ip_header_length = ((*ip_header) & 0x0F);
	/* The IHL is number of 32-bit segments. Multiply
	   by four to get a byte count for pointer arithmetic */
	ip_header_length = ip_header_length * 4;
	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

	/* Now that we know where the IP header is, we can
	   inspect the IP header for a protocol number to
	   make sure it is TCP before going any further.
	   Protocol is always the 10th byte of the IP header */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) {
		printf("Not a TCP packet. Skipping...\n\n");
		return;
	}

	/* Add the ethernet and ip header length to the start of the packet
	   to find the beginning of the TCP header */
	tcp_header = packet + ethernet_header_length + ip_header_length;
	/* TCP header length is stored in the first half
	   of the 12th byte in the TCP header. Because we only want
	   the value of the top half of the byte, we have to shift it
	   down to the bottom half otherwise it is using the most
	   significant bits instead of the least significant bits */
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	/* The TCP header length stored in those 4 bits represents
	   how many 32-bit words there are in the header, just like
	   the IP header length. We multiply by four again to get a
	   byte count. */
	tcp_header_length = tcp_header_length * 4;
	printf("TCP header length in bytes: %d\n", tcp_header_length);



	/* Add up all the header sizes to find the payload offset */
	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	printf("Size of all headers combined: %d bytes\n", total_headers_size);
	payload_length = header->caplen -
		(ethernet_header_length + ip_header_length + tcp_header_length);
	printf("Payload size: %d bytes\n", payload_length);
	payload = packet + total_headers_size;
	printf("Memory address where payload begins: %p\n\n", payload);

	/* Print payload in ASCII */
	FILE *f = fopen("./log2.txt", "a");
	string temp((char *)payload);
	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		while (byte_count++ < payload_length) {
			fprintf(f,"%c", *temp_pointer);
			temp_pointer++;
		}
		fprintf(f,"\n---------\n");

	}
	fclose(f);
	regex location("(Location(\s?):(\s?).+)");
	regex link("(http.*(\.*)[(mp3)|(MP3)].+)");

	smatch smatch,smatch2;
	cout << "Text: " << temp << endl;
	if (regex_search(temp, smatch, location)) {
		// (3)  

		cout << endl;
		cout << "Before the address: " << smatch.prefix() << endl;
		cout << "After the address: " << smatch.suffix() << endl;
		cout << endl;
		cout << "Length of adress: " << smatch.length() << endl;
		cout << endl;
		cout << "address: " << smatch[0] << endl;          // (6)
		cout << "Local part: " << smatch[1] << endl;             // (4)
		//cout << "Domain name: " << smatch[2] << endl;            // (5)
		string locat(smatch[0]);
		if (regex_search(locat, smatch2, link)) {
			cout << "Before the address: " << smatch2.prefix() << endl;
				cout << "After the address: " << smatch2.suffix() << endl;
				cout << endl;
				cout << "Length of adress: " << smatch2.length() << endl;
				cout << endl;
				cout << "address: " << smatch2[0] << endl;          // (6)
				cout << "Local part: " << smatch2[1] << endl;             // (4)
		}

	}

	cout << endl;
	//system("pause");
	return;
}