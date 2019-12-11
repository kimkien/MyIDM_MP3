
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
#include<stdlib.h>
#include "ws2tcpip.h"
#include<string.h>
#include<conio.h>
#include <cstring>


#define nThread 4

using namespace std;

typedef struct LINK {
	//
	char* ip;
	char* messGetContent;
	char fileName[128];

	//multithread
	int stat = 0, begin, end;

	//check if done
	bool isDone = false;

	int vitri = 0;
	int sizeFile = 0;
	char messGetHead[512];
} LINK, THREADDATA;


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//xu ly lua chon de download
DWORD WINAPI initDownloader(LPVOID lpParam);
//int initDownloader(char* lpParam);

//decode file dang url sang chuoi binh thuong
char *urldecode(const char *url);

//preprocessing to download blocking
void down_Blocking(char *link);

//  lay host name, path, file name, chuoi de gui request
void detachUrl(char * url, char * hostname, char * filename,char * messGetHead, char * messGetContent);

// Phan giai ten mien de lay id tao message
void convertDomain(char * hostname, char *ip); 

//lay header => dung luong file
void getHead(char * messGetHead, SOCKADDR_IN addr, int & sizeFile); 

// download file
void taiFile(LINK lk); 

// download file da luong
DWORD WINAPI DownloadThread(LPVOID);

//noi cac file sau khi download da luong
void concatFile(char* nameFile);

//preprocessing to download multithread
void down_Multithread(char* link);

//remove url in list url 
void RemoveUrl(char* url);

/*---------------------------
--------GLOBAL VALUES--------
-----------------------------*/

int totalLink; // de luu tru tong so link trong file
LINK structLinks[64];
HANDLE handle[64];

THREADDATA* tData[4]; //luu du lieu cua cac thread
HANDLE thread[4]; // luu cac thread
HANDLE t;
CRITICAL_SECTION cr = { 0 };
int downloaded = 0;
int pexit = 0;
char url_file[20][256];
int num_url = 0;
int key; //chon cach thuc download file

char c = ' '; // kiem tra xem co dung khong (p=stop; r=resum)


/*----------------------------------------
-------------MAIN FUNCTION----------------
------------------------------------------*/
int main()
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

	printf("\n==========DOWNLOADER=============");
	printf("\nLua chon chuc nang: \n");
	printf("1. Download file don luong.\n");
	printf("2. Download file da luong.\n");
	printf("Phim khac de thoat\n");
	printf("Vui long chon: ");
	cin >> key;
	if ((key != 1) && (key != 2))
		return -1;


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
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet
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
	//printf("Total packet available: %d bytes\n", header->caplen);
	//printf("Expected packet size: %d bytes\n", header->len);

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
	//printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

	/* Now that we know where the IP header is, we can
	   inspect the IP header for a protocol number to
	   make sure it is TCP before going any further.
	   Protocol is always the 10th byte of the IP header */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) {
		//printf("Not a TCP packet. Skipping...\n\n");
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
	//printf("TCP header length in bytes: %d\n", tcp_header_length);



	/* Add up all the header sizes to find the payload offset */
	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	//printf("Size of all headers combined: %d bytes\n", total_headers_size);
	payload_length = header->caplen -
		(ethernet_header_length + ip_header_length + tcp_header_length);
	//printf("Payload size: %d bytes\n", payload_length);
	payload = packet + total_headers_size;
	//printf("Memory address where payload begins: %p\n\n", payload);

	/* Print payload in ASCII */
	string temp((char *)payload);
	/*FILE *f = fopen("./log2.txt", "a");
	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		while (byte_count++ < payload_length) {
			fprintf(f,"%c", *temp_pointer);
			temp_pointer++;
		}
		fprintf(f,"\n---------\n");

	}
	fclose(f);*/
	regex location("(Location(\s?):(\s?).+)");
	regex link("(http.*(\.*)[(mp3)|(MP3)].+)");

	smatch smatch,smatch2; 
	//cout << "Text: " << temp << endl;
	if (regex_search(temp, smatch, location)) {
		string locat(smatch[0]);
		if (regex_search(locat, smatch2, link)) {
				cout << "address: " << smatch2[0] << endl;          // (6)
				string str_url = smatch2[0];

				char temp[256];
				strcpy(url_file[num_url], str_url.c_str());
				//strcpy(url_file[num_url], temp);
				cout << "url: " << url_file[num_url] << endl;
				CreateThread(NULL, 0, initDownloader, url_file[num_url], 0, NULL);
		}

	}

	//cout << endl;
	//system("pause");
	return;
}

DWORD WINAPI initDownloader(LPVOID lpParam) {
	char *url = (char *)lpParam;
	printf("%s", url);

	num_url++;

	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);

	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r); //stores the console's current dimensions

	MoveWindow(console, r.left, r.top, 1200, 600, TRUE);

	InitializeCriticalSection(&cr);

	//system("cls");
	switch (key)
	{
	case 1:
		down_Blocking(url);
		break;
	case 2:
		down_Multithread(url);
		break;
	default:
		exit(0);
	}
	DeleteCriticalSection(&cr);
	WSACleanup();
	return 0;
}

void down_Blocking(char *link) {
	char hostname[256];
	LINK lk;

	lk.messGetContent = new char[256];
	detachUrl(link, hostname, lk.fileName, lk.messGetHead, lk.messGetContent);
	strcpy(lk.fileName, urldecode(lk.fileName));
	lk.ip = new char[256];
	convertDomain(hostname, lk.ip);
	taiFile(lk);
	//system("cls");
}

void taiFile(LINK lk) {
	SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKADDR_IN addr;
	char server_reply[10000];
	int total = 0;
	int sizeFile, sizeHeadInFile = 0;
	ofstream file;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(lk.ip);
	addr.sin_port = htons(80);

	getHead(lk.messGetHead, addr, sizeFile);
	int ret = connect(client, (SOCKADDR *)&addr, sizeof(addr));

	sprintf(lk.messGetContent, "%s\r\n", lk.messGetContent);
	file.open(lk.fileName, ios::out | ios::binary);
	if (!file.is_open()) {
		printf("File could not opened");
	}


	send(client, lk.messGetContent, strlen(lk.messGetContent), 0);

	int k = 0;
	printf("\n-------Downloading file: %s \n\n", lk.fileName);
	while (1)
	{
		char lenh[1024];
		int received_len = recv(client, server_reply, sizeof(server_reply), 0);
		if (received_len < 0) {
			printf("\n-------Fail to download file: %s \n\n", lk.fileName);
			break;
		}
		if (received_len == 0) {
			/*char deleteFile[256];
			sprintf(deleteFile, "temp//%s.txt", lk.fileName);
			remove(deleteFile);*/
			printf("\n-------Success file : %s \n\n", lk.fileName);
			break;
		}
		//no phan HTTP/1.1 o dau file
		if (k == 0 && (strncmp(server_reply, "HTTP/1.1", 8) == 0)) {
			for (int j = 0; j < received_len - 4; j++) {
				if (strncmp(server_reply + j, "\r\n\r\n", 4) == 0) {
					sizeHeadInFile = j + 4;
					break;
				}
			}
			memcpy(server_reply, server_reply + sizeHeadInFile, received_len - sizeHeadInFile);
			received_len -= sizeHeadInFile;
			k++;
		}
		total += received_len;
		file.write(server_reply, received_len);

		//luu lai thong tin tai

		/*sprintf(lenh, "echo %d>temp//\"%s.txt\"", total, lk.fileName);
		system(lenh);*/
		//printf("\nFile: %s- Kich thuoc da nhan: %d/%d", lk.fileName, total, sizeFile);
		//system("cls");
		if (total >= sizeFile) {
			char deleteFile[256];
			/*sprintf(deleteFile, "temp//%s.txt", lk.fileName);
			remove(deleteFile);*/
			printf("\n-------Success file: %s \n\n", lk.fileName);
			break;
		}
	}
	file.close();
	closesocket(client);
	structLinks[lk.vitri].isDone = true;
}

void down_Multithread(char* link) {
	char hostname[512], filename[512];
	char ip[512];
	//char link[256];
	char messGetHead[512], messGetContent[512];
	char server_reply[10000];
	int sizeFile;
	SOCKADDR_IN addr;
	pexit = 0;
	char cmd[512];

	detachUrl(link, hostname, filename, messGetHead, messGetContent);
	strcpy(filename, urldecode(filename));
	convertDomain(hostname, ip);

	sprintf(cmd, "echo %s > temp1//\"link_%s_%s.txt\"", link, hostname, filename);
	downloaded = 0;
	system(cmd);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(80);


	getHead(messGetHead, addr, sizeFile);
	int sizePerThread = sizeFile / nThread;
	printf("size per thread/size file: %d/%d\n", sizePerThread, sizeFile);
	for (int i = 0; i < nThread; i++) {
		tData[i] = (THREADDATA *)malloc(sizeof(THREADDATA));
		tData[i]->ip = ip;
		tData[i]->messGetContent = messGetContent;
		tData[i]->stat = 0;
		tData[i]->begin = i * sizePerThread;
		if (i != nThread - 1)
			tData[i]->end = (i + 1) * sizePerThread - 1;
		else
			tData[i]->end = sizeFile;

		sprintf(tData[i]->fileName, "df_%s_%s_%d.txt", hostname, filename, i);
		
		remove(tData[i]->fileName);
		
	}

	{
		for (int i = 0; i < nThread; i++) {
			thread[i] = CreateThread(NULL, 0, DownloadThread, tData[i], 0, NULL);
		}


		while (1) {
			if (pexit == nThread) {
					printf("\rdownloaded %dB -100%%  ", sizeFile);
					printf("\nOK!\n\n");
					CloseHandle(t);
					concatFile(filename);
					break;
			}
		}
	}
}

void concatFile(char* nameFile) {
	remove(nameFile);
	char cmd[256];
	ofstream file(nameFile);
	file.close();
	for (int i = 0; i < nThread; i++) {
		sprintf(cmd, "copy /b \"%s\" + \"%s\" \"%s\"", nameFile, tData[i]->fileName, nameFile);
		system(cmd);
		remove(tData[i]->fileName);
	}
	printf("\n-------Success file: %s \n\n", nameFile);
}

DWORD WINAPI DownloadThread(LPVOID lpParam) {

	THREADDATA* threadData = (THREADDATA *)lpParam;
	SOCKET s;
	SOCKADDR_IN server;
	server.sin_addr.s_addr = inet_addr(threadData->ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(80);
	ofstream file;
	char message[512], buf[100000];

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	connect(s, (SOCKADDR *)&server, sizeof(server));

	file.open(threadData->fileName, ios::out | ios::binary);
		if (!file.is_open()) {
			printf("File could not open");
		}


	sprintf(message, "%sRange: bytes=%d-%d\r\n\r\n", threadData->messGetContent, threadData->begin + threadData->stat, threadData->end);

	if (send(s, message, strlen(message), 0) < 0)
	{
		puts("Send failed");

		return 1;
	}
	int k = 0, sizeHeadInFile;
	while (1)
	{
		char lenh[1024];
		if (c == 'p') {
			sprintf(lenh, "echo %s %d>temp1//\"%s.txt\"", threadData->ip, threadData->stat, threadData->fileName);
			system(lenh);
			EnterCriticalSection(&cr);
			pexit += 1;
			LeaveCriticalSection(&cr);
			break;
		}

		int received_len = recv(s, buf, sizeof buf, 0);

		if (received_len < 0) {
			puts("recv failed");
			break;
		}
		if (received_len == 0) {
			EnterCriticalSection(&cr);
			pexit += 1;
			LeaveCriticalSection(&cr);
			char tmp[256];
			sprintf(tmp, "temp1//%s.txt", threadData->fileName);
			remove(tmp);
			break;
		}

		if(received_len< 100000)
			buf[received_len] = 0;

		if (k == 0 && (strncmp(buf, "HTTP/1.1", 8) == 0)) {
			for (int j = 0; j < received_len - 4; j++) {
				if (strncmp(buf + j, "\r\n\r\n", 4) == 0) {
					sizeHeadInFile = j + 4;
					break;
				}
			}
			memcpy(buf, buf + sizeHeadInFile, received_len - sizeHeadInFile);
			received_len -= sizeHeadInFile;

			k++;
		}

		EnterCriticalSection(&cr);
		downloaded += received_len;
		LeaveCriticalSection(&cr);

		threadData->stat += received_len;

		file.write(buf, received_len);

		if (threadData->stat >= threadData->end - threadData->begin) {
			EnterCriticalSection(&cr);
			pexit += 1;
			LeaveCriticalSection(&cr);
			char tmp[256];
			sprintf(tmp, "temp1//%s.txt", threadData->fileName);
			remove(tmp);

			break;
		}
	}
	file.close();
	closesocket(s);
	return 0;
}

void detachUrl(char * url, char * hostname, char * filename, char * messGetHead, char * messGetContent) {
	int i = 7, k = 0;
	char path[256];
	for (; i < strlen(url); i++) {
		if (url[i] == '/') {
			break;
		}
		hostname[i - 7] = url[i];
		hostname[i - 6] = 0;
	}
	sprintf(path, "%s", url + i);
	for (k = strlen(url) - 1; k >= 0; k--) {
		if (url[k] == '/') {
			break;
		}
	}
	sprintf(filename, "%s", url + 1 + k);
	sprintf(messGetHead, "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, hostname);
	sprintf(messGetContent, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nKeep-Alive: 300\r\n", path, hostname);
}

void getHead(char * messGetHead, SOCKADDR_IN addr, int &sizeFile) {
	char buf[1024];

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int ret = connect(s, (SOCKADDR *)&addr, sizeof(addr));
	send(s, messGetHead, strlen(messGetHead), 0);
	ret = recv(s, buf, sizeof(buf), 0);
	if (ret > 0) {
		if(ret <1024)
			buf[ret] = 0;

		for (int i = 0; i < ret; i++) {
			if (strncmp(buf + i, "Content-Length: ", 16) == 0) {
				i += 16;
				int j = i;
				char temp[16];
				while (buf[j] != '\r') {
					j++;
				}
				strncpy(temp, buf + i, j - i);
				sscanf(temp, "%d", &sizeFile);
				break;
			}
		}
	}
	//	
	closesocket(s);
}

void convertDomain(char * hostname, char *ip) {
	struct hostent *host;

	host = gethostbyname(hostname);
	if (host == NULL)
	{
		cout << "loi phan giai";
	}
	else
	{
		strcpy(ip, (inet_ntoa(*((struct in_addr *) host->h_addr_list[0]))));
	}

}

char* urldecode(const char *url) {
	int i = 0;
	int key = 0;
	char buff[256] = "";
	boolean addtail = false;
	while (i < strlen(url)) {
		if (url[i] == '%' && url[i + 1] == '2' && url[i + 2] == '0') {
			strncat(buff, url + key, i - key);
			i += 2;
			key = i + 1;
			strcat(buff, " ");
		}
		if ((url[i] == '/' || url[i] == '<' || url[i] == '>'
			|| url[i] == ':' || url[i] == '*' || url[i] == '?'
			|| url[i] == '\\' || url[i] == '|' || url[i] == '\"')) {
			strncat(buff, url + key, i-key);
			i = i + 1;
			key = i+1;
			strcat(buff, "_");
		}
		if (i == (strlen(url) - 3) && url[i] != '.') addtail = true;
		i++;
	}
	strcat(buff, url + key);
	if (addtail) strcat(buff, ".mp3");
	return (char *)buff;
}

void RemoveUrl(char* url)
{
	// Tim vi tri can xoa
	int i = 0;
	for (; i < num_url; i++)
		if (strcmp(url_file[i], url)==0 )
			break;

	// Xoa phan tu tai vi tri i
	if (i < num_url)
	{
		if (i < num_url - 1)
		{
			strcpy(url_file[i], url_file[num_url - 1]);
		}

		num_url--;
	}
}
