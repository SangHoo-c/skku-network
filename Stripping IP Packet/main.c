#include <stdio.h>
#include <time.h>

// socket 관련 헤더 파일
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define MAC_ADDR_LEN 6
#define MAX_PACKET 5


// PCAP-Header
//  _______________________________________________________________________________
//  |            8                                 |          4            |        4             |
//   ______________________________________________________________________________
//  | seconds(4)         | micro seconds(4)         |        caplen          |       len          |
//  _______________________________________________________________________________

typedef struct _timeval {
    unsigned int timesec;
    unsigned int timeusec;
}timeval;

typedef struct _pcap_header
{
    timeval time;
    unsigned int caplen; /* length of portionpresent */
    unsigned int len;     /*length thispacket (off wire) */
}pcap_header;



//                 ethernet protocal stack
//   ____________________________________________________________________________
//  |                   6                  |                 6                 |       2       |
//  ____________________________________________________________________________
//  |          dest mac address       |       src mac address                    |     type     |
//  ____________________________________________________________________________

// 총 14 bytes
typedef struct _ethernet
{
    unsigned char dest_mac[MAC_ADDR_LEN];
    unsigned char src_mac[MAC_ADDR_LEN];
    unsigned short type;
}ethernet;

//                          IPv4 protocol stack
//   _____________________________________________________________________________________
//  |    4      |    4      |        8           |              16                       |
//   _____________________________________________________________________________________
//  |   version |  HLEN     |    service type    |         total length                  |
//   _____________________________________________________________________________________
//  |                      16                    |     3   |              13             |
//   _____________________________________________________________________________________
//  |                 identification             |  Flags  |      Fragment offset        |
//   _____________________________________________________________________________________
//  |         8             |        8           |              16                       |
//   _____________________________________________________________________________________
//  |    Time To Live       |     Protocol       |            Header Checksum            |
//   ____________________________________________________________________________________
//  |                                           32                                       |
//   ____________________________________________________________________________________
//  |                                   Source IPv4 Address                              |
//   ____________________________________________________________________________________
//  |                                           32                                       |
//   ____________________________________________________________________________________
//  |                                 Destination IPv4 Address                           |
//   ____________________________________________________________________________________
//  |                                     0~320(40 바이트)                               |
//   ____________________________________________________________________________________
//  |                                    Options and Padding                             |
//   ____________________________________________________________________________________


typedef struct IPHeader{
    unsigned char Version : 4;
    unsigned char IHL : 4;
    unsigned char TOS;
    u_short TotalLen;
    unsigned short Identification;
    unsigned char Flagsx : 1;
    unsigned char FlagsD : 1;
    unsigned char FlagsM : 1;
    unsigned int FO : 13;
    unsigned char TTL;
    unsigned char Protocal;
    unsigned short HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;




pcap_header headers[MAX_PACKET];
int pcnt;
int parsing(FILE *fp);
void view_ethernet(char *buf);
unsigned short custom_ntohs(unsigned short value);
void view_ip(char *buf);


void help(){
    printf("Write File Name\n");
    printf("ex) captrue.pcap \n pcap 파일 명을 입력하세요 :  ");
}

int main(int argc, char* argv[])
{
    if (argc != 2){
        help();
        return -1;
    }

    char *fname;
    fname = argv[1];
    FILE *fp = fopen(fname, "rb"); // 전달받은 파일을 읽기/바이너리모드로 열기
    if(fp == NULL){
        printf("error : 파일이 없습니다. \n");
        return 0;
    }

    parsing(fp);
    fclose(fp);
    return 0;
}


int parsing(FILE *fp)
{
    // 파일 정보 읽기
    char pfh[24] = {0,};
    fread(&pfh, 24, 1, fp);

    char buf[65536];
    pcap_header *ph = headers;
//    printf("\n%d \n", sizeof(pcap_header));
//    printf("\n%d \n", sizeof(timeval));

    int i = 0;
    while (feof(fp) == 0)
    {
        // header 파일 읽기
        if (fread(ph, 16, 1, fp) != 1) break;
        if (pcnt > MAX_PACKET) break;

        // time.h 헤더에 있는 time_t 구조체에 sec 값으로 초기화 한다.
        time_t t = ph->time.timesec;

        struct tm tm = *localtime(&t);
        pcnt++;
        printf("%s\n", "=======================");
        printf("NO %d packet. \n", pcnt);

        printf("#1. local time : %d:%d:%d.%d\n",
               tm.tm_hour, tm.tm_min, tm.tm_sec, ph->time.timeusec);

        printf("#2. cap-len : %d,  actual-len : %d \n",ph->caplen, ph->len);
        fread(buf, 1, ph->caplen, fp);  // capture 한만큼 읽어서 buffer 에 저장해둔다.

        view_ethernet(buf);     // ethernet 분석
        view_ip(buf+14);    // ip 분석, (ethernet 14 bytes 이동)

        ph++;
    }
    return 0;
}


void view_ethernet(char *buf)
{
    ethernet *ph = (ethernet *)buf;

    printf("#3. src mac : 0x");
    for (int i = 0;i < MAC_ADDR_LEN; ++i){
        if(i==5) printf("%x", ph->src_mac[i]);
        else printf("%x:", ph->src_mac[i]);
    }
    printf(", dest mac:0x");
    for (int i = 0;i < MAC_ADDR_LEN; ++i){
        if(i==5) printf("%x", ph->dest_mac[i]);
        else printf("%x:", ph->dest_mac[i]);
    }
    printf("\n");
}

// network byte order 의 패킷 정보를 host byte order 로 변환
// Unsigned 16 bit conversion
// ref. https://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func
unsigned short custom_ntohs(unsigned short value)
{
    return (value >> 8) | (value << 8) ;
}


void view_ip(char *buf)
{
    IPH *ih;
    ih = (IPH *)buf;
//    if (ih -> Protocal == 0x06) printf ("TCP\n");
    printf("#4. ");
    printf("Src IP  : %s, ", inet_ntoa(ih->SrcAdd) );
    printf("Dst IP  : %s\n", inet_ntoa(ih->DstAdd) );

    printf("#5. Protocol : ");
    switch (ih->Protocal)   // Protocol: ICMP(1), TCP(6), UDP(17)
    {
        case 1: printf("ICMP\n"); break;
        case 6: printf("TCP\n"); break;
        case 17: printf("UDP\n"); break;
        default: printf("Not support\n"); break;
    }

    printf("#6. identification : %#x ,", custom_ntohs(ih->Identification)); // fragment 하여 보내지는 패킷을 구분하기 위한 필드
    printf("Flags : 0x");
    printf("%d", ih->FlagsD);
    printf("%d\n", ih->FlagsM);

    printf("#7. identification in decimal : %d ,", custom_ntohs(ih->Identification));
    if(ih->FlagsD == 0) printf("%s \n", "DF ");
    else printf("%s \n", "MF ");

    printf("#8. TTL : %d \n", ih->TTL);


}
