#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>       
#include <ws2tcpip.h>
using namespace std;

#pragma comment(lib, "Ws2_32.lib")

//IP数据报头
typedef struct IP_HEADER
{	
	unsigned char hdr_len : 4;       //4位首部长度
	unsigned char version : 4;       //4位版本号
	unsigned char tos;               //8位服务类型
	unsigned short tlen;             //16位总长度
	unsigned short identifier;       //16位标识符
	unsigned short flags_fo;         //3位标志加13位片偏移
	unsigned char ttl;               //8位生存时间
	unsigned char proto;             //8位上层协议号
	unsigned short checksum;         //16位校验和
	unsigned long sourceIP;          //32位源IP地址
	unsigned long destIP;            //32位目的IP地址
} IP_HEADER;

//ICMP数据报头
typedef struct ICMP_HEADER
{
	BYTE type;    //8位类型字段
	BYTE code;    //8位代码字段
	USHORT cksum; //16位校验和
	USHORT id;    //16位标识符
	USHORT seq;   //16位序列号
} ICMP_HEADER;

//报文解析结构
typedef struct DECODE_RESULT
{
	USHORT usSeqNo;        //序列号
	DWORD dwRoundTripTime; //时间戳
	in_addr dwIPaddr;      //返回报文的IP地址
}DECODE_RESULT;

//构造ICMP回显请求消息，并以TTL递增的顺序发送报文
//ICMP类型字段
const BYTE ICMP_ECHO_REQUEST = 8;    //ICMP回送请求
const BYTE ICMP_ECHO_REPLY = 0;    //ICMP回送回答
const BYTE ICMP_TIMEOUT = 11;   //ICMP时间超过

//其他常量定义
const int DEF_ICMP_DATA_SIZE = 32;    //ICMP报文默认数据字段长度
const int MAX_ICMP_PACKET_SIZE = 1500;  //ICMP报文最大长度
const DWORD DEF_ICMP_TIMEOUT = 3000;  //回显应答超时时间
const int DEF_MAX_HOP = 16;    //最大跳数设置16


// 创建原始套接字
SOCKET sockRaw;
// 填充目的端socket地址
sockaddr_in destSockAddr;

USHORT checksum(USHORT* pBuf, int iSize);//计算校验和

BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT);//解析ICMP数据包

u_long resolveIPAddress(char* ipAddress);//解析IP地址，得到32位

void initializeSocket(u_long DestIP);//初始化套接字

void Traceroute();//追踪路由



//计算校验和函数
USHORT checksum(USHORT* pBuf, int iSize)
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT); //每次iSize减2
	}
	if (iSize)//如果iSize为正，即为奇数个字节，则在末尾补上一个字节，使之有偶数个字节
	{
		cksum += *(UCHAR*)pBuf; 
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);//高16位和低16位相加
	cksum += (cksum >> 16);//得到最终的16位数
	return (USHORT)(~cksum);//结果取反
}

//对ICMP数据包进行解析
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT)
{
	//检查数据报大小的合法性
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;    //IP数据报头的长度是以4B为单位

	//若数据包大小 < IP数据报头 + ICMP数据报头，则数据报大小不合法
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
		return FALSE;

	//根据ICMP数据报文类型提取ID字段和seq字段
	ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf + iIpHdrLen);//ICMP数据报头 = 接收到的缓冲数据 + IP数据报头
	USHORT usID, usSquNo;

	if (pIcmpHdr->type == ICMP_ECHO_REPLY)    //ICMP回送回答报文
	{
		usID = pIcmpHdr->id;        //ICMP报文ID
		usSquNo = pIcmpHdr->seq;    //ICMP报文seq
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)//ICMP时间超过报文
	{
		char* pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER); //载荷中的IP头
		int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4; //载荷中的IP头长
		ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr + iInnerIPHdrLen);//载荷中的ICMP头

		usID = pInnerIcmpHdr->id;        //ICMP报文ID
		usSquNo = pInnerIcmpHdr->seq;    //ICMP报文seq
	}
	else
	{
		return false;
	}

	//检查ID和序列号以确定收到期待数据报
	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo)
	{
		return false;
	}
	//记录IP地址并计算往返时间
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime;

	//处理正确收到的ICMP数据报
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
	{
		//立刻输出往返时间信息
		if (DecodeResult.dwRoundTripTime)
			cout << "      " << DecodeResult.dwRoundTripTime << "ms" << flush;
		else
			cout << "      " << "<1ms" << flush;
	}
	return true;
}

u_long resolveIPAddress(char* ipAddress) {
	//得到IP地址
	u_long DestIP = inet_addr(ipAddress);//转化为32位二进制数
	//转换不成功时按域名解析
	if (DestIP == INADDR_NONE) 
	{
		hostent* pHostent = gethostbyname(ipAddress);//获取主机信息
		if (pHostent) {
			DestIP = (*(in_addr*)pHostent->h_addr).s_addr;//获取目的IP地址
		}
		else {
			cout << "Invalid IP address or Domain Name!" << endl;
			WSACleanup();//释放资源
			exit(1);
		}
	}
	return DestIP;
}

void initializeSocket(u_long DestIP) {
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in));//清除destSockAddr结构体中数据
	destSockAddr.sin_family = AF_INET;//设置版本为IPV4
	destSockAddr.sin_addr.s_addr = DestIP;//目的IP地址赋值

	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);//创建套接字，使用IPV4地址，接收原始数据，ICMP协议
	if (sockRaw == INVALID_SOCKET) {
		cout << "Failed to create raw socket." << endl;
		WSACleanup();
		exit(2);
	}

	//超时时间
	int timeout = 3000;

	// 设置接收超时时间
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	// 设置发送超时时间
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

	return;
}

void Traceroute() {
	//填充ICMP报文中每次发送时不变的字段
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];   //定义发送缓冲区  长度为头部+数据
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));                  //初始化发送缓冲区为0
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                       //定义接收缓冲区
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));				  //初始化接收缓冲区

	ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST;						  //设置ICMP类型为回送请求
	pIcmpHeader->code = 0;                                        //设置代码字段为0
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();			  //ID字段为当前进程号，使请求和响应报文匹配
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 0, DEF_ICMP_DATA_SIZE);//初始化数据字段

	USHORT usSeqNo = 0;            //ICMP报文序列号
	int iTTL = 1;                  //TTL初始值为1
	BOOL bReachDestHost = FALSE;   //到达目的标志
	int iMaxHot = DEF_MAX_HOP;     //ttl最大跳数为16
	DECODE_RESULT DecodeResult;    

	while (!bReachDestHost && iMaxHot--)//未到达目的且未到最大跳数
	{
		//设置IP报头的TTL字段
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		cout << iTTL << flush;    

		//填充ICMP报文中每次发送变化的字段
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;                   //校验和置为0
		((ICMP_HEADER*)IcmpSendBuf)->seq = usSeqNo++;             //填充序列号，每次加1
		((ICMP_HEADER*)IcmpSendBuf)->cksum =
			checksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE); //计算校验和

		//记录序列号和当前时间
		DecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;				//当前序号
		DecodeResult.dwRoundTripTime = GetTickCount();                          //获取当前时间戳

		//向目的地址发送缓冲区数据
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));

		//接收ICMP差错报文并进行解析处理
		sockaddr_in dst;           //对端socket地址
		int iFromLen = sizeof(dst);//地址结构大小
		int iReadDataLen;           //接收数据长度
		while (1)
		{
			//接收数据
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&dst, &iFromLen);
			if (iReadDataLen != SOCKET_ERROR)
			{
				//对数据包进行解析
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
				{
					//到达目的地，退出循环
					if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						//标志置为true
						bReachDestHost = true; 
					//输出IP地址
					cout << '\t' << inet_ntoa(DecodeResult.dwIPaddr) << endl;
					break;
				}
			}
			else if (WSAGetLastError() == WSAETIMEDOUT)    //socket超时失败
			{
				cout << "         *" << '\t' << "Request timed out." << endl;
				break;
			}
			else
			{
				break;
			}
		}
		iTTL++;    //递增TTL值，进行下次试探
	}
}

int main()
{
	//初始化Windows sockets网络环境
	WSADATA soc;
	WSAStartup(MAKEWORD(2, 2), &soc);
	//存储IP地址或域名
	char IpAddress[128];
	cout << "Please Input an IP address or Domain Name：";
	cin >> IpAddress;
	//解析IP地址或域名，形成32位二进制数
	u_long DestIP = resolveIPAddress(IpAddress);
	cout << "Tracing route to " << IpAddress << " with a maximum of 16 hops.\n" << endl;
	//根据目的IP地址创建套接字
	initializeSocket(DestIP);
	//执行路由追踪
	Traceroute();
	return 0;
}