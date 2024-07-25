#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>       
#include <ws2tcpip.h>
using namespace std;

#pragma comment(lib, "Ws2_32.lib")

//IP���ݱ�ͷ
typedef struct IP_HEADER
{	
	unsigned char hdr_len : 4;       //4λ�ײ�����
	unsigned char version : 4;       //4λ�汾��
	unsigned char tos;               //8λ��������
	unsigned short tlen;             //16λ�ܳ���
	unsigned short identifier;       //16λ��ʶ��
	unsigned short flags_fo;         //3λ��־��13λƬƫ��
	unsigned char ttl;               //8λ����ʱ��
	unsigned char proto;             //8λ�ϲ�Э���
	unsigned short checksum;         //16λУ���
	unsigned long sourceIP;          //32λԴIP��ַ
	unsigned long destIP;            //32λĿ��IP��ַ
} IP_HEADER;

//ICMP���ݱ�ͷ
typedef struct ICMP_HEADER
{
	BYTE type;    //8λ�����ֶ�
	BYTE code;    //8λ�����ֶ�
	USHORT cksum; //16λУ���
	USHORT id;    //16λ��ʶ��
	USHORT seq;   //16λ���к�
} ICMP_HEADER;

//���Ľ����ṹ
typedef struct DECODE_RESULT
{
	USHORT usSeqNo;        //���к�
	DWORD dwRoundTripTime; //ʱ���
	in_addr dwIPaddr;      //���ر��ĵ�IP��ַ
}DECODE_RESULT;

//����ICMP����������Ϣ������TTL������˳���ͱ���
//ICMP�����ֶ�
const BYTE ICMP_ECHO_REQUEST = 8;    //ICMP��������
const BYTE ICMP_ECHO_REPLY = 0;    //ICMP���ͻش�
const BYTE ICMP_TIMEOUT = 11;   //ICMPʱ�䳬��

//������������
const int DEF_ICMP_DATA_SIZE = 32;    //ICMP����Ĭ�������ֶγ���
const int MAX_ICMP_PACKET_SIZE = 1500;  //ICMP������󳤶�
const DWORD DEF_ICMP_TIMEOUT = 3000;  //����Ӧ��ʱʱ��
const int DEF_MAX_HOP = 16;    //�����������16


// ����ԭʼ�׽���
SOCKET sockRaw;
// ���Ŀ�Ķ�socket��ַ
sockaddr_in destSockAddr;

USHORT checksum(USHORT* pBuf, int iSize);//����У���

BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT);//����ICMP���ݰ�

u_long resolveIPAddress(char* ipAddress);//����IP��ַ���õ�32λ

void initializeSocket(u_long DestIP);//��ʼ���׽���

void Traceroute();//׷��·��



//����У��ͺ���
USHORT checksum(USHORT* pBuf, int iSize)
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT); //ÿ��iSize��2
	}
	if (iSize)//���iSizeΪ������Ϊ�������ֽڣ�����ĩβ����һ���ֽڣ�ʹ֮��ż�����ֽ�
	{
		cksum += *(UCHAR*)pBuf; 
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);//��16λ�͵�16λ���
	cksum += (cksum >> 16);//�õ����յ�16λ��
	return (USHORT)(~cksum);//���ȡ��
}

//��ICMP���ݰ����н���
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE  ICMP_TIMEOUT)
{
	//������ݱ���С�ĺϷ���
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;    //IP���ݱ�ͷ�ĳ�������4BΪ��λ

	//�����ݰ���С < IP���ݱ�ͷ + ICMP���ݱ�ͷ�������ݱ���С���Ϸ�
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
		return FALSE;

	//����ICMP���ݱ���������ȡID�ֶκ�seq�ֶ�
	ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf + iIpHdrLen);//ICMP���ݱ�ͷ = ���յ��Ļ������� + IP���ݱ�ͷ
	USHORT usID, usSquNo;

	if (pIcmpHdr->type == ICMP_ECHO_REPLY)    //ICMP���ͻش���
	{
		usID = pIcmpHdr->id;        //ICMP����ID
		usSquNo = pIcmpHdr->seq;    //ICMP����seq
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)//ICMPʱ�䳬������
	{
		char* pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER); //�غ��е�IPͷ
		int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4; //�غ��е�IPͷ��
		ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr + iInnerIPHdrLen);//�غ��е�ICMPͷ

		usID = pInnerIcmpHdr->id;        //ICMP����ID
		usSquNo = pInnerIcmpHdr->seq;    //ICMP����seq
	}
	else
	{
		return false;
	}

	//���ID�����к���ȷ���յ��ڴ����ݱ�
	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo)
	{
		return false;
	}
	//��¼IP��ַ����������ʱ��
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime;

	//������ȷ�յ���ICMP���ݱ�
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
	{
		//�����������ʱ����Ϣ
		if (DecodeResult.dwRoundTripTime)
			cout << "      " << DecodeResult.dwRoundTripTime << "ms" << flush;
		else
			cout << "      " << "<1ms" << flush;
	}
	return true;
}

u_long resolveIPAddress(char* ipAddress) {
	//�õ�IP��ַ
	u_long DestIP = inet_addr(ipAddress);//ת��Ϊ32λ��������
	//ת�����ɹ�ʱ����������
	if (DestIP == INADDR_NONE) 
	{
		hostent* pHostent = gethostbyname(ipAddress);//��ȡ������Ϣ
		if (pHostent) {
			DestIP = (*(in_addr*)pHostent->h_addr).s_addr;//��ȡĿ��IP��ַ
		}
		else {
			cout << "Invalid IP address or Domain Name!" << endl;
			WSACleanup();//�ͷ���Դ
			exit(1);
		}
	}
	return DestIP;
}

void initializeSocket(u_long DestIP) {
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in));//���destSockAddr�ṹ��������
	destSockAddr.sin_family = AF_INET;//���ð汾ΪIPV4
	destSockAddr.sin_addr.s_addr = DestIP;//Ŀ��IP��ַ��ֵ

	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);//�����׽��֣�ʹ��IPV4��ַ������ԭʼ���ݣ�ICMPЭ��
	if (sockRaw == INVALID_SOCKET) {
		cout << "Failed to create raw socket." << endl;
		WSACleanup();
		exit(2);
	}

	//��ʱʱ��
	int timeout = 3000;

	// ���ý��ճ�ʱʱ��
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	// ���÷��ͳ�ʱʱ��
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

	return;
}

void Traceroute() {
	//���ICMP������ÿ�η���ʱ������ֶ�
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];   //���巢�ͻ�����  ����Ϊͷ��+����
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));                  //��ʼ�����ͻ�����Ϊ0
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                       //������ջ�����
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));				  //��ʼ�����ջ�����

	ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST;						  //����ICMP����Ϊ��������
	pIcmpHeader->code = 0;                                        //���ô����ֶ�Ϊ0
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();			  //ID�ֶ�Ϊ��ǰ���̺ţ�ʹ�������Ӧ����ƥ��
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 0, DEF_ICMP_DATA_SIZE);//��ʼ�������ֶ�

	USHORT usSeqNo = 0;            //ICMP�������к�
	int iTTL = 1;                  //TTL��ʼֵΪ1
	BOOL bReachDestHost = FALSE;   //����Ŀ�ı�־
	int iMaxHot = DEF_MAX_HOP;     //ttl�������Ϊ16
	DECODE_RESULT DecodeResult;    

	while (!bReachDestHost && iMaxHot--)//δ����Ŀ����δ���������
	{
		//����IP��ͷ��TTL�ֶ�
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		cout << iTTL << flush;    

		//���ICMP������ÿ�η��ͱ仯���ֶ�
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;                   //У�����Ϊ0
		((ICMP_HEADER*)IcmpSendBuf)->seq = usSeqNo++;             //������кţ�ÿ�μ�1
		((ICMP_HEADER*)IcmpSendBuf)->cksum =
			checksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE); //����У���

		//��¼���кź͵�ǰʱ��
		DecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;				//��ǰ���
		DecodeResult.dwRoundTripTime = GetTickCount();                          //��ȡ��ǰʱ���

		//��Ŀ�ĵ�ַ���ͻ���������
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));

		//����ICMP����Ĳ����н�������
		sockaddr_in dst;           //�Զ�socket��ַ
		int iFromLen = sizeof(dst);//��ַ�ṹ��С
		int iReadDataLen;           //�������ݳ���
		while (1)
		{
			//��������
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&dst, &iFromLen);
			if (iReadDataLen != SOCKET_ERROR)
			{
				//�����ݰ����н���
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
				{
					//����Ŀ�ĵأ��˳�ѭ��
					if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						//��־��Ϊtrue
						bReachDestHost = true; 
					//���IP��ַ
					cout << '\t' << inet_ntoa(DecodeResult.dwIPaddr) << endl;
					break;
				}
			}
			else if (WSAGetLastError() == WSAETIMEDOUT)    //socket��ʱʧ��
			{
				cout << "         *" << '\t' << "Request timed out." << endl;
				break;
			}
			else
			{
				break;
			}
		}
		iTTL++;    //����TTLֵ�������´���̽
	}
}

int main()
{
	//��ʼ��Windows sockets���绷��
	WSADATA soc;
	WSAStartup(MAKEWORD(2, 2), &soc);
	//�洢IP��ַ������
	char IpAddress[128];
	cout << "Please Input an IP address or Domain Name��";
	cin >> IpAddress;
	//����IP��ַ���������γ�32λ��������
	u_long DestIP = resolveIPAddress(IpAddress);
	cout << "Tracing route to " << IpAddress << " with a maximum of 16 hops.\n" << endl;
	//����Ŀ��IP��ַ�����׽���
	initializeSocket(DestIP);
	//ִ��·��׷��
	Traceroute();
	return 0;
}