/*ϵͳ����ģ��*/
#ifndef _SYSUTIL_H_
#define _SYSUTIL_H_

#include"common.h"

int tcp_server(const char *host, unsigned short port); 
int tcp_client(int port);  //�ͻ��˴����׽��� ��20�˿�

char* statbuf_get_perms(struct stat *sbuf);//��ȡȨ����Ϣ
char* statbuf_get_date(struct stat *sbuf);

void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);

unsigned long long get_time_sec();//��ȡ��ǰ�������
unsigned long long get_time_usec();//��ȡ��ǰ���΢����
void nano_sleep(double sleep_time);

#endif /* _SYSUTIL_H_ */