/*系统工具模块*/
#ifndef _SYSUTIL_H_
#define _SYSUTIL_H_

#include"common.h"

int tcp_server(const char *host, unsigned short port); 
int tcp_client(int port);  //客户端创建套接字 绑定20端口

char* statbuf_get_perms(struct stat *sbuf);//获取权限信息
char* statbuf_get_date(struct stat *sbuf);

void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);

unsigned long long get_time_sec();//获取当前点的秒数
unsigned long long get_time_usec();//获取当前点的微秒数
void nano_sleep(double sleep_time);

#endif /* _SYSUTIL_H_ */