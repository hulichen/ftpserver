#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"

//会话结构
typedef struct session
{
	//控制连接
  uid_t uid;
  int ctrl_fd;  //客户端和服务端之间通信创建的套接字
	
  char cmdline[MAX_COMMOND_LINE_SIZE];  //命令行接收发来的命令
  char cmd[MAX_CMD_SIZE];
  char arg[MAX_ARG_SIZE];

	//数据连接
	struct sockaddr_in *port_addr;  //端口地址结构
	int  data_fd;   //数据连接用的套接字
	int   pasv_listen_fd;  //被动链接套接字
	int    data_process;  //判断是否处于数据连接状态，用于数据连接空闲断开中

	//ftp协议状态
	char* rnfr_name;  //保存更改文件时文件的原始名字
	int is_ascii;
	unsigned long long restart_pos; //断点续传位置
	unsigned int  max_clients;  //最大连接数
	unsigned int  max_per_ip;//每IP最大连接数
	
	//父子进程通道
	int parent_fd;
	int child_fd;

	//限速
	unsigned long long transfer_start_sec; //传输起始时间-->秒
	unsigned long long transfer_start_usec; //传输起始时间-->微秒

}session_t;

void begin_session(session_t *sess);

#endif /* _SESSION_H_ */
