#include"ftpproto.h"
#include"session.h"
#include"str.h"
#include"ftpcodes.h"
#include"sysutil.h"
#include"privsock.h"
#include"tunable.h"


extern  session_t* p_sess;  //引入全局会话结构

void ftp_reply(session_t *sess, unsigned int code, const char *text)
{
	char buffer[MAX_BUFFER_SIZE] = {0};
	sprintf(buffer, "%d %s\r\n", code, text);
	send(sess->ctrl_fd, buffer, strlen(buffer), 0);
}

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_pwd(session_t *sess);
static void do_type(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_list(session_t *sess);
static void do_cwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_size(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_rest(session_t* sess);

//命令映射
typedef struct ftpcmd
{
	const char *cmd; // 命令
	void(*cmd_handler)(session_t *sess); //命令处理方法
}ftpcmd_t;

ftpcmd_t ctrl_cmds[] = 
{
	{"USER", do_user},//保存用户信息
	{"PASS", do_pass},//鉴权登录
	{"SYST", do_syst},//打印系统信息
	{"FEAT", do_feat},//打印系统支持的特性
	{"PWD" , do_pwd },//打印当前工作目录
	{"TYPE", do_type},//协商数据传输模式，  A或a 则 ASCII模式
	{"PORT", do_port}, //主动模式
	{"PASV", do_pasv},//被动模式
	{"LIST", do_list},//列出目录详细清单
	{"CWD" , do_cwd },  //改变工作目录
	{"MKD" , do_mkd },  //创建目录
	{"RMD" , do_rmd },  //删除文件目录
	{"DELE", do_dele}, //删除普通文件
	{"SIZE", do_size},  //返回文件大小

	{"RNFR", do_rnfr}, // 重命名
	{"RNTO", do_rnto},  // 重命名到哪里

	{"RETR", do_retr},  //从服务器下载 
	{"STOR", do_stor},   //上传

	{"REST", do_rest} //断点续传
};

/////////////////////////////////////////////////////////////////////////////////////////
//空闲断开

// 1 控制连接空闲断开
void handle_ctrl_timeout(int sig) //处理控制连接超时函数
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);//关闭控制连接读端
	//421 Timeout.
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");

	shutdown(p_sess->ctrl_fd, SHUT_WR);//关闭控制连接写端
	exit(EXIT_SUCCESS);
}

void start_cmdio_alarm() //开始安装闹钟信号
{
	if (tunable_idle_session_timeout > 0)
	{
		signal(SIGALRM, handle_ctrl_timeout);//安装闹钟信号
		alarm(tunable_idle_session_timeout); //启动闹钟
	}
}

// 2 数据连接空闲断开
void start_data_alarm();
void handle_data_timeout(int sig)//处理数据连接超时函数
{
	if (!p_sess->data_process) //没有处于数据连接状态
	{		//空闲断开
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout, Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	p_sess->data_process = 0;

	//重新启动数据连接的空闲断开
	start_data_alarm();
}
void start_data_alarm()
{
	if (tunable_data_connection_timeout > 0)
	{
		signal(SIGALRM, handle_data_timeout);
		alarm(tunable_data_connection_timeout);
	}
}




//ftp 服务进程
void handle_child(session_t *sess)
{
	//send(sess->ctrl_fd, "220 (miniftp 1.0.1)\r\n", strlen("220 (miniftp 1.0.1)\r\n"), 0);
	ftp_reply(sess, FTP_GREET, "(miniftp 1.0.1)");
	while(1)
	{
		//不停的等待客户端的命令并做出处理
		memset(sess->cmdline, 0, MAX_COMMOND_LINE_SIZE);
		memset(sess->cmd, 0, MAX_CMD_SIZE);
		memset(sess->arg, 0, MAX_ARG_SIZE);

		//开启 控制连接空闲断开
		start_cmdio_alarm();

		int ret = recv(sess->ctrl_fd, sess->cmdline, MAX_COMMOND_LINE_SIZE, 0);
		if(ret < 0)
			ERR_EXIT("recv");
		if(ret == 0)
			exit(EXIT_SUCCESS);
		

		str_trim_crlf(sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');

		//printf("cmdline = %s\n", sess->cmdline);
		//printf("cmd = %s\n", sess->cmd);
		//printf("arg = %s\n", sess->arg);

		//命令映射
		int table_size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		int i;
		for(i=0; i<table_size; ++i)
		{
			if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0)
			{
				if(ctrl_cmds[i].cmd_handler)
					ctrl_cmds[i].cmd_handler(sess);
				else
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				break;
			}
		}
		if(i >= table_size)
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
	}

}

static void do_user(session_t *sess) 
{
	struct passwd *pwd = getpwnam(sess->arg);
	if(pwd != NULL)
		sess->uid = pwd->pw_uid; //保存用户ID即uid
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password");
}

static void do_pass(session_t *sess) 	//实现鉴权登录
{
	struct passwd *pwd = getpwuid(sess->uid); //根据uid获取的用户信息
	if(pwd == NULL)
	{
		//用户不存在    530，FTP_LOGINERR
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	struct spwd *spd = getspnam(pwd->pw_name);  //根据用户名获取用户的影子密码
	if(spd == NULL)//用户存在，但是密码不存在
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//crypt（）函数用于获取影子密码。crypt（）为库函数，需要连接库-lcrypt
	//参数sess->arg为明文密码，spd->sp_pwdp相当于影子密码
	char *encrypted_pw = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encrypted_pw, spd->sp_pwdp) != 0) //密码错误
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//更改ftp服务进程
	setegid(pwd->pw_gid); //修改用户gid和uid
	seteuid(pwd->pw_uid);  
	chdir(pwd->pw_dir);   //修改工作目录

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "Linux Type: L8");
}

static void do_feat(session_t *sess) //服务器支持的功能
{
	send(sess->ctrl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
	send(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
	send(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
	send(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
	send(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
	send(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0); //断点续传
	send(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
	send(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
	send(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
	send(sess->ctrl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
}

static void do_pwd(session_t *sess)
{
	char cwd[MAX_CWD_SIZE] = {0};
	getcwd(cwd, MAX_CWD_SIZE);
	char text[MAX_BUFFER_SIZE] = {0};
	sprintf(text, "\"%s\"", cwd);
	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_type(session_t *sess)
{
	if(strcmp(sess->arg,"A")==0 || strcmp(sess->arg,"a")==0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg,"I")==0 || strcmp(sess->arg,"i")==0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		//500 Unrecognised TYPE command.
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}

/////////////////////////////////////////////////////////////////////
//数据协商

static void do_port(session_t *sess)  //主动连接（服务器主动链接客户端）
//客户端向服务器发送数据连接的IP和PORT，服务器保存下来，方便下一步建立连接
{
	//eg: PORT 192,168,86,3,161,206  其中161,206为port按单字节无符号整型显示出来，需要进一步解析出来
	unsigned int v[6] = {0};
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr));

	//填充协议家族
	sess->port_addr->sin_family = AF_INET;

	//填充port
	unsigned char *p = (unsigned char *)&(sess->port_addr->sin_port);
	p[0] = v[4];
	p[1] = v[5];

	//填充ip
	p = (unsigned char *)&(sess->port_addr->sin_addr);
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];

	// 200 PORT command successful. Consider using PASV.
	ftp_reply(sess, FTP_PROTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess) //被动连接   只需accept然后保存被动链接套接字，响应227
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN); //请求被动链接套接字
	char ip[16] = {0};

	//接收ip
	int len = priv_sock_get_int(sess->child_fd);
	priv_sock_recv_buf(sess->child_fd, ip, len);
	//接收port
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);

	//////////////////////////////////////////////////////////

	unsigned v[4] = {0};
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[MAX_BUFFER_SIZE] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
		v[0],v[1],v[2],v[3], port>>8, port&0x00ff);

	//227 Entering Passive Mode (192,168,232,10,248,159).
	ftp_reply(sess, FTP_PASVOK, text);
}

////////////////////////////////////////////////////////////////////////
//数据连接
int port_active(session_t* sess);
int pasv_active(session_t *sess);
int port_active(session_t *sess)
{
	if(sess->port_addr != NULL)//sess->port_addr初始化为NULl，不为NULL则执行过do_port()
	{
		if(pasv_active(sess))  //不能同时激活两种模式
			ERR_EXIT("both port an pasv are active");
		return 1;  //表示仅主动模式被激活
	}
	return 0;
}

int pasv_active(session_t *sess) //判断PASV是否激活
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd); 
	if(active != -1)
	{
		if(port_active(sess))//不能同时激活两种模式
			ERR_EXIT("both port an pasv are active");
		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)//获取主动模式的套接字
{
	//ftp服务进程向父（nobody）进程发送命令，请求主动连接的套接字
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	
	//发送ip
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd, strlen(ip));
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	//发送port
	unsigned short port = ntohs(sess->port_addr->sin_port);
	priv_sock_send_int(sess->child_fd, (int)port);

	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)  //请求失败
		return -1;

	sess->data_fd = priv_sock_recv_fd(sess->child_fd);//接收数据连接套接字
	return 0;
}

int get_pasv_fd(session_t *sess)//获取被动模式的套接字
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
		return -1;

	sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	return 0;
}

static int get_transfer_fd(session_t *sess) 
//建立数据连接（do_list）之前判断有没有协商主动模式或者被动模式
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		//425 Use PORT or PASV first.
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return -1;
	}
	if(port_active(sess))
	{
		if(get_port_fd(sess) != 0)  //获取主动连接套接字
			return -1;
	}
	if(pasv_active(sess))
	{
		if(get_pasv_fd(sess) != 0)
			return -1;
	}

	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	//开启数据连接空闲断开
	start_data_alarm();

	return 0;
}

//drwxrwxr-x    2 1000     1000          114 Dec 05  2020 93
void list_common(session_t *sess)
{
	DIR *dir = opendir(".");
	if(dir == NULL)
		ERR_EXIT("opendir");

	struct stat  sbuf;
	char   buf[MAX_BUFFER_SIZE] = {0};
	unsigned int offset = 0;

	struct dirent *dt;
	while((dt = readdir(dir)))  //循环获取每一个文件信息
	//	                                 UID      GID     文件大小
	//目录/列表中查看eg:drwxrwxr-x    4 1000     1000           37 Aug 28  2021 projects
	{
		if(stat(dt->d_name,&sbuf)<0)  //stat()根据文件名获取文件信息sbuf
			ERR_EXIT("stat");

		if(dt->d_name[0] == '.')
			continue;
		
		const char *perms = statbuf_get_perms(&sbuf);  //获取文件权权限信息 
	
		//将数据格式化到buf中
		offset = sprintf(buf, "%s", perms);

		offset += sprintf(buf+offset, "%3d %-8d %-8d %8lld ", 
			(int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (unsigned long long)sbuf.st_size);

		const char *pdate = statbuf_get_date(&sbuf);  //获取最后修改时间
		offset += sprintf(buf+offset, "%s ", pdate);  //加上时间

		sprintf(buf+offset, "%s\r\n", dt->d_name); //加上文件名

		send(sess->data_fd, buf, strlen(buf), 0);//通过数据连接套接字发送
	}

	closedir(dir);
}

static void do_list(session_t *sess)
{
	//1 创建数据连接
	if(get_transfer_fd(sess) != 0)
		return;

	//2 150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3 传输列表
	list_common(sess);

	//4 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");



	//关闭数据连接
	close(sess->data_fd);
	sess->data_fd = -1;

	//重新开启控制连接断开
	start_cmdio_alarm();
}

static void do_cwd(session_t *sess)//改变工作目录
{
	if(chdir(sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
	else
		ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_mkd(session_t *sess)  //mkdir  创建目录
{
	//MKD  /home/hlc/projects/111
	if(mkdir(sess->arg, 0755) < 0)    //mkdir(路径，权限）
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed.");
	else
	{
		char text[MAX_BUFFER_SIZE] = {0};
		sprintf(text, "\"%s\" created", sess->arg);  
		ftp_reply(sess, FTP_MKDIROK, text);  //257 "/home/hlc/projects/111" created
	}
}

static void do_rmd(session_t *sess) // rmdir  删除目录
{
	//RMD /home/hlc/projects/111
	if(rmdir(sess->arg) < 0)
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
	else                 //250 Remove directory operation successful.
		ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful."); 

}

static void do_dele(session_t *sess)  //删除普通文件
{  //DELE  /home/hlc/projects/test.c
	if(unlink(sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
	else
		ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_size(session_t *sess)  //求文件大小
{ //  SIZE  [filename]
  
	struct stat sbuf;
	if(stat(sess->arg, &sbuf) < 0)
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");//550 Could not get file size
	else
	{
		char text[MAX_BUFFER_SIZE] = {0};
		sprintf(text, "%d", (int)sbuf.st_size);
		ftp_reply(sess, FTP_SIZEOK, text);  //213  [size]
	}
}

static void do_rnfr(session_t *sess)  // 重命名
//文件重命名RNFR  [path+old_filename] ---> RNTO  [path+new_filename]
{
	//保存原始文件名字到sess->rnfr_name
	unsigned int len = strlen(sess->arg);
	sess->rnfr_name = (char*)malloc(len + 1);
	memset(sess->rnfr_name, 0, len+1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
static void do_rnto(session_t *sess) //重命名为...
{
	if(sess->rnfr_name == NULL)
	{  //RNTO之前需要先响应RNFR
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}

	//rename(old_filename,new_filename)
	if(rename(sess->rnfr_name, sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
	}
	else
	{
		free(sess->rnfr_name);
		sess->rnfr_name = NULL;
		ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
	}
}


//////////////////////////////////////////////////////////////////////////////////
//同时对上传和下载限速
void limit_rate(session_t* sess, unsigned long bytes_transfer, int is_upload)
{                      //is_upload ：1表示上传，0表示下载
	//登记结束时间
	unsigned long long cur_sec = get_time_sec();
	unsigned long long cur_usec = get_time_usec();

	double pass_time = (double)(cur_sec - sess->transfer_start_sec); //计算传输经过的秒
	pass_time += ((double)(cur_usec - sess->transfer_start_usec) / 1000000); //加上传输经过的微秒

	//当前的传输速度
	unsigned long cur_rate = (unsigned long)(bytes_transfer / pass_time);
	double rate_ratio; //速率

	if (is_upload) 		//上传
	{
		if (tunable_upload_max_rate == 0 || cur_rate <= tunable_upload_max_rate)
		{			//不限速
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_upload_max_rate;
	}
	else  		//下载
	{
		if (tunable_download_max_rate == 0 || cur_rate <= tunable_download_max_rate)
		{			//不限速
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_download_max_rate;
	}

	double sleep_time = (rate_ratio - 1) * pass_time;//休眠时间
	nano_sleep(sleep_time);	//休眠

	//重新登记开始时间
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}





static void do_retr(session_t *sess)  //下载
{
	if(get_transfer_fd(sess) != 0) //先建立数据连接
		return;

	int fd;
	if((fd = open(sess->arg, O_RDONLY)) < 0) //打开文件
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	struct stat sbuf; 
	fstat(fd, &sbuf); //将上面打开的文件的信息放入sbuf中
	char buf[MAX_BUFFER_SIZE] = {0};
	if(sess->is_ascii)   //判断是ASCII传输还是二进制传输  
		//将回复内容先格式化到buf中
		sprintf(buf, "Opening ASCII mode data connection for %s (%ull bytes).", sess->arg, (unsigned long long)sbuf.st_size);
	else
		sprintf(buf, "Opening BINARY mode data connection for %s (%ull bytes).",sess->arg, (unsigned long long)sbuf.st_size);
	ftp_reply(sess, FTP_DATACONN, buf);	//回复150 创建数据链接成功

	//开始传输数据  文件切片传输
	unsigned long long  total_size = sbuf.st_size;

	//断点续载
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if (offset >= total_size) //已经传输结束 
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else
	{
		if (lseek(fd, offset, SEEK_SET) < 0) //调整偏移量失败
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		}
		else //调整偏移量成功
		{
			int read_count = 0; //每次读取的字节数
			total_size -= offset;
			
			//登记开始传输时间
			sess->transfer_start_sec = get_time_sec(); //秒
			sess->transfer_start_usec = get_time_usec();//微秒
			
			while (1)
			{
				memset(buf, 0, MAX_BUFFER_SIZE);
				read_count = total_size > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : total_size;
				int ret = read(fd, buf, read_count);
				if (ret == -1 || ret != read_count)
				{  //读取数据失败
					ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
					break;
				}
				if (ret == 0)
				{                  //   226     传输完毕
					ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
					break;
				}

				//标记是处于数据连接状态
				sess->data_process = 1;

				//根据读出来的数据 判断有无超速，超速则限速（睡眠）
				//限速 --函数里会登记结束时间
				limit_rate(sess, ret, 0);

				send(sess->data_fd, buf, ret, 0); //从服务器发送数据到客户端
				total_size -= read_count;
			}
		}	
	}

	close(fd);
	if(sess->data_fd != -1)
	{
		close(sess->data_fd);
		sess->data_fd = -1;
	}

	//重新开启控制连接断开
	start_cmdio_alarm();
}

static void do_stor(session_t *sess)  //上传
{
	if(get_transfer_fd(sess) != 0)
		return;

	int fd;
	if((fd = open(sess->arg, O_CREAT|O_WRONLY, 0755)) < 0)  //创建文件（只写）
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//回复150
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//断点续传
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if (lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	//登记时间
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();

	//传输数据
	char buf[MAX_BUFFER_SIZE] = {0};
	while(1)
	{
		memset(buf, 0, MAX_BUFFER_SIZE);
		int ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
		if(ret == -1)
		{
			ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
			break;
		}
		if(ret == 0)
		{
			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
			break;
		}

		//标记是处于数据连接状态
		sess->data_process = 1;

		//限速
		limit_rate(sess, ret, 1); //1表示上传

		write(fd, buf, ret);
	}

	close(fd);
	if(sess->data_fd != -1)
	{
		close(sess->data_fd);
		sess->data_fd = -1;
	}

	//重新开启控制连接断开
	start_cmdio_alarm();
}

//断点续传或续载 命令REST [pos]   需要记录下pos信息，然后上传或下载时偏移响应位置读写
static void do_rest(session_t* sess) 
{
	sess->restart_pos = (unsigned long long)atoll(sess->arg);  //将str转为unsigned long long

	char text[MAX_BUFFER_SIZE] = { 0 };
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	//350 Restart position accepted (restart_pos的大小).
	ftp_reply(sess, FTP_RESTOK, text);
}