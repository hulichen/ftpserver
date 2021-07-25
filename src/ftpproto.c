#include"ftpproto.h"
#include "session.h"
#include "str.h"
#include "ftpcodes.h"


static void ftp_reply(session_t *sess, unsigned int code, const char *text);//回复的内容text放到buffer里加上\r\n

static void do_user(session_t*sess);  //处理用户uid
static void do_pass(session_t *sess);  //处理用户密码
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_pwd(session_t *sess);
static void do_type(session_t *sess);
static void do_port(session_t *sess);
static void do_list(session_t *sess);


//命令映射
typedef struct ftpcmd
{
	const char *cmd; // 命令
	void(*cmd_handler)(session_t *sess); //命令处理方法
}ftpcmd_t;

ftpcmd_t ctrl_cmds[] = 
{
	{"USER", do_user},
	{"PASS", do_pass},
	{"SYST", do_syst},
	{"FEAT", do_feat},
	{"PWD" , do_pwd },
	{"TYPE", do_type},
	{"PORT", do_port},
	{"LIST", do_list}

};


//ftp 服务进程
void handle_child(session_t *sess)
{
	//send(sess->ctrl_fd, "220 (miniftp 1.0.0)\r\n", strlen("220 (miniftp 1.0.0)\r\n"), 0);
	ftp_reply(sess,FTP_GREET,"miniftp 1.0.0");
	while(1)
	{
		//不停的等待客户端的命令并做出处理
		memset(sess->cmdline,0,MAX_COMMOND_LINE_SIZE);  
		memset(sess->cmd,0,MAX_CMD_SIZE);  
		memset(sess->arg,0,MAX_ARG_SIZE);  
    int ret =recv(sess->ctrl_fd,sess->cmdline,MAX_COMMOND_LINE_SIZE,0);
    if(ret<0)
      ERR_EXIT("recv errror");
    if(ret==0) //客户端关闭，接受数据大小为0
      exit(EXIT_SUCCESS);
		//printf("cmdline=%s\n",sess->cmdline);   //USER hlc

    str_trim_crlf(sess->cmdline);
    str_split(sess->cmdline, sess->cmd, sess->arg, ' ');

    //printf("cmdline=%s\n",sess->cmdline);
    //printf("cmd=%s\n",sess->cmd);
    //printf("arg=%s\n",sess->arg);

    int table_size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
	int i;
	for(i=0; i<table_size; ++i)   
	{
		if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0)  //表中找这个方法
		{
			if(ctrl_cmds[i].cmd_handler)   //处理方法存在则处理。
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




static void ftp_reply(session_t *sess, unsigned int code, const char *text)   
	//回复的内容text放到buffer里加上\r\n
{
	char buffer[MAX_BUFFER_SIZE] = {0};
	sprintf(buffer, "%d %s\r\n", code, text);
	send(sess->ctrl_fd, buffer, strlen(buffer), 0);
}

static void do_user(session_t *sess)  
{  //man  getpwnam命令查看结构体信息   
	//getpwnam()获取用户登录相关信息,返回一个指针，指向一个passwd结构体，其中包含用户名
	//密码,uid等信息。如果找不到匹配项或发生错误，则返回NULL。
	struct passwd *pwd = getpwnam(sess->arg);  //sess->arg 即为解析到的用户名
	if(pwd != NULL)     //用户名存在则保存用户ID即uid
		sess->uid = pwd->pw_uid;  
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password");//FTP_GIVEPWORD 331  Please specify the password
}

static void do_pass(session_t *sess)
{ //验证用户名和密码

    struct passwd *pwd = getpwuid(sess->uid);
   //getpwuid()用来逐一搜索参数uid 指定的用户识别码, 找到时便将该用户的数据以结构passwd结构返回
   //如果返回NULL 则表示已无数据, 或者有错误发生
	if(pwd == NULL)
	{
		//用户名不存在 回复 FTP_LOGINERR  530
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");  
		return;
	}

//getspnam()  获取
	struct spwd *spd = getspnam(pwd->pw_name);
	if(spd == NULL)
	{
		//用户不存在  
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	char *encrypted_pw = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encrypted_pw, spd->sp_pwdp) != 0)
	{
		//密码错误
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//更改ftp服务进程信息  
	setegid(pwd->pw_gid);
	seteuid(pwd->pw_uid);
	chdir(pwd->pw_dir);  //更改用户的家目录

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t *sess)//SYST   获取系统信息   回复：215 LINUX Type: L8
{
   ftp_reply(sess, FTP_SYSTOK, "LINUX Type: L8");
}

static void do_feat(session_t *sess)
{  //FEAT   服务器特性，回复服务器支持什么功能
	send(sess->ctrl_fd,"211-Features\r\n",strlen("211-Features\r\n"),0);
	send(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
	send(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
	send(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
	send(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
	send(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0);
	send(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
	send(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
	send(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
	send(sess->ctrl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
}

static void do_pwd(session_t *sess)
{  //PWD 目录   响应： 257   ”目录” 
	char cwd[MAX_CWD_SIZE]={0};
	getcwd(cwd,MAX_CWD_SIZE);  //获取当前工作目录
	char text[MAX_CWD_SIZE]={0};
	sprintf(text,"\"%s\"",cwd);
	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_type(session_t *sess)
{   //TYPE  文件传输类型  二进程或ASCII码
	if(strcmp(sess->arg,"a")==0||strcmp(sess->arg,"A")==0){
		sess->is_ascii=1;
		ftp_reply(sess,FTP_TYPEOK,"Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg,"i")==0||strcmp(sess->arg,"I")==0){
		sess->is_ascii=0;
		ftp_reply(sess,FTP_TYPEOK,"Switching to Binary mode.");
	}
}

static void do_port(session_t *sess)  
{//数据连接协商  主动or被动    先主动，主动连不上在被动 
//主动-->服务器主动连接客户端，需要先知道客户端地址   
//PORT告诉服务器主动连接    PORT 192,168,124,23,239,24  需解析其ip和端口号


	
	
}

static void do_list(session_t *sess){ //显示列表
	//1 创建数据连接

	//2 回复150

	//3 传输列表

	//4 回复226
}