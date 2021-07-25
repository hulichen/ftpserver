#include"ftpproto.h"
#include "session.h"
#include "str.h"
#include "ftpcodes.h"


static void ftp_reply(session_t *sess, unsigned int code, const char *text);//�ظ�������text�ŵ�buffer�����\r\n

static void do_user(session_t*sess);  //�����û�uid
static void do_pass(session_t *sess);  //�����û�����
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_pwd(session_t *sess);
static void do_type(session_t *sess);
static void do_port(session_t *sess);
static void do_list(session_t *sess);


//����ӳ��
typedef struct ftpcmd
{
	const char *cmd; // ����
	void(*cmd_handler)(session_t *sess); //�������
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


//ftp �������
void handle_child(session_t *sess)
{
	//send(sess->ctrl_fd, "220 (miniftp 1.0.0)\r\n", strlen("220 (miniftp 1.0.0)\r\n"), 0);
	ftp_reply(sess,FTP_GREET,"miniftp 1.0.0");
	while(1)
	{
		//��ͣ�ĵȴ��ͻ��˵������������
		memset(sess->cmdline,0,MAX_COMMOND_LINE_SIZE);  
		memset(sess->cmd,0,MAX_CMD_SIZE);  
		memset(sess->arg,0,MAX_ARG_SIZE);  
    int ret =recv(sess->ctrl_fd,sess->cmdline,MAX_COMMOND_LINE_SIZE,0);
    if(ret<0)
      ERR_EXIT("recv errror");
    if(ret==0) //�ͻ��˹رգ��������ݴ�СΪ0
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
		if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0)  //�������������
		{
			if(ctrl_cmds[i].cmd_handler)   //��������������
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
	//�ظ�������text�ŵ�buffer�����\r\n
{
	char buffer[MAX_BUFFER_SIZE] = {0};
	sprintf(buffer, "%d %s\r\n", code, text);
	send(sess->ctrl_fd, buffer, strlen(buffer), 0);
}

static void do_user(session_t *sess)  
{  //man  getpwnam����鿴�ṹ����Ϣ   
	//getpwnam()��ȡ�û���¼�����Ϣ,����һ��ָ�룬ָ��һ��passwd�ṹ�壬���а����û���
	//����,uid����Ϣ������Ҳ���ƥ������������򷵻�NULL��
	struct passwd *pwd = getpwnam(sess->arg);  //sess->arg ��Ϊ���������û���
	if(pwd != NULL)     //�û��������򱣴��û�ID��uid
		sess->uid = pwd->pw_uid;  
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password");//FTP_GIVEPWORD 331  Please specify the password
}

static void do_pass(session_t *sess)
{ //��֤�û���������

    struct passwd *pwd = getpwuid(sess->uid);
   //getpwuid()������һ��������uid ָ�����û�ʶ����, �ҵ�ʱ�㽫���û��������Խṹpasswd�ṹ����
   //�������NULL ���ʾ��������, �����д�����
	if(pwd == NULL)
	{
		//�û��������� �ظ� FTP_LOGINERR  530
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");  
		return;
	}

//getspnam()  ��ȡ
	struct spwd *spd = getspnam(pwd->pw_name);
	if(spd == NULL)
	{
		//�û�������  
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	char *encrypted_pw = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encrypted_pw, spd->sp_pwdp) != 0)
	{
		//�������
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//����ftp���������Ϣ  
	setegid(pwd->pw_gid);
	seteuid(pwd->pw_uid);
	chdir(pwd->pw_dir);  //�����û��ļ�Ŀ¼

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t *sess)//SYST   ��ȡϵͳ��Ϣ   �ظ���215 LINUX Type: L8
{
   ftp_reply(sess, FTP_SYSTOK, "LINUX Type: L8");
}

static void do_feat(session_t *sess)
{  //FEAT   ���������ԣ��ظ�������֧��ʲô����
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
{  //PWD Ŀ¼   ��Ӧ�� 257   ��Ŀ¼�� 
	char cwd[MAX_CWD_SIZE]={0};
	getcwd(cwd,MAX_CWD_SIZE);  //��ȡ��ǰ����Ŀ¼
	char text[MAX_CWD_SIZE]={0};
	sprintf(text,"\"%s\"",cwd);
	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_type(session_t *sess)
{   //TYPE  �ļ���������  �����̻�ASCII��
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
{//��������Э��  ����or����    �������������������ڱ��� 
//����-->�������������ӿͻ��ˣ���Ҫ��֪���ͻ��˵�ַ   
//PORT���߷�������������    PORT 192,168,124,23,239,24  �������ip�Ͷ˿ں�


	
	
}

static void do_list(session_t *sess){ //��ʾ�б�
	//1 ������������

	//2 �ظ�150

	//3 �����б�

	//4 �ظ�226
}