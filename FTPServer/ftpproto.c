#include"ftpproto.h"
#include"session.h"
#include"str.h"
#include"ftpcodes.h"
#include"sysutil.h"
#include"privsock.h"
#include"tunable.h"


extern  session_t* p_sess;  //����ȫ�ֻỰ�ṹ

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

//����ӳ��
typedef struct ftpcmd
{
	const char *cmd; // ����
	void(*cmd_handler)(session_t *sess); //�������
}ftpcmd_t;

ftpcmd_t ctrl_cmds[] = 
{
	{"USER", do_user},//�����û���Ϣ
	{"PASS", do_pass},//��Ȩ��¼
	{"SYST", do_syst},//��ӡϵͳ��Ϣ
	{"FEAT", do_feat},//��ӡϵͳ֧�ֵ�����
	{"PWD" , do_pwd },//��ӡ��ǰ����Ŀ¼
	{"TYPE", do_type},//Э�����ݴ���ģʽ��  A��a �� ASCIIģʽ
	{"PORT", do_port}, //����ģʽ
	{"PASV", do_pasv},//����ģʽ
	{"LIST", do_list},//�г�Ŀ¼��ϸ�嵥
	{"CWD" , do_cwd },  //�ı乤��Ŀ¼
	{"MKD" , do_mkd },  //����Ŀ¼
	{"RMD" , do_rmd },  //ɾ���ļ�Ŀ¼
	{"DELE", do_dele}, //ɾ����ͨ�ļ�
	{"SIZE", do_size},  //�����ļ���С

	{"RNFR", do_rnfr}, // ������
	{"RNTO", do_rnto},  // ������������

	{"RETR", do_retr},  //�ӷ��������� 
	{"STOR", do_stor},   //�ϴ�

	{"REST", do_rest} //�ϵ�����
};

/////////////////////////////////////////////////////////////////////////////////////////
//���жϿ�

// 1 �������ӿ��жϿ�
void handle_ctrl_timeout(int sig) //����������ӳ�ʱ����
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);//�رտ������Ӷ���
	//421 Timeout.
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");

	shutdown(p_sess->ctrl_fd, SHUT_WR);//�رտ�������д��
	exit(EXIT_SUCCESS);
}

void start_cmdio_alarm() //��ʼ��װ�����ź�
{
	if (tunable_idle_session_timeout > 0)
	{
		signal(SIGALRM, handle_ctrl_timeout);//��װ�����ź�
		alarm(tunable_idle_session_timeout); //��������
	}
}

// 2 �������ӿ��жϿ�
void start_data_alarm();
void handle_data_timeout(int sig)//�����������ӳ�ʱ����
{
	if (!p_sess->data_process) //û�д�����������״̬
	{		//���жϿ�
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout, Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	p_sess->data_process = 0;

	//���������������ӵĿ��жϿ�
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




//ftp �������
void handle_child(session_t *sess)
{
	//send(sess->ctrl_fd, "220 (miniftp 1.0.1)\r\n", strlen("220 (miniftp 1.0.1)\r\n"), 0);
	ftp_reply(sess, FTP_GREET, "(miniftp 1.0.1)");
	while(1)
	{
		//��ͣ�ĵȴ��ͻ��˵������������
		memset(sess->cmdline, 0, MAX_COMMOND_LINE_SIZE);
		memset(sess->cmd, 0, MAX_CMD_SIZE);
		memset(sess->arg, 0, MAX_ARG_SIZE);

		//���� �������ӿ��жϿ�
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

		//����ӳ��
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
		sess->uid = pwd->pw_uid; //�����û�ID��uid
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password");
}

static void do_pass(session_t *sess) 	//ʵ�ּ�Ȩ��¼
{
	struct passwd *pwd = getpwuid(sess->uid); //����uid��ȡ���û���Ϣ
	if(pwd == NULL)
	{
		//�û�������    530��FTP_LOGINERR
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	struct spwd *spd = getspnam(pwd->pw_name);  //�����û�����ȡ�û���Ӱ������
	if(spd == NULL)//�û����ڣ��������벻����
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//crypt�����������ڻ�ȡӰ�����롣crypt����Ϊ�⺯������Ҫ���ӿ�-lcrypt
	//����sess->argΪ�������룬spd->sp_pwdp�൱��Ӱ������
	char *encrypted_pw = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encrypted_pw, spd->sp_pwdp) != 0) //�������
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//����ftp�������
	setegid(pwd->pw_gid); //�޸��û�gid��uid
	seteuid(pwd->pw_uid);  
	chdir(pwd->pw_dir);   //�޸Ĺ���Ŀ¼

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "Linux Type: L8");
}

static void do_feat(session_t *sess) //������֧�ֵĹ���
{
	send(sess->ctrl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
	send(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
	send(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
	send(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
	send(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
	send(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0); //�ϵ�����
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
//����Э��

static void do_port(session_t *sess)  //�������ӣ��������������ӿͻ��ˣ�
//�ͻ���������������������ӵ�IP��PORT������������������������һ����������
{
	//eg: PORT 192,168,86,3,161,206  ����161,206Ϊport�����ֽ��޷���������ʾ��������Ҫ��һ����������
	unsigned int v[6] = {0};
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);

	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr));

	//���Э�����
	sess->port_addr->sin_family = AF_INET;

	//���port
	unsigned char *p = (unsigned char *)&(sess->port_addr->sin_port);
	p[0] = v[4];
	p[1] = v[5];

	//���ip
	p = (unsigned char *)&(sess->port_addr->sin_addr);
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];

	// 200 PORT command successful. Consider using PASV.
	ftp_reply(sess, FTP_PROTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess) //��������   ֻ��acceptȻ�󱣴汻�������׽��֣���Ӧ227
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN); //���󱻶������׽���
	char ip[16] = {0};

	//����ip
	int len = priv_sock_get_int(sess->child_fd);
	priv_sock_recv_buf(sess->child_fd, ip, len);
	//����port
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
//��������
int port_active(session_t* sess);
int pasv_active(session_t *sess);
int port_active(session_t *sess)
{
	if(sess->port_addr != NULL)//sess->port_addr��ʼ��ΪNULl����ΪNULL��ִ�й�do_port()
	{
		if(pasv_active(sess))  //����ͬʱ��������ģʽ
			ERR_EXIT("both port an pasv are active");
		return 1;  //��ʾ������ģʽ������
	}
	return 0;
}

int pasv_active(session_t *sess) //�ж�PASV�Ƿ񼤻�
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd); 
	if(active != -1)
	{
		if(port_active(sess))//����ͬʱ��������ģʽ
			ERR_EXIT("both port an pasv are active");
		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)//��ȡ����ģʽ���׽���
{
	//ftp��������򸸣�nobody�����̷�����������������ӵ��׽���
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	
	//����ip
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd, strlen(ip));
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	//����port
	unsigned short port = ntohs(sess->port_addr->sin_port);
	priv_sock_send_int(sess->child_fd, (int)port);

	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)  //����ʧ��
		return -1;

	sess->data_fd = priv_sock_recv_fd(sess->child_fd);//�������������׽���
	return 0;
}

int get_pasv_fd(session_t *sess)//��ȡ����ģʽ���׽���
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
		return -1;

	sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	return 0;
}

static int get_transfer_fd(session_t *sess) 
//�����������ӣ�do_list��֮ǰ�ж���û��Э������ģʽ���߱���ģʽ
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		//425 Use PORT or PASV first.
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return -1;
	}
	if(port_active(sess))
	{
		if(get_port_fd(sess) != 0)  //��ȡ���������׽���
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

	//�����������ӿ��жϿ�
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
	while((dt = readdir(dir)))  //ѭ����ȡÿһ���ļ���Ϣ
	//	                                 UID      GID     �ļ���С
	//Ŀ¼/�б��в鿴eg:drwxrwxr-x    4 1000     1000           37 Aug 28  2021 projects
	{
		if(stat(dt->d_name,&sbuf)<0)  //stat()�����ļ�����ȡ�ļ���Ϣsbuf
			ERR_EXIT("stat");

		if(dt->d_name[0] == '.')
			continue;
		
		const char *perms = statbuf_get_perms(&sbuf);  //��ȡ�ļ�ȨȨ����Ϣ 
	
		//�����ݸ�ʽ����buf��
		offset = sprintf(buf, "%s", perms);

		offset += sprintf(buf+offset, "%3d %-8d %-8d %8lld ", 
			(int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (unsigned long long)sbuf.st_size);

		const char *pdate = statbuf_get_date(&sbuf);  //��ȡ����޸�ʱ��
		offset += sprintf(buf+offset, "%s ", pdate);  //����ʱ��

		sprintf(buf+offset, "%s\r\n", dt->d_name); //�����ļ���

		send(sess->data_fd, buf, strlen(buf), 0);//ͨ�����������׽��ַ���
	}

	closedir(dir);
}

static void do_list(session_t *sess)
{
	//1 ������������
	if(get_transfer_fd(sess) != 0)
		return;

	//2 150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3 �����б�
	list_common(sess);

	//4 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");



	//�ر���������
	close(sess->data_fd);
	sess->data_fd = -1;

	//���¿����������ӶϿ�
	start_cmdio_alarm();
}

static void do_cwd(session_t *sess)//�ı乤��Ŀ¼
{
	if(chdir(sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
	else
		ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_mkd(session_t *sess)  //mkdir  ����Ŀ¼
{
	//MKD  /home/hlc/projects/111
	if(mkdir(sess->arg, 0755) < 0)    //mkdir(·����Ȩ�ޣ�
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed.");
	else
	{
		char text[MAX_BUFFER_SIZE] = {0};
		sprintf(text, "\"%s\" created", sess->arg);  
		ftp_reply(sess, FTP_MKDIROK, text);  //257 "/home/hlc/projects/111" created
	}
}

static void do_rmd(session_t *sess) // rmdir  ɾ��Ŀ¼
{
	//RMD /home/hlc/projects/111
	if(rmdir(sess->arg) < 0)
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
	else                 //250 Remove directory operation successful.
		ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful."); 

}

static void do_dele(session_t *sess)  //ɾ����ͨ�ļ�
{  //DELE  /home/hlc/projects/test.c
	if(unlink(sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
	else
		ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_size(session_t *sess)  //���ļ���С
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

static void do_rnfr(session_t *sess)  // ������
//�ļ�������RNFR  [path+old_filename] ---> RNTO  [path+new_filename]
{
	//����ԭʼ�ļ����ֵ�sess->rnfr_name
	unsigned int len = strlen(sess->arg);
	sess->rnfr_name = (char*)malloc(len + 1);
	memset(sess->rnfr_name, 0, len+1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
static void do_rnto(session_t *sess) //������Ϊ...
{
	if(sess->rnfr_name == NULL)
	{  //RNTO֮ǰ��Ҫ����ӦRNFR
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
//ͬʱ���ϴ�����������
void limit_rate(session_t* sess, unsigned long bytes_transfer, int is_upload)
{                      //is_upload ��1��ʾ�ϴ���0��ʾ����
	//�Ǽǽ���ʱ��
	unsigned long long cur_sec = get_time_sec();
	unsigned long long cur_usec = get_time_usec();

	double pass_time = (double)(cur_sec - sess->transfer_start_sec); //���㴫�侭������
	pass_time += ((double)(cur_usec - sess->transfer_start_usec) / 1000000); //���ϴ��侭����΢��

	//��ǰ�Ĵ����ٶ�
	unsigned long cur_rate = (unsigned long)(bytes_transfer / pass_time);
	double rate_ratio; //����

	if (is_upload) 		//�ϴ�
	{
		if (tunable_upload_max_rate == 0 || cur_rate <= tunable_upload_max_rate)
		{			//������
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_upload_max_rate;
	}
	else  		//����
	{
		if (tunable_download_max_rate == 0 || cur_rate <= tunable_download_max_rate)
		{			//������
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_download_max_rate;
	}

	double sleep_time = (rate_ratio - 1) * pass_time;//����ʱ��
	nano_sleep(sleep_time);	//����

	//���µǼǿ�ʼʱ��
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}





static void do_retr(session_t *sess)  //����
{
	if(get_transfer_fd(sess) != 0) //�Ƚ�����������
		return;

	int fd;
	if((fd = open(sess->arg, O_RDONLY)) < 0) //���ļ�
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	struct stat sbuf; 
	fstat(fd, &sbuf); //������򿪵��ļ�����Ϣ����sbuf��
	char buf[MAX_BUFFER_SIZE] = {0};
	if(sess->is_ascii)   //�ж���ASCII���仹�Ƕ����ƴ���  
		//���ظ������ȸ�ʽ����buf��
		sprintf(buf, "Opening ASCII mode data connection for %s (%ull bytes).", sess->arg, (unsigned long long)sbuf.st_size);
	else
		sprintf(buf, "Opening BINARY mode data connection for %s (%ull bytes).",sess->arg, (unsigned long long)sbuf.st_size);
	ftp_reply(sess, FTP_DATACONN, buf);	//�ظ�150 �����������ӳɹ�

	//��ʼ��������  �ļ���Ƭ����
	unsigned long long  total_size = sbuf.st_size;

	//�ϵ�����
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if (offset >= total_size) //�Ѿ�������� 
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else
	{
		if (lseek(fd, offset, SEEK_SET) < 0) //����ƫ����ʧ��
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		}
		else //����ƫ�����ɹ�
		{
			int read_count = 0; //ÿ�ζ�ȡ���ֽ���
			total_size -= offset;
			
			//�Ǽǿ�ʼ����ʱ��
			sess->transfer_start_sec = get_time_sec(); //��
			sess->transfer_start_usec = get_time_usec();//΢��
			
			while (1)
			{
				memset(buf, 0, MAX_BUFFER_SIZE);
				read_count = total_size > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : total_size;
				int ret = read(fd, buf, read_count);
				if (ret == -1 || ret != read_count)
				{  //��ȡ����ʧ��
					ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
					break;
				}
				if (ret == 0)
				{                  //   226     �������
					ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
					break;
				}

				//����Ǵ�����������״̬
				sess->data_process = 1;

				//���ݶ����������� �ж����޳��٣����������٣�˯�ߣ�
				//���� --�������Ǽǽ���ʱ��
				limit_rate(sess, ret, 0);

				send(sess->data_fd, buf, ret, 0); //�ӷ������������ݵ��ͻ���
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

	//���¿����������ӶϿ�
	start_cmdio_alarm();
}

static void do_stor(session_t *sess)  //�ϴ�
{
	if(get_transfer_fd(sess) != 0)
		return;

	int fd;
	if((fd = open(sess->arg, O_CREAT|O_WRONLY, 0755)) < 0)  //�����ļ���ֻд��
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//�ظ�150
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//�ϵ�����
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if (lseek(fd, offset, SEEK_SET) < 0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	//�Ǽ�ʱ��
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();

	//��������
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

		//����Ǵ�����������״̬
		sess->data_process = 1;

		//����
		limit_rate(sess, ret, 1); //1��ʾ�ϴ�

		write(fd, buf, ret);
	}

	close(fd);
	if(sess->data_fd != -1)
	{
		close(sess->data_fd);
		sess->data_fd = -1;
	}

	//���¿����������ӶϿ�
	start_cmdio_alarm();
}

//�ϵ����������� ����REST [pos]   ��Ҫ��¼��pos��Ϣ��Ȼ���ϴ�������ʱƫ����Ӧλ�ö�д
static void do_rest(session_t* sess) 
{
	sess->restart_pos = (unsigned long long)atoll(sess->arg);  //��strתΪunsigned long long

	char text[MAX_BUFFER_SIZE] = { 0 };
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	//350 Restart position accepted (restart_pos�Ĵ�С).
	ftp_reply(sess, FTP_RESTOK, text);
}