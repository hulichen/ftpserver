/*ϵͳ����ģ��*/
#include"sysutil.h"

void getlocalip(char* ip)  //��ȡ������IP��ַ
{
	char host[MAX_HOST_NAME_SIZE] = { 0 };
	if (gethostname(host, MAX_HOST_NAME_SIZE) < 0) //��ȡ������
		ERR_EXIT("getlocalip");

	struct hostent* pht;
	if ((pht = gethostbyname(host)) == NULL)   //������������ȡIP����Ϣ
		ERR_EXIT("gethostbyname");

	strcpy(ip, inet_ntoa(*(struct in_addr*)pht->h_addr));
}

int tcp_server(const char *host, unsigned short port)  //����������TCP�����׽���
{
	int listenfd;
	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  //���������׽���
		ERR_EXIT("sys create socket error");

    //�󶨵�ַ
	struct sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(port);
	addrSer.sin_addr.s_addr = inet_addr(host);

	//��֮ǰ ʹ��setsockopt���õ�ַ���� 
	int on = 1;
	if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		ERR_EXIT("sys setsockopt");

	if(bind(listenfd, (struct sockaddr*)&addrSer, sizeof(addrSer)) < 0)
		ERR_EXIT("sys bind error");

	if(listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("sys listen error");

	return listenfd;
}



int tcp_client(int port)
{
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("socket");

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = INADDR_ANY;

	int on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) //���õ�ַ�˿ڿ�������
		ERR_EXIT("setsockopt");

	if (bind(sock, (struct sockaddr*)&address, sizeof(address)) < 0)
		ERR_EXIT("bind 20");

	return sock;
}

char* statbuf_get_perms(struct stat *sbuf)  //��ȡ�ļ�Ȩ����Ϣ
{
	//eg:drwxrwxr-x    4 1000     1000           37 Aug 28  2021 projects
	static char perms[] = "----------";
	mode_t mode = sbuf->st_mode;

	//���жϵ�һ����Ϣ--->�ļ�����
	switch(mode & S_IFMT)
	{
	case S_IFREG:   //��ͨ�ļ�
		perms[0] = '-';
		break;
	case S_IFDIR:  //Ŀ¼�ļ�
		perms[0] = 'd';
		break;
	case S_IFCHR:   //�ַ��ļ�
		perms[0] = 'c';
		break;
	case S_IFIFO:  //�ܵ��ļ�
		perms[0] = 'p';
		break;
	case S_IFBLK:  //���豸�ļ�
		perms[0] = 'b';
		break;
	case S_IFLNK:  //�����ļ�
		perms[0] = 'l';
		break;
	}

    //�ж�Ȩ��
    if(mode & S_IRUSR)
		perms[1] = 'r';
	if(mode & S_IWUSR)
		perms[2] = 'w';
	if(mode & S_IXUSR)
		perms[3] = 'x';

	if(mode & S_IRGRP)
		perms[4] = 'r';
	if(mode & S_IWGRP)
		perms[5] = 'w';
	if(mode & S_IXGRP)
		perms[6] = 'x';

	if(mode & S_IROTH)
		perms[7] = 'r';
	if(mode & S_IWOTH)
		perms[8] = 'w';
	if(mode & S_IXOTH)
		perms[9] = 'x';
    
	return perms;
}

char* statbuf_get_date(struct stat *sbuf)//��ȡ����޸�ʱ��
{
	static char date[64] = {0};
	struct tm *ptm = localtime(&sbuf->st_mtime);//��ʱ���ʽ��
	strftime(date, 64, "%b %e %H:%M", ptm);  //�ַ���ʱ���ʽ��  man strftime�鿴
	return date;
}

void send_fd(int sock_fd, int fd)  
//����֮�䷢���׽���  ����ֱ�ӷ����֣���Ҫ����һЩ������Ϣ����
{
	int ret;
	struct msghdr msg;
	struct cmsghdr* p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int* p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)  //�����׽���
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr* p_cmsg;
	int* p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}



static struct timeval s_cur_time; //����һ����ǰʱ��ֵ�� ȫ�ֽṹ��timeval
unsigned long long get_time_sec()
{
	if (gettimeofday(&s_cur_time, NULL) < 0) //��ȡ��ǰʱ��ʧ��
		ERR_EXIT("gettimeofday");
	return s_cur_time.tv_sec;
}
unsigned long long get_time_usec()
{
	return s_cur_time.tv_usec;
}

void nano_sleep(double sleep_time) //���뼶�������
{
	unsigned long sec = (unsigned long)sleep_time;
	double decimal = sleep_time - (double)sec;

	struct timespec ts;    // timespec ����΢�������
	ts.tv_sec = (time_t)sec;
	ts.tv_nsec = (long)(decimal * 1000000000);

	int ret;
	do
	{
		ret = nanosleep(&ts, &ts);
	} while (ret == -1 && errno == EINTR); //ѭ������Ԥ�����߱��ź��ж�
}