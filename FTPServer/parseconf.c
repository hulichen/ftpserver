//�����ļ�����ģ��
#include"parseconf.h"
#include"tunable.h"
#include"str.h"

//Ŀǰ֧�� bool int �� str���͵������������
//����������������ͣ�������������ͽ���������ģ�鼴�� 

//bool��������
static struct parseconf_bool_setting
{
	const char* p_setting_name; //�����������
	int* p_variable;     //�������ֵ
}
parseconf_bool_array[] =   //����bool��������ĳ�ʼֵ
{
	{"pasv_enable", &tunable_pasv_enable},//������-���Ƿ�������ģʽ
	{"port_enable", &tunable_port_enable}, //������-���Ƿ�������ģʽ
	{NULL, NULL}  //NULLΪ�������
};

//int������
static struct parseconf_uint_setting
{
	const char* p_setting_name;//�����������
	unsigned int* p_variable;//�������ֵ
}
parseconf_uint_array[] =    //����int��������ĳ�ʼֵ
{
	{"listen_port", &tunable_listen_port}, //�˿�
	{"max_clients", &tunable_max_clients}, //���������
	{"max_per_ip" , &tunable_max_per_ip}, //ÿip���������
	{"accept_timeout", &tunable_accept_timeout}, //Accept���ӳ�ʱʱ��
	{"connect_timeout", &tunable_connect_timeout}, //Connect���ӳ�ʱʱ��
	{"idle_session_timeout", &tunable_idle_session_timeout}, //�������ӳ�ʱʱ��
	{"data_connection_timeout", &tunable_data_connection_timeout},//�������ӳ�ʱʱ��
	{"local_umask", &tunable_local_umask}, //����
	{"upload_max_rate", &tunable_upload_max_rate}, //����ϴ��ٶ�
	{"download_max_rate", &tunable_download_max_rate},// ��������ٶ�
	{NULL, NULL}
};


//str������
static struct parseconf_str_setting
{
	const char* p_setting_name;
	const char** p_variable;
}
parseconf_str_array[] =
{
	{"listen_address", &tunable_listen_address}, //������ַ
	{NULL, NULL}
};


void parseconf_load_file(const char* path) //�����ļ�
{
	FILE* fp = fopen(path, "r");  //ֻ����
	if (NULL == fp)
		ERR_EXIT("parseconf_load_file");

	char setting_line[MAX_SETTING_LINE_SIZE] = { 0 };
	while (fgets(setting_line, MAX_SETTING_LINE_SIZE, fp) != NULL) //ѭ����ȡ������Ϣ������
	{
		if (setting_line[0] == '\0' || setting_line[0] == '#')  //���ε����к�#��ͷ��ע����
			continue;
		str_trim_crlf(setting_line); //ȥ���ַ����Ļس��ͻ���

		//����������
		parseconf_load_setting(setting_line);

		memset(setting_line, 0, MAX_SETTING_LINE_SIZE);
	}

	fclose(fp);
}

//listen_port=9100
void parseconf_load_setting(const char* setting)  
//������(setting)��������Ҫ��������������ݣ�����ȡ���������ļ���Ϣ���浽�����ȫ�ֱ�����
{
	char key[MAX_KEY_SIZE] = { 0 };
	char value[MAX_VALUE_SIZE] = { 0 };
	str_split(setting, key, value, '=');//����=�ָ�������key=val;

	//��ѯstr������
	//����һ�ṹ������ָ��ָ��str������������Ԫ��
	const struct parseconf_str_setting* p_str_setting = parseconf_str_array;
	while (p_str_setting->p_setting_name != NULL)//���������鲻��
	{
		if (strcmp(key, p_str_setting->p_setting_name) == 0)//ͨ�����������ֲ����������Ƿ����
		{
			const char** p_cur_setting = p_str_setting->p_variable;
			if (*p_cur_setting) //�ͷ���һ�α������ݿ��ٵĿռ�
				free((char*)*p_cur_setting);
			*p_cur_setting = strdup(value);//��valuek������p_cur_setting�У�strdup���Զ��ڵײ�malloc�ռ�
			return;
		}
		p_str_setting++; //��ȡ������������һ��
	}

	//��ѯbool������  0/1������ 
	const struct parseconf_bool_setting* p_bool_setting = parseconf_bool_array;
	while (p_bool_setting->p_setting_name != NULL)
	{
		if (strcmp(key, p_bool_setting->p_setting_name) == 0)
		{
			str_upper(value); //yes->YES
			int* p_cur_setting = p_bool_setting->p_variable;
			if (strcmp(value, "YES") == 0)
				*p_cur_setting = 1;
			else if (strcmp(value, "NO") == 0)
				*p_cur_setting = 0;
			else
				ERR_EXIT("parseconf_load_setting");
			return;
		}
		p_bool_setting++;
	}

	//��ѯint������  
	const struct parseconf_uint_setting* p_uint_setting = parseconf_uint_array;
	while (p_uint_setting->p_setting_name != NULL)
	{
		if (strcmp(key, p_uint_setting->p_setting_name) == 0)
		{
			unsigned int* p_cur_setting = p_uint_setting->p_variable;
			*p_cur_setting = atoi(value);//�����������Ϊһ��str
			return;
		}
		p_uint_setting++;
	}
}