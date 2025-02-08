#ifndef LOG_CONFIG_POLICY_H_
#define LOG_CONFIG_POLICY_H_

#include "sec_domain.h"

enum {
	RECORD_SUCCESS = 1,
	RECORD_FAIL = 2,
	RECORD_NO = 4,
	RECORD_ALL = 8,
};

struct log_config{
	//	int log_level;
	int program_log_level;
	int dmeasure_log_level;
	//	int study_log_on;//������ѧϰ��־�������
	int log_buffer_on;//��־�־û��濪��
	int log_integrity_on;//��־�����Լ�鿪��
	unsigned int log_buffer_limit;//��־�����С����(mb)
	unsigned int log_buffer_rotate_size;//��־������ת��С
	unsigned int log_buffer_rotate_time;//��־������ת��С(hours)
	unsigned int log_inmem_limit;//�޻���ʱ��־�ڴ��С����(mb)
};

int log_config_policy_init(void);
void log_config_policy_exit(void);
int get_log_config_policy(int type, int result, struct sec_domain *sec_d);

#endif /* LOG_CONFIG_POLICY_H_ */
