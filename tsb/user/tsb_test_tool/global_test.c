#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_policy.h"

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	struct global_control_policy global_policy={0};
	global_policy.be_program_measure_on = htonl(0); //����������
	global_policy.be_program_control = htonl(1);  //ѧϰģʽ
	global_policy.be_measure_use_cache = htonl(0);   //�Ƿ��û��� 1��  0����

	global_policy.be_program_measure_mode = htonl(PROCESS_MEASURE_MODE_SOFT);   //����ģʽtsb/tpcm
	//global_policy.be_program_measure_match_mode = htonl(1);  //�Ƿ�ƥ��·��

	global_policy.be_dynamic_measure_on = htonl(1); //��̬��������

	global_policy.be_process_verify_lib_mode = htonl(PROCESS_VERIFY_MODE_SPECIFIC_LIB);

	global_policy.be_tsb_flag1 = htonl(0); //�Ա���

	if (strcmp(argv[1], "1") == 0)
		tsb_set_global_control_policy((unsigned char *)&global_policy, sizeof(global_policy));
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_global_control_policy();
	else
		printf("param argv error!\n");
	
	return 0;
}
