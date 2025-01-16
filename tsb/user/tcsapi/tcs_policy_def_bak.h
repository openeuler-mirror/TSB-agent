

#ifndef TCSAPI_TCS_POLICY_DEF_H_
#define TCSAPI_TCS_POLICY_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
enum{
	PROCESS_DMEASURE_REF_START,//ƥ�������ɼ�ֵ
	PROCESS_DMEASURE_REF_LIB,//ƥ�������Ի�׼��
	//PROCESS_DMEASURE_REF_SEPCIFIC_LIB//ƥ��һ���ض���
};

enum{
	PROCESS_DMEASURE_MATCH_HASH_ONLY,//ֻƥ��HASH
	PROCESS_DMEASURE_MATCH_WITH_PATH,//ƥ��HASH��·��
};

enum{
	PROCESS_DMEASURE_LIB_NOT = 1,//�������⡣
	PROCESS_DMEASURE_LIB_GLOBAL ,//��ȫ�ֻ�׼�������
	//PROCESS_DMEASURE_LIB_SPECIFIC,//��ר�Ż�׼�������
};

enum{
	PROCESS_VERIFY_MODE_DEFAULT ,//������ָ����ʽ��
	PROCESS_VERIFY_MODE_NO_LIB ,//����֤�⡣
	PROCESS_VERIFY_MODE_REF_LIB ,//��ȫ�ֻ�׼����֤��
	PROCESS_VERIFY_MODE_SPECIFIC_LIB,//��ר�Ż�׼����֤��
};
#pragma pack(push, 1)



struct global_control_policy{

	uint32_t be_size;
	uint32_t be_boot_measure_on;//on or not,Ĭ��ֵΪ�����ر�ʱ������BIOS,ֱ�ӷ��سɹ���

	  uint32_t be_program_measure_on;//on or not��Ĭ��ֵΪ�أ����ذ�������򿪡��������빳�Ӻ���
      uint32_t be_dynamic_measure_on;//on or not

	uint32_t be_boot_control;//control or not
	  uint32_t be_program_control;//control or not ������ڰ������У��Ƿ����

	//uint32_t be_policy_require_auth;
	//uint32_t be_static_reference_auth;
	//uint32_t be_dynamic_reference_auth;

//	uint32_t be_policy_auth;//none��hmac��signature
//	uint32_t be_static_reference_auth;//none��hmac��signature
//	uint32_t be_dynamic_reference_auth;//none
//	uint32_t be_auth_reference_auth;//hmac��signature

	uint32_t be_policy_replay_check;//check or not?
	uint32_t be_static_reference_replay_check;//check or not?
	uint32_t be_dynamic_reference_replay_check;//check or not?

	//uint32_t be_policy_require_process_bind;//if bind process
	//uint32_t be_static_reference_require_process_bind;//if bind process
	//uint32_t be_dynamic_reference_require_process_bind;//if bind process

	//uint32_t be_policy_require_state_bind;//if state process
	//uint32_t be_static_reference_require_state_bind;//if state process
	//uint32_t be_dynamic_reference_require_state_bind;//if state process


	//uint32_t be_process_bind_mode;//program_name,main_code,libs

	  uint32_t be_program_measure_mode;//software_measure,tcs_check,tcs_measure,auto
	  uint32_t be_measure_use_cache;//disabe enable

	  uint32_t be_dmeasure_max_busy_delay;//��̬��������ӳ٣������ƣ�
	uint32_t be_process_dmeasure_ref_mode;//����ʱ�ɼ����ļ������Կ⣿
	uint32_t be_process_dmeasure_match_mode;//ֻƥ��HASH������Ҳ·��
	  uint32_t be_program_measure_match_mode;//ֻƥ��HASH������Ҳ·��
	uint32_t be_process_dmeasure_lib_mode;//�Ƿ������
	uint32_t be_process_verify_lib_mode;//�Ƿ�����⣿�ļ������Կ⣿ʹ�������֤�⡣
	//uint32_t be_padding;//

};

struct global_control_policy_update{
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct global_control_policy policy;
};






struct policy_report_content{
	struct global_control_policy global_control_policy;
	//uint64_t be_nonce;//
	uint32_t be_file_integrity_valid;
	uint32_t be_file_integrity_total;
	uint32_t be_boot_measure_ref_bumber;
	uint32_t be_dynamic_measure_ref_bumber;
	uint32_t be_admin_cert_number;
	uint32_t be_trusted_cert_number;
	unsigned char program_reference_hash[32] ;
	unsigned char boot_reference_hash[32] ;
	unsigned char dynamic_reference_hash[32] ;
	unsigned char admin_cert_hash[32];
	unsigned char trusted_cert_hash[32];

};
struct policy_report{
	uint64_t be_nonce;
	struct policy_report_content content;
	unsigned char signiture[32];
};
#pragma pack(pop)

#endif /* TCSAPI_TCS_POLICY_DEF_H_ */
