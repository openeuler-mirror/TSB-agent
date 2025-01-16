

#ifndef TSBAPI_TSB_MEASURE_KERNEL_H_
#define TSBAPI_TSB_MEASURE_KERNEL_H_

enum{
	TSB_MEASURE_FAILE = 1,
	TSB_ERROR_CALC_HASH,
	TSB_ERROR_SYSTEM,
};

/** whitelist error */
enum{
	TSB_ERROR_FILE = 100,
};

/** dmeasure error */
enum{
	TSB_ERROR_DMEASURE_POLICY_NOT_FOUND = 200,
	TSB_ERROR_DMEASURE_NAME,
};

/** process identity error */
enum{
	TSB_ERROR_PROCESS_IDENTITY_POLICY = 300,
};


/*
 * 	�����ļ������ԣ�ֻƥ��HASH
 * 	�������û��ռ�
 */
int tsb_measure_file(const char *path);

/*
 *
 * 	�����ļ������ԣ�ֻƥ��HASH,���ļ�ָ��
 * 	���������û��ռ�
 */

int tsb_measure_file_filp(struct file *filp);

/*
 *	�����ļ������ԣ�ƥ��·����HASH
 *	�������û��ռ�
 */
int tsb_measure_file_path(const char *path);

/*
 *	�����ļ������ԣ�ƥ��·����HASH�����ļ�ָ��
 *	���������û��ռ�
 */
int tsb_measure_file_path_filp(struct file *filp);

/*
 *
 *	�����ļ������ԣ�ƥ��ָ��·����HASH�����ļ�ָ��
 *	���������û��ռ�
 */
int tsb_measure_file_specific_path_filp(const char *path,struct file *filp);


/*
 * 	��׼��ƥ��
 */
int tsb_match_file_integrity(const unsigned char *hash, int hash_length);
/*
 * 	��׼�ⰴ·����ƥ��
 */
int tsb_match_file_integrity_by_path(
		const unsigned char *hash, int hash_length,
		const unsigned char *path, int path_length);

/*
 * 	���̶�̬�����ͽ��������֤�ӿ�
 */


/*
 * 	���̶�̬������������ID
 * 	pid=0������ǰ����
 *	�������û��ռ�
 */
int tsb_measure_process(unsigned pid);
/*
 * 	���̶�̬������������ָ��
 * 	���������û��ռ�
 */
int tsb_measure_process_taskp(struct task_struct *task);



/*
 * ����ָ���ں˶�
 */
int tsb_measure_kernel_memory(const char *name);

/*
 * ���������ں˶�
 * (���룬ϵͳ���ñ��жϱ�)
 */
int tsb_measure_kernel_memory_all(void);


/*
 * 	���������֤��������ID
 * 	pid=0��֤��ǰ����
 * 	�������û��ռ�
 */
int tsb_verify_process(int pid,const char *name);



/*
 * 	���������֤��������ָ��
 * 	���������û��ռ�
 */
int tsb_verify_process_taskp(struct task_struct *task,const char *name);


/*
  * ��ȡ��ǰ�������
 */
int tsb_get_process_identity(unsigned char *process_name,int *process_name_length);

/*
  *  ��ȡ��ǰ�û���ɫ
 */
int tsb_is_role_member(const unsigned char *role_name);
#endif /* TSBAPI_TSB_MEASURE_KERNEL_H_ */
