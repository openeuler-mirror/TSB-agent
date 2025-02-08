

#ifndef TSBAPI_TSB_MEASURE_USER_H_
#define TSBAPI_TSB_MEASURE_USER_H_
/*
 *
 * 	�����ļ������ԣ�ֻƥ��HASH
 * 	�������û��ռ�
 */
int tsb_measure_file(const char *path);


/*
 *	�����ļ������ԣ�ƥ��·����HASH
 *	�������û��ռ�
 */
int tsb_measure_file_path(const char *path);

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
 * 	���������֤��������ID
 * 	pid=0��֤��ǰ����
 * 	�������û��ռ�
 */
int tsb_verify_process(int pid,const char *name);




/*
 * ����ָ���ں˶�
 */
int tsb_measure_kernel_memory(const char *name);

/*
 * ���������ں˶�
 * (���룬ϵͳ���ñ��жϱ�)
 */
int tsb_measure_kernel_memory_all();


/*
  * ��ȡ��ǰ�������
 */
int tsb_get_process_identity(unsigned char *process_name,int *process_name_length);

/*
  *  ��ȡ��ǰ�û���ɫ
 */
int tsb_is_role_member(const unsigned char *role_name);

//�ɲ��ú�̨�̣߳��첽�����Ƿ���Ҫ��




/*
 * �����ͳ��������֤�ӿ�
 * only in kernel
 */

//int tcf_measure_process_taskp(struct task_struct *p,int checklib);
//int tcf_measure_process_path_taskp(struct task_struct *p,int checklib);
//int tcf_measure_process_with_path_taskp(struct task_struct *p,int checklib,const char *path);
//
//
//int tcf_verify_process_taskp(struct task_struct *p,int checklib,const char *name);
//int tcf_verify_process_path_taskp(struct task_struct *p,int checklib,const char *name);
//int tcf_verify_process_with_path_taskp(struct task_struct *p,int checklib,const char *name,const char *path);
//�ɲ��ú�̨�̣߳��첽�����Ƿ���Ҫ��





#endif /* TSBAPI_TSB_MEASURE_USER_H_ */
