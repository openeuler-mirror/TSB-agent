

#ifndef TCSAPI_TCS_ATTEST_DEF_H_
#define TCSAPI_TCS_ATTEST_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#include "tcs_policy_def.h"


#define MAX_REMOTE_CERT_SIZE 	4096

enum {
	BOOT_PCR_BIOS = 1,	//启动度量初始阶段至BIOS阶段的PCR
	BOOT_PCR_BOOTLOADER,//启动度量初始阶段至BOOTLOADER阶段的PCR
	BOOT_PCR_KERNEL,	//启动度量初始阶段至KERNEL阶段的PCR
	BOOT_PCR_TSB,		//启动度量初始阶段至TSB阶段的PCR
};

enum{
	STATUS_TRUSTED,
	STATUS_UNTRUSTED,
	STATUS_UNKNOWN,
};

enum TPCM_FEATURES_BIT{
	TPCM_FEATURES_INTERCEPT_MEASURE = 0,
	TPCM_FEATURES_DYNAMIC_MEASURE,
	TPCM_FEATURES_SIMPLE_BOOT_MEASURE,
	TPCM_FEATURES_IMPORT_BIOS_MEASURE_RESULT,
	TPCM_FEATURES_FIRMWARE_UPGRADE,
	TPCM_FEATURES_FLASH_ACCESS,
	TPCM_FEATURES_SIMPLE_INTERCEPT_MEASURE,
};

#pragma pack(push, 1)
struct trust_evidence{
	uint64_t be_nonce;//防重放标记
	uint32_t be_eval;//可信评分
	uint32_t be_boot_times;//启动次数计数	4字节	TPCM启动次数
	uint32_t be_tpcm_time;//内部时钟计数	4字节	TPCM内部时钟计数
	uint64_t be_tpcm_report_time;//TPCM上报时间	8字节	TPCM上报可信报告的时间
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
	unsigned char attached_hash[DEFAULT_HASH_SIZE];//附带数据的HASH
	unsigned char signature[DEFAULT_SIGNATURE_SIZE];
};
/*
 * 带数据和应用远程可信证明
 * 远程证明认证协议
 */
struct trust_report_content{
	//uint32_t be_length;
	//uint32_t be_signature_length;
	uint64_t be_host_report_time;//报告时间	8字节	TPCM宿主设备申请报告时间
	uint64_t be_host_startup_time;//系统启动时间	8字节	TPCM宿主设备启动时间

	unsigned char host_id[MAX_HOST_ID_SIZE];//机器ID	 32字节	TPCM宿主设备ID
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];

	struct global_control_policy global_control_policy;//8 byte 对齐

	uint32_t be_eval;//可信评分	4字节	满分100分，启动度量失败为0分
	uint32_t be_host_ip;//IP地址	4字节	TPCM宿主设备IP地址

	uint32_t be_ilegal_program_load;//非法程序执行次数	4字节	TPCM记录的非法程序执行次数
	uint32_t be_ilegal_lib_load;//非法动态库加载次数	4字节	TPCM记录的非法动态库加载次数

	uint32_t be_ilegal_kernel_module_load;//非法内核模块加载次数	4字节	TPCM记录的非法内核模块加载次数
	uint32_t be_ilegal_file_access;//非法文件访问次数	4字节	TPCM记录的非法文件访问次数

	uint32_t be_ilegal_device_access;//非法设备访问次数	4字节	TPCM记录的非法设备访问次数
	uint32_t be_ilegal_network_inreq;//非法网络访问次数	4字节	TPCM记录的非法网络访问次数

	uint32_t be_ilegal_network_outreq;//非法网络对外请求次数	4字节	TPCM记录的非法网络请求次数
	uint32_t be_process_code_measure_fail;//	程序代码段度量失败次数	4字节	TPCM记录的程序代码段度量失败次数

	uint32_t be_kernel_code_measure_fail;//内核代码段度量失败次数	4字节	TPCM记录的内核代码段度量失败次数
	uint32_t be_kernel_data_measure_fail;//内核关键数据度量失败次数	4字节	TPCM记录的内核关键数据度量失败次数

	uint32_t be_notify_fail;//错误通知次数	4字节	TPCM记录的发送通知失败的次数
	uint32_t be_boot_measure_result;//启动度量是否合法	4字节	0=启动合法
	//1=启动不合法
	//2=状态未知
	uint32_t be_boot_times;//启动次数计数	4字节	TPCM启动次数
	uint32_t be_tpcm_time;//内部时钟计数	4字节	TPCM内部时钟计数

	uint64_t be_tpcm_report_time;//TPCM上报时间	8字节	TPCM上报可信报告的时间

	uint32_t be_log_number;//日志条数	4字节	TPCM发送成功日志条数
	unsigned char log_hash[DEFAULT_HASH_SIZE];	//	日志完整性hash值	32字节	发送日志的PSR扩展值，用于完整性校验
	//		策略完整性hash值	32字节	当前策略的hash值，用于完整性校验
	unsigned char bios_pcr[DEFAULT_PCR_SIZE];
	unsigned char boot_loader_pcr[DEFAULT_PCR_SIZE];
	unsigned char kernel_pcr[DEFAULT_PCR_SIZE];
	unsigned char tsb_pcr[DEFAULT_PCR_SIZE];
	unsigned char boot_pcr[DEFAULT_PCR_SIZE];

};
struct trust_report{
	struct trust_report_content content;
	uint64_t be_nonce;//防重放标记
	unsigned char signature[DEFAULT_SIGNATURE_SIZE];
};

struct remote_cert{
	uint32_t  be_alg;
	uint32_t  be_length;
	unsigned char id[MAX_TPCM_ID_SIZE];
	unsigned char cert[MAX_REMOTE_CERT_SIZE];
};

struct tpcm_info{//参照之前的格式
//白名单可用的空间
	uint64_t be_host_time;//获取状态信息的时间	8字节
	struct global_control_policy global_control_policy;
	uint32_t be_cmd_handled;//已处理命令数量	4字节
	uint32_t be_cmd_pending;//待处理命令数量	4字节
	uint32_t be_cmd_error_param;//错误命令数量（发现参数错误）	4字节
	uint32_t be_cmd_error_refused;//拒绝接收命令数量（队列满）	4字节
	uint32_t be_file_integrity_valid;//完整性基准库有效条数	4字节
	uint32_t be_file_integrity_total;//完整性基准库总条数	4字节
	uint32_t be_boot_measure_ref_bumber;//启动基准库条数	4字节
	uint32_t be_dynamic_measure_ref_bumber;//动态度量基准库条数 4字节
	uint32_t be_admin_cert_number;//管理员证书数量  4字节
	uint32_t be_trusted_cert_number;//信任的证书数量    4字节
	uint32_t be_boot_times;//启动次数	4字节
	uint64_t be_dmeasure_times;//动态度量次数	8字节
	uint32_t be_file_integrity_measure_times;//程序启动度量次数	4字节
	uint32_t be_file_notify_times;//通知次数	4字节
	uint32_t be_tpcm_type;//TPCM类型	4字节	TPCM运行在哪个CPU
	uint32_t be_tpcm_total_mem;//总内存	4字节
	uint32_t be_tpcm_available_mem;//可用内存	4字节
	uint32_t be_tpcm_nvsapce_size;//存储空间(FLASH 数据)	4字节
	uint32_t be_tpcm_nvsapce_availble_size;//可用存储空间（FLASH数据剩余部分）	4字节
	//进程数量	4字节	当前为1
	uint32_t be_boot_trust_state;//启动可信状态	4字节	0：可信
	//1：不可信（有未匹配字段）
	//2：状态未知（基准值未设置时启动，基准值为全零）
	uint32_t be_trust_os_version;//可信操作系统版本号	4字节
	uint32_t be_cpu_firmware_version;//CPU基础固件版本号
	uint32_t be_bios_firmware_version;//BIOS固件版本号
	uint32_t be_tpcm_firmware_version;//TPCM版本号	4字节
	//有效程序基准库条数	4字节
	uint32_t be_tpcm_cpu_number;//CPU数量	4字节
	uint32_t be_ek_generated;//EK是否生成	4字节
	uint32_t be_srk_generated;//根存储密钥是否生成	4字节
	uint32_t be_pik_generated;//、PIK是否生成	4字节
	uint32_t be_pesistent_key_number;//持久存储密钥数量	4字节
	uint32_t be_alg_mode;//算法实现（软，硬）	4字节	软算法=1
	//硬算法=2
	unsigned char id[MAX_TPCM_ID_SIZE];
};


#pragma pack(pop)

#endif /* TCSAPI_TCS_ATTEST_DEF_H_ */
