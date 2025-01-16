#ifndef SM3_H_
#define SM3_H_

#define SM3_DIGEST_SIZE		32

#include <linux/types.h>

struct sm3_context {
	uint32_t total_bytes_High;
	uint32_t total_bytes_Low;
	uint32_t vector[8];
	uint8_t buffer[64];	/* 64 byte buffer                            */

//  unsigned char ipad[64];     /*!< HMAC: inner padding        */
//  unsigned char opad[64];     /*!< HMAC: outer padding        */
};

typedef struct sm3_context sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

	int sm3_starts(sm3_context * index);

/************************************************************************/
/* sm3_init											                    */
/* \brief			��ʼ�� SM3 ������                                   */
/* \param ctx		SM3 ������                                          */
/************************************************************************/
	int sm3_init(sm3_context * ctx);

	sm3_context *sm3_alloc_init(void);

/************************************************************************/
/* sm3_update															*/
/* \brief			������ϢժҪ										*/
/* \param ctx		SM3 ������                                          */
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/************************************************************************/
	int sm3_update(sm3_context * index, const unsigned char *chunk_data,
		       unsigned int chunk_length);

/************************************************************************/
/* sm3_finish															*/
/* \brief			��ȡժҪֵ											*/
/* \param ctx		SM3 ������                                          */
/* \param output	���������											*/
/* \remark			�������ȡ����� SM3_DIGEST_SIZE ��С���ڴ�			*/
/************************************************************************/
	int sm3_finish(sm3_context * index,
		       unsigned char output[SM3_DIGEST_SIZE]);

/************************************************************************/
/* sm3																	*/
/* \brief			���㲢��ȡ��ϢժҪֵ								*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/* \param output	���������											*/
/* \remark			�������ȡ����� SM3_DIGEST_SIZE ��С���ڴ�			*/
/************************************************************************/
	void sm3(const unsigned char *input, int ilen,
		 unsigned char output[SM3_DIGEST_SIZE]);

//int sm3_file( const char *path, unsigned char output[SM3_DIGEST_SIZE] );


#ifdef __cplusplus
}
#endif
#endif				//SM3_H_
