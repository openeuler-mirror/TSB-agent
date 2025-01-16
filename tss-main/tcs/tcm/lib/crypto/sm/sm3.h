#ifndef __SM3_H__
#define __SM3_H__

#include <inttypes.h>

#define SM3_DIGEST_SIZE		32

typedef struct sm3_context {
    uint32_t total_bytes_High;
    uint32_t total_bytes_Low;
    uint32_t vector[8];
    uint8_t  buffer[64];
} sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_SM3_CONTEXT_MAX_SIZE
#define CONFIG_SM3_CONTEXT_MAX_SIZE (0x200)
#endif

struct sm3_ctx_common{
	unsigned char context[CONFIG_SM3_CONTEXT_MAX_SIZE];
};

/************************************************************************/
/* sm3_init											                */
/* \brief			��ʼ�� SM3 ������                                   */
/* \param ctx		SM3 ������                                          */
/************************************************************************/
int sm3_init (sm3_context *ctx);

/************************************************************************/
/* sm3_update															*/
/* \brief			������ϢժҪ										*/
/* \param ctx		SM3 ������                                          */
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/************************************************************************/
int sm3_update (sm3_context *ctx, const unsigned char *chunk_data, unsigned int chunk_length);

/************************************************************************/
/* sm3_finish															*/
/* \brief			��ȡժҪֵ											*/
/* \param ctx		SM3 ������                                          */
/* \param output	���������											*/
/* \remark			�������ȡ����� SM3_DIGEST_SIZE ��С���ڴ�			*/
/************************************************************************/
int sm3_finish (sm3_context *ctx, unsigned char output[SM3_DIGEST_SIZE]);

/************************************************************************/
/* sm3																	*/
/* \brief			���㲢��ȡ��ϢժҪֵ								*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/* \param output	���������											*/
/* \remark			�������ȡ����� SM3_DIGEST_SIZE ��С���ڴ�			*/
/************************************************************************/
void sm3 (const unsigned char *input, int ilen, unsigned char output[SM3_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif	/** __SM3_H__ */

