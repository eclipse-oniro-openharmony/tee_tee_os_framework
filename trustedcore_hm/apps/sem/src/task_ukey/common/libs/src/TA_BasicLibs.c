#include "TA_BasicLibs.h"
#include "TA_Log.h"
#include "tee_mem_mgmt_api.h"

uint32_t TA_Strlen(const char *str)
{
	if (NULL == str) {
		return 0;
	} else {
		const char *p = str;
		while (*p++ != '\0');
		return p - str - 1;
	}
}

void itoa(int val, char *buf, unsigned radix)
{
    if(NULL == buf)
    {
        return;
    }

    char*   p;
    char*   firstdig;
    char   temp;
    unsigned   digval;
    p = buf;

    if (val < 0)
    {
        *p++ = '-';
        val = (unsigned long)(-(long)val);
    }

    firstdig = p;
    do
    {
        digval = (unsigned)(val % radix);
        val /= radix;

        if  (digval > 9)
        { *p++ = (char)(digval - 10 + 'a'); }
        else
        { *p++ = (char)(digval + '0'); }
    }while (val > 0);
    *p-- = '\0';

    do
    {
        temp = *p;
        *p = *firstdig;
        *firstdig = temp;
        --p;
        ++firstdig;
    }while (firstdig < p);

    return;
}

uint64_t get_time()
{
    TEE_Time t;
    TEE_GetSystemTime(&t);
    SLogTrace("%d.%d", t.seconds, t.millis);
    return (t.seconds * 1000ull) + t.millis;
}
/*
void printHexWithTag(const char *tag, const unsigned char *IN, int size)
{
	int i, j;
	if (IN == NULL) {
		return;
	}
	int sizeOut = size * 2;
	char *out = (char *)TEE_Malloc(sizeOut + 1, 0);
	if (NULL == out) {
		LOGI("printHexWithTag TEE_Malloc error\n");
		return;
	}
	TEE_MemFill(out, 0, sizeOut + 1);
	for (i = 0; i < size; i++) {
		out[2 * i] = (IN[i] >> 4);
		out[2 * i + 1] = (IN[i] & 0x0F);
	}

	for (j = 0; j < sizeOut; j++) {

		if (out[j] <= 9) {
			out[j] += '0';
		} else {
			out[j] += ('A' - 0x0A);
		}
	}
	LOGI("%s : %s\n", tag, out);
	LOGI("\n\n");
	TEE_Free(out);
}
*/

