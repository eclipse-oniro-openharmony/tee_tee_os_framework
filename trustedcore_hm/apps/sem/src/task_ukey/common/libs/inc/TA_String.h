#ifndef TA_STRING_H
#define TA_STRING_H

#include "TA_Parcel.h"

/*===========================================================================
 * struct of ta_string
 =========================================================================== */
typedef struct ta_string {
	ta_parcel_t parcel;         // parcel data ,used to storage the string data

	/*===========================================================================
	DESCRIPTION: append a ta_string
	PARAMETER:
	  @param self:[INPUT] self pointer.
	  @param str:[INPUT] append string.
	RETURN:
	  @return TA_TRUE  (ok)
	  @return TA_FALSE (error)
	NOTICE:
	  It will add '\0' automatically.
	===========================================================================*/
	TA_BOOL(*append)(struct ta_string *self, struct ta_string str);

	/*===========================================================================
	DESCRIPTION: append string pointer
	PARAMETER:
	  @param self:[INPUT] self pointer.
	  @param str:[INPUT] string pointer.
	RETURN:
	  @return TA_TRUE  (ok)
	  @return TA_FALSE (error)
	NOTICE:
	  It will add '\0' automatically.
	===========================================================================*/
	TA_BOOL(*append_p)(struct ta_string *self, const char *str);

	/*===========================================================================
	DESCRIPTION: append a char
	PARAMETER:
	  @param self:[INPUT] self pointer.
	  @param str:[INPUT] char.
	RETURN:
	  @return TA_TRUE  (ok)
	  @return TA_FALSE (error)
	NOTICE:
	  It will add '\0' automatically.
	===========================================================================*/
	TA_BOOL(*append_c)(struct ta_string *self, char c);

	/*===========================================================================
	DESCRIPTION: assign a value to the ta_string
	PARAMETER:
	  @param self:[INPUT] self pointer.
	  @param str:[INPUT] assign value of ta_sting.
	RETURN:
	  @return TA_TRUE  (ok)
	  @return TA_FALSE (error)
	NOTICE:
	  It will add '\0' automatically.
	===========================================================================*/
	TA_BOOL(*set)(struct ta_string *self, struct ta_string str);

	/*===========================================================================
	DESCRIPTION: assign a value to the ta_string
	PARAMETER:
	  @param self:[INPUT] self pointer.
	  @param str:[INPUT] assign value of string pointer.
	RETURN:
	  @return TA_TRUE  (ok)
	  @return TA_FALSE (error)
	NOTICE:
	  It will add '\0' automatically.
	===========================================================================*/
	TA_BOOL(*set_p)(struct ta_string *self, const char *str);

	/*===========================================================================
	DESCRIPTION: get the string pointer data
	PARAMETER:
	  @param self:[INPUT] self pointer.
	RETURN:
	  @return the pointer data of the string
	NOTICE:
	  none.
	===========================================================================*/
	const char *(*get)(const struct ta_string *self);

	/*===========================================================================
	DESCRIPTION: get the length of the string
	PARAMETER:
	  @param self:[INPUT] self pointer.
	RETURN:
	  @return the length of the string
	NOTICE:
	  none.
	===========================================================================*/
	uint32_t (*length)(const struct ta_string *self);
} ta_string_t;

/*===========================================================================
FUNCTION: ta_string_t create_string()
DESCRIPTION: Create a string.
PARAMETER:
  none.
RETURN:
  @return return the created string.
NOTICE:
  You should delete_string when you don't need the string anymore.
===========================================================================*/
ta_string_t create_string();

/*===========================================================================
FUNCTION: void delete_string(ta_string_t* str)
DESCRIPTION: Delete a string. In fact it will not destroy the string,
             but only free the allocate memory of the string and reset the member's value
             of the string.
             You can continue to use the string if you want.
PARAMETER:
  @param str:[INPUT] The string you want to delete.
NOTICE:
  You should delete the string when you don't need it any more to avoid memory leak.
===========================================================================*/
void delete_string(ta_string_t *str);

#endif
