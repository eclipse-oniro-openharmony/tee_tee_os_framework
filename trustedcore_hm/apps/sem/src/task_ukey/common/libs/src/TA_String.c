#include "TA_String.h"
#include "TA_BasicLibs.h"


#define STRING_ALLOC_SIZE 10
#define STRING_END_CHAR_LENGHT 1
#define STRING_END_CHAR '\0'

/*===========================================================================
FUNCTION: TA_BOOL append(ta_string_t* self, ta_string_t str)
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
TA_BOOL append(ta_string_t *self, ta_string_t str)
{
	uint32_t length = get_parcel_data_size(&str.parcel);
	if (NULL != self && length > 0) {
		// remove '\0'
		parcel_pop_back(&self->parcel, STRING_END_CHAR_LENGHT);
		// append string(include '\0')
		return self->append_p(self, get_parcel_data(&str.parcel));
	}

	return TA_FALSE;
}

/*===========================================================================
FUNCTION: TA_BOOL append_p(ta_string_t* self, const char* str)
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
TA_BOOL append_p(ta_string_t *self, const char *str)
{
	if (NULL != self && str != NULL) {
		// remove '\0'
		parcel_pop_back(&self->parcel, STRING_END_CHAR_LENGHT);
		// append string (include '\0')
		return parcel_write(&self->parcel, (void *)str, TA_Strlen(str) + 1);
	}

	return TA_FALSE;
}

/*===========================================================================
FUNCTION: TA_BOOL append_c(ta_string_t* self, char c)
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
TA_BOOL append_c(ta_string_t *self, char c)
{
	if (NULL != self && c != STRING_END_CHAR) {
		// remove '\0'
		parcel_pop_back(&self->parcel, STRING_END_CHAR_LENGHT);

		if (parcel_write_int8(&self->parcel, c)) {
			return parcel_write_int8(&self->parcel, (uint32_t)STRING_END_CHAR);
		}
	}

	return TA_FALSE;
}

/*===========================================================================
FUNCTION: TA_BOOL set(ta_string_t* self, ta_string_t str)
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
TA_BOOL set(ta_string_t *self, ta_string_t str)
{
	if (NULL != self) {
		delete_parcel(&self->parcel);
		return self->append(self, str);
	}

	return TA_FALSE;
}

/*===========================================================================
FUNCTION: TA_BOOL set_p(ta_string_t* self, const char* str)
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
TA_BOOL set_p(ta_string_t *self, const char *str)
{
	if (NULL != self) {
		delete_parcel(&self->parcel);
		return self->append_p(self, str);
	}

	return TA_FALSE;
}

/*===========================================================================
FUNCTION: const char* get(const ta_string_t* self)
DESCRIPTION: get the string pointer data
PARAMETER:
  @param self:[INPUT] self pointer.
RETURN:
  @return the pointer data of the string
NOTICE:
  none.
===========================================================================*/
const char *get(const ta_string_t *self)
{
	if (NULL == self) {
		return NULL;
	}

	return get_parcel_data(&self->parcel);

}

/*===========================================================================
FUNCTION: uint32_t length(const ta_string_t* self)
DESCRIPTION: get the length of the string
PARAMETER:
  @param self:[INPUT] self pointer.
RETURN:
  @return the length of the string
NOTICE:
  none.
===========================================================================*/
uint32_t length(const ta_string_t *self)
{
	if (NULL == self) {
		return 0;
	} else {
		uint32_t length = get_parcel_data_size(&self->parcel);
		if (length > 0) {
			return length - STRING_END_CHAR_LENGHT;
		} else {
			return 0;
		}
	}
}

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
ta_string_t create_string()
{
	ta_string_t str;
	str.parcel = create_parcel(0, STRING_ALLOC_SIZE);

	str.append = append;
	str.append_p = append_p;
	str.append_c = append_c;
	str.set = set;
	str.set_p = set_p;
	str.get = get;
	str.length = length;

	parcel_write_int8(&str.parcel, STRING_END_CHAR);
	return str;
}

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
void delete_string(ta_string_t *str)
{
	if (NULL != str) {
		delete_parcel(&str->parcel);
	}
}

