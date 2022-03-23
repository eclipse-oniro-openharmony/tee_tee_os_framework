/****************************************************************************
 *
 * ftstdlib.h
 *
 *   ANSI-specific library and header configuration file (specification
 *   only).
 *
 * Copyright (C) 2002-2020 by
 * David Turner, Robert Wilhelm, and Werner Lemberg.
 *
 * This file is part of the FreeType project, and may only be used,
 * modified, and distributed under the terms of the FreeType project
 * license, LICENSE.TXT.  By continuing to use, modify, or distribute
 * this file you indicate that you have read the license and
 * understand and accept it fully.
 *
 */


  /**************************************************************************
   *
   * This file is used to group all `#includes` to the ANSI~C library that
   * FreeType normally requires.  It also defines macros to rename the
   * standard functions within the FreeType source code.
   *
   * Load a file which defines `FTSTDLIB_H_` before this one to override it.
   *
   */


#ifndef FTSTDLIB_H_
#define FTSTDLIB_H_



#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
extern void free(void *FirstByte);
#define ft_ptrdiff_t  ptrdiff_t
#define isspace(c) (c == ' ' ? 1 : 0)
#define isdigit(c) ((c >= '0' && c <= '9') ? 1 : 0)
#define isalpha(c) (((c >= 'a' && c <= 'z') || c >= 'A' && c <= 'Z') ? 1 : 0)
#define isupper(c) ((c >= 'A' && c <= 'Z') ? 1 : 0)

  /**************************************************************************
   *
   *                          integer limits
   *
   * `UINT_MAX` and `ULONG_MAX` are used to automatically compute the size of
   * `int` and `long` in bytes at compile-time.  So far, this works for all
   * platforms the library has been tested on.
   *
   * Note that on the extremely rare platforms that do not provide integer
   * types that are _exactly_ 16 and 32~bits wide (e.g., some old Crays where
   * `int` is 36~bits), we do not make any guarantee about the correct
   * behaviour of FreeType~2 with all fonts.
   *
   * In these cases, `ftconfig.h` will refuse to compile anyway with a
   * message like 'couldn't find 32-bit type' or something similar.
   *
   */


#include <limits.h>

#define FT_CHAR_BIT    CHAR_BIT
#define FT_USHORT_MAX  USHRT_MAX
#define FT_INT_MAX     INT_MAX
#define FT_INT_MIN     INT_MIN
#define FT_UINT_MAX    UINT_MAX
#define FT_LONG_MIN    LONG_MIN
#define FT_LONG_MAX    LONG_MAX
#define FT_ULONG_MAX   ULONG_MAX
#define FT_SHRT_MAX    SHRT_MAX
#define FT_LONG_MAX    LONG_MAX


  /**************************************************************************
   *
   *                character and string processing
   *
   */


void *memchr(const void *s, int c, size_t n);

#define ft_memchr   memchr
#define ft_memcmp   memcmp
#define ft_memcpy   memcpy
#define ft_memmove  memmove
#define ft_memset   memset
#define ft_strcat   strcat
#define ft_strcmp   strcmp
#define ft_strcpy   strcpy
#define ft_strlen   strlen
#define ft_strncmp  strncmp
#define ft_strncpy  strncpy
#define ft_strrchr  strrchr
#define ft_strstr   strstr

#ifndef PP_DEBUG
#define PP_DEBUG 0
#if PP_DEBUG
#define plog(fmt, args ...)                           \
    ({                                                \
        uart_printf_func("ppdebug:%s(%d) " fmt "\n",  \
                         __func__, __LINE__, ##args); \
    })
#else
#define plog(fmt, args ...)                           \
    ({                                                \
        ;                                             \
    })
#endif
#endif

  /**************************************************************************
   *
   *                          file handling
   *
   */


#define FT_FILE int
long ft_ftell(FT_FILE *fd);
FT_FILE *ft_fopen(const char *name, char *mode);
int ft_fread(char *buffer, int len, int numbers, FT_FILE *fd);
int ft_fclose(FT_FILE *fd);
int ft_fseek(FT_FILE *stream, long offset, int whence);

#ifndef EMULATOR_TUI
#define FT_SEEK_SET 0
#define FT_SEEK_END 2
#endif
void tui_file_close(int fd);
/*
#define FT_FILE     FILE
#define ft_fclose   fclose
#define ft_fopen    fopen
#define ft_fread    fread
#define ft_fseek    fseek
#define ft_ftell    ftell
#define ft_sprintf  sprintf
*/

  /**************************************************************************
   *
   *                            sorting
   *
   */



#define ft_qsort  qsort


  /**************************************************************************
   *
   *                       memory allocation
   *
   */
unsigned char *ftmalloc(unsigned int sz);

#define ft_scalloc   calloc
#define ft_sfree     ftfree
#define ft_smalloc   ftmalloc
#define ft_srealloc  realloc


  /**************************************************************************
   *
   *                         miscellaneous
   *
   */


long  atol(const char* nptr);
#define ft_strtol  strtol
#define ft_getenv  getenv


  /**************************************************************************
   *
   *                        execution control
   *
   */


#include <setjmp.h>

#define ft_jmp_buf     jmp_buf  /* note: this cannot be a typedef since  */
                                /*       `jmp_buf` is defined as a macro */
                                /*       on certain platforms            */

#define ft_longjmp     longjmp
#define ft_setjmp( b ) setjmp( *(ft_jmp_buf*) &(b) ) /* same thing here */


  /* The following is only used for debugging purposes, i.e., if   */
  /* `FT_DEBUG_LEVEL_ERROR` or `FT_DEBUG_LEVEL_TRACE` are defined. */

 char * strchr(const char *p, int ch);
 char * strrchr(const char *str, int ch);
#endif /* FTSTDLIB_H_ */


/* END */
