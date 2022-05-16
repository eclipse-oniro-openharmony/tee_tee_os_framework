#include <stdio.h>
#include <nl_types.h>

//__attribute__((weak, visibility("hidden")))
void *__dso_handle = (void *) 0;

// stubbed catopen function which we do not support at the moment
nl_catd catopen(const char *name, int flag)
{
	printf("Stub for catopen(). this function is not implement\n");
	*(int *)0 = 0;
	return  0;
}

// stubbed catopen function which we do not support at the moment
int catclose(nl_catd catalog)
{
	printf("Stub for catclose(). this function is not implement\n");
	*(int *)0 = 0;
	return  0;
}

// stubbed catopen function which we do not support at the moment
char *catgets(nl_catd catalog, int set_number, int message_number,
	      const char *message)
{
	printf("Stub for catgets(). this function is not implement\n");
	*(int *)0 = 0;
	return (void *) 0;
}
