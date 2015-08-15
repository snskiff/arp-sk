#ifndef _SK_LIBPORTABLE_
#define _SK_LIBPORTABLE_

#ifdef HAVE_CONFIG_H
#include "../include/config.h"
#endif

#ifndef HAVE_GETOPT
#include "getopt.h"
#endif

#ifndef HAVE_GETOPT_LONG
#include "getopt.h"
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_INET_NTOP
 const char *inet_ntop(int af, const void *src, char *dst, size_t cnt);
#endif

#ifndef HAVE_STRERROR
char *strerror(int errnum);
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2);
#endif



#endif /* _SK_LIBPORTABLE_ */
