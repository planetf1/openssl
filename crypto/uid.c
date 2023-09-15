/*
 * Copyright 2001-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* NOTE requires libcap-dev / libcap-devel for compiling */
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#ifdef OPENSSL_NETCAP_ALLOW_ENV
#include <sys/capability.h>
#include <sys/types.h>
#endif

#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI) || defined(__wasi__)

int OPENSSL_issetugid(void)
{
    return 0;
}

#elif defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ > 2) || defined(__DragonFly__) || (defined(__GLIBC__) && defined(__FreeBSD_kernel__))

# include <unistd.h>

int OPENSSL_issetugid(void)
{
    return issetugid();
}

#else

# include <unistd.h>
# include <sys/types.h>

# if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#  if __GLIBC_PREREQ(2, 16)
#   include <sys/auxv.h>
#   define OSSL_IMPLEMENT_GETAUXVAL
#  endif
# elif defined(__ANDROID_API__)
/* see https://developer.android.google.cn/ndk/guides/cpu-features */
#  if __ANDROID_API__ >= 18
#   include <sys/auxv.h>
#   define OSSL_IMPLEMENT_GETAUXVAL
#  endif
# endif

/*
 * Allows for slightly more permissive environment variable retrieval. Requires capability checks
 */
#ifdef OPENSSL_NETCAP_ALLOW_ENV
/*
 * Tests to see if a process has ONLY the requested capability
 */
int HasOnlyCapability(int capability)
{
    cap_t capTest; 
    cap_t capProc;
    int   cmp_rc=0;
    int   set_rc;
    cap_value_t cap_list[CAP_LAST_CAP+1];


    /* Make our capability to test against.  */
    cap_list[0] = capability;
    capTest = cap_init();
    if (capTest !=NULL)
    {
        set_rc=cap_set_flag(capTest,CAP_EFFECTIVE,1,&cap_list,CAP_SET);
        if (set_rc==0)
        {
            // get our actual capabilities
            capProc = cap_get_proc();
            if (capProc != NULL)
            {
                // 0 for exact match
                cmp_rc=cap_compare(capProc,capTest);
                cap_free(capProc);
            }
        }
        cap_free(capTest);
    }
    // true if cmp_rc is 0
    return (cmp_rc==0);
}
#endif

int OPENSSL_issetugid(void)
{
# ifdef OSSL_IMPLEMENT_GETAUXVAL
#   ifdef OPENSSL_NETCAP_ALLOW_ENV
      /* AT_SECURE is set if privileged. We allow this if ONLY NET_BIND capability set */
      int at_secure = getauxval(AT_SECURE);
      int has_net_bind_service = HasOnlyCapability(CAP_NET_BIND_SERVICE);
      return at_secure != 0 && !has_net_bind_service;
      //return getauxval(AT_SECURE) != 0 && !HasOnlyCapability(CAP_NET_BIND_SERVICE);
#   else
      return getauxval(AT_SECURE) != 0;
#   endif
# else
    return getuid() != geteuid() || getgid() != getegid();
# endif
}
#endif