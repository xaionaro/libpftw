    NAME
           pftw - parallel file tree walk
    
    SYNOPSIS
           #include <pftw.h>
    
           int pftw_init(int num_threads);
    
           int pftw(const char *dirpath,
                   int (*fn) (const char *fpath, const struct stat *sb,
                              int typeflag, struct FTW *ftwbuf, void *arg),
                   int nopenfd, int flags, void *arg);
    
           int pftw_deinit();
    
    
    DESCRIPTION
           pftw()  does  the  same  as  nftw(3), but in parallel threads [based on
           pthreads(7)].  The additional argument arg is just an  arbitrary  user-
           defined   argument.   Before   running  pftw()  it's  required  to  run
           pftw_init() where num_threads  is  a  number  of  workers  threads  for
           pftw().   Argument  nopenfd  is  ignored. Some nftw(3) flags may be not
           supported.
    
    RETURN VALUE
           Functions  pftw_init(),  pftw() and  pftw_deinit() returns 0 on success
           and errno if an error occurs.
    
    
    AUTHOR
           Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
    
    SUPPORT
           You can get support on IRC-channel in Freenode "#clsync" or on github's
           issue     tracking     system     of     the     libpftw     repository
           https://github.com/xaionaro/libpftw.
    
    
    SEE ALSO
           nftw(3)
