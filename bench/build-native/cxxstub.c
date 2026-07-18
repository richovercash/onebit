#include <string.h>
#include <ctype.h>

/* --- libc++ base-class symbols not exported by the phone's platform libc++
 * (referenced by the prebuilt barretenberg archive; not called on our path) */
long long _ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE7seekposENS_4fposI11__mbstate_tEEj(void){return -1;}
long long _ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj(void){return -1;}

/* --- glibc-isms the archive references but bionic lacks --- */
int bcmp(const void *a, const void *b, size_t n){ return memcmp(a, b, n); }
int __res_init(void){ return 0; }

/* bionic exposes errno via __errno(); glibc callers want __errno_location(). */
extern volatile int *__errno(void);
int *__errno_location(void){ return (int*)__errno(); }

/* glibc __ctype_* : tables indexed [-128,255]. Build real ASCII tables so any
 * isspace/isdigit-style use during parsing stays correct. */
static unsigned short ctb[384];
static int cttol[384];
static int cttou[384];
static const unsigned short *ctb_p   = ctb   + 128;
static const int           *cttol_p = cttol + 128;
static const int           *cttou_p = cttou + 128;

__attribute__((constructor)) static void init_ctype(void){
    for (int i = -128; i < 256; i++){
        unsigned short m = 0;
        int c = i & 0xff;
        if (i >= 0) {
            if (isupper(c)) m |= 0x0100;
            if (islower(c)) m |= 0x0200;
            if (isalpha(c)) m |= 0x0400;
            if (isdigit(c)) m |= 0x0800;
            if (isxdigit(c))m |= 0x1000;
            if (isspace(c)) m |= 0x2000;
            if (isprint(c)) m |= 0x4000;
            if (isgraph(c)) m |= 0x8000;
            if (c == ' ' || c == '\t') m |= 0x0001; /* blank */
            if (iscntrl(c)) m |= 0x0002;
            if (ispunct(c)) m |= 0x0004;
            if (isalnum(c)) m |= 0x0008;
        }
        ctb[128 + i]   = m;
        cttol[128 + i] = (i >= 0) ? tolower(c) : i;
        cttou[128 + i] = (i >= 0) ? toupper(c) : i;
    }
}
const unsigned short **__ctype_b_loc(void){ return &ctb_p; }
const int **__ctype_tolower_loc(void){ return &cttol_p; }
const int **__ctype_toupper_loc(void){ return &cttou_p; }
