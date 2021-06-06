#ifndef SDK_BINDINGS_C_SERVER_DBGMISC
#define SDK_BINDINGS_C_SERVER_DBGMISC

#define DEBUG

typedef enum DBGRET
{
    DBGRET_SUCCESS = 0, DBGRET_EINIT, DBGRET_ERELEASE, DBGRET_EGENERAL, DBGRET_ESHELL, DBGRET_EOUTOFMEM, DBGRET_EMPTYLINE, DBGRET_TERMINATE, DBGRET_EPARSE, DBGRET_ECMDFAIL, DBGRET_EARGTOOFEW, DBGRET_EARGTOOMANY, DBGRET_ENULLPTR,
} DBGRET;

#ifdef DEBUG
#define debug_printf(...) {printf("[DEBUG] " __VA_ARGS__); printf("\n");}
#define debug_printf_normal(...) printf(__VA_ARGS__)
#define debug_print_tag() printf("[DEBUG] ")
#else
#define debug_printf(...)
#define debug_printf_normal(...)
#define debug_print_tag()
#endif

#define RT_ELEMENTS(aArray)                     ( sizeof(aArray) / sizeof((aArray)[0]) )

#endif /* SDK_BINDINGS_C_SERVER_DBGMISC */
