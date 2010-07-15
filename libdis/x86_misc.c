#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libdis.h"
#include "ia32_insn.h"
#include "ia32_settings.h"
extern ia32_settings_t ia32_settings;

#ifdef _MSC_VER
        #define snprintf        _snprintf
        #define inline          __inline
#endif


/* =========================================================== INIT/TERM */
static DISASM_REPORTER __x86_reporter_func = NULL;

int x86_init( enum x86_options options, DISASM_REPORTER reporter )
{
        ia32_settings.options = options;
        __x86_reporter_func = reporter;

        return( 1 );
}

void x86_set_options( enum x86_options options ){
        ia32_settings.options = options;
}

enum x86_options x86_get_options( void ) {
        return( ia32_settings.options );
}

int x86_cleanup( void )
{
        return( 1 );
}

/* =========================================================== ERRORS */
void x86_report_error( enum x86_report_codes code, void *arg ) {
        if ( __x86_reporter_func ) {
                (*__x86_reporter_func)(code, arg);
        }
}


/* =========================================================== MISC */
unsigned int x86_endian(void)        { return( ia32_settings.endian );  }
unsigned int x86_addr_size(void)     { return( ia32_settings.sz_addr ); }
unsigned int x86_op_size(void)       { return( ia32_settings.sz_oper ); }
unsigned int x86_word_size(void)     { return( ia32_settings.sz_word ); }
unsigned int x86_max_inst_size(void) { return( ia32_settings.max_insn ); }
unsigned int x86_sp_reg(void)        { return( ia32_settings.id_sp_reg );      }
unsigned int x86_fp_reg(void)        { return( ia32_settings.id_fp_reg );      }
unsigned int x86_ip_reg(void)        { return( ia32_settings.id_ip_reg );      }
