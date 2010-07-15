#include "qword.h"
#include "x86_imm.h"


unsigned int x86_imm_signsized( unsigned char * buf, size_t buf_len,
				void *dest, unsigned int size ) {
	signed char *cp = (unsigned char *) dest;
	signed short *sp = (unsigned short *) dest;
	signed long *lp = (unsigned long *) dest;
	qword *qp = (qword *) dest;

	if ( size > buf_len ) {
		return 0;
	}

	/* Copy 'size' bytes from *buf to *op
	 * return number of bytes copied */
	switch (size) {
		case 1:		/* BYTE */
			*cp =  *((signed char *) buf);
			break;
		case 2:		/* WORD */
			*sp =  *((signed short *) buf);
			break;
		case 6:
		case 8:		/* QWORD */
			*qp = *((qword *) buf);
			break;
		case 4:		/* DWORD */
		default:
			*lp = *((signed long *) buf);
			break;
	}
	return (size);
}

unsigned int x86_imm_sized( unsigned char * buf, size_t buf_len, void *dest,
			    unsigned int size ) {
	unsigned char *cp = (unsigned char *) dest;
	unsigned short *sp = (unsigned short *) dest;
	unsigned long *lp = (unsigned long *) dest;
	qword *qp = (qword *) dest;

	if ( size > buf_len ) {
		return 0;
	}

	/* Copy 'size' bytes from *buf to *op
	 * return number of bytes copied */
	switch (size) {
		case 1:		/* BYTE */
			*cp =  *((unsigned char *) buf);
			break;
		case 2:		/* WORD */
			*sp =  *((unsigned short *) buf);
			break;
		case 6:
		case 8:		/* QWORD */
			*qp = *((qword *) buf);
			break;
		case 4:		/* DWORD */
		default:
			*lp = *((unsigned long *) buf);
			break;
	}

	return (size);
}

