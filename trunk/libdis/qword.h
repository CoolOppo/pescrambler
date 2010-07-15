#ifndef LIBDISASM_QWORD_H
#define LIBDISASM_QWORD_H

/* platform independent data types */

#ifdef _MSC_VER
	typedef __int64         qword;
#else
	typedef long long       qword;
#endif

#endif
