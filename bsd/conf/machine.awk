BEGIN {
	hdr =	"#if\tm68k\n"				\
		"#import <m68k/%s/%s>\n"	\
		"#endif\tm68k\n"			\
		"#if\tm88k\n"				\
		"#import <m88k/%s/%s>\n"	\
		"#endif\tm88k\n"
	hdr =	"#import <m68k/%s/%s>\n"
}
/\.h$/ {
	ofile = sprintf("%s/%s", loc, $1);
	printf(hdr, dir, $1, dir, $1) > ofile;
	continue;
}

{
	dir = $1; loc = $2;
}
