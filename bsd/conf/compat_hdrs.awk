BEGIN {
	hdr =	"#warning Compatibility header file imported, use <%s/%s>\n" \
		"#import\t<%s/%s>\n"
}
/^#/ {		# skip comments in data file
	continue;
}
/COMPATMACHINE/ {
	ofile = sprintf("compat/%s/%s", $2, $3);
	printf("#import\t<machine/compat_%s>\n", $3) > ofile
	printf(hdr, $1, $3, $1, $3) > ofile;
	continue;
}
/DELETED/ {
	ofile = sprintf("compat/%s/%s", $2, $3);
	printf("#error This file has been removed\n") > ofile;
	continue;
}
{
	ofile = sprintf("compat/%s/%s", $2, $3);
	printf(hdr, $1, $NF, $1, $NF) > ofile;
}
