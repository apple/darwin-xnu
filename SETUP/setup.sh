setup_tmp=`mktemp -d -t setup`
printenv | sort > "${setup_tmp}/orig"
make print_exports | grep -E -v '^(MAKE|MFLAGS|SHLVL)' > "${setup_tmp}/exports"
eval `comm -13 "${setup_tmp}/orig" "${setup_tmp}/exports" | sed 's,^\(.*\)$,export "\1",'`


