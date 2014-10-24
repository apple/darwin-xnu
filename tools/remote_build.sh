#!/bin/bash
#
# Script that rsyncs a source/build tree to a remote server, performs a build,
# and copies the result back
#

# This script is invoked instead of the initial recursive make(1) in ./Makefile.
# First it must cache all binaries that might be used during the build by
# calling "make print_exports" (any target would work) with an overriden xcrun(1)
# which caches tools an SDKs into ./BUILD/obj/BuildTools. When the combined
# source+build tree is rsync-ed to the remote server, we run a script to
# re-initiate the build using an overriden xcrun(1) which hands back
# cached tools in ./BUILD/obj/BuildTools instead of whatever Xcode tools are on
# the remote system (or if no Xcode tools are installed remotely). Finally,
# the build results are copied back locally.
#

function die() {
    echo "$1" 1>&2
    exit 1
}


TARGET=
declare -a ARGS
declare -a REMOTEARGS
index=0
for arg in "$@"; do
    case $arg in
	_REMOTEBUILD_TARGET=*)
	    TARGET=`echo $arg | awk -F= '{print $2}'`
	    continue
	    ;;
	_REMOTEBUILD_MAKE=*)
	    MAKE=`echo $arg | awk -F= '{print $2}'`
	    continue
	    ;;
	REMOTEBUILD=*)
	    # Don't restart another remote build remotely
	    ;;
	SRCROOT=*)
	    continue
	    ;;
	OBJROOT=*)
	    continue
	    ;;
	SYMROOT=*)
	    continue
	    ;;
	DSTROOT=*)
	    continue
	    ;;
	CCHROOT=*)
	    continue
	    ;;
	RC_XBS=*)
	    # Remote build isn't chrooted or special in any way
	    arg="VERBOSE=YES"
	    continue
	    ;;
	VERBOSE=YES)
	    set -x
	    ;;
    esac
    ARGS[$index]="$arg"
    REMOTEARGS[$index]="\"$arg\""
    index=$(($index+1))
done


ARGS[$index]="REMOTEBUILD="
REMOTEARGS[$index]="\"REMOTEBUILD=\""

# For some targets like installsrc, we can't to a remote build
SKIPREMOTE=0
case $TARGET in
    clean)
	SKIPREMOTE=1
	;;
    installsrc)
	SKIPREMOTE=1
	;;
    installopensource)
	SKIPREMOTE=1
	;;
    cscope)
	SKIPREMOTE=1
	;;
    tags)
	SKIPREMOTE=1
	;;
    help)
	SKIPREMOTE=1
	;;
esac

if [ $SKIPREMOTE -eq 1 ]; then
    exec "$MAKE" "$TARGET" "${ARGS[@]}"
fi

SRC="$(pwd -P)"
SRCNAME="$(basename $SRC)"

# Pick up build locations passed in the environment
OBJROOT="${OBJROOT}"
SYMROOT="${SYMROOT}"
DSTROOT="${DSTROOT}"

if [ -z "${OBJROOT}" ]; then
    die "OBJROOT not set in environment"
fi
mkdir -p "${OBJROOT}" || die "Could not create ${OBJROOT}"

if [ -z "${SYMROOT}" ]; then
    die "SYMROOT not set in environment"
fi
mkdir -p "${SYMROOT}" || die "Could not create ${SYMROOT}"

if [ -z "${DSTROOT}" ]; then
    die "DSTROOT not set in environment"
fi
mkdir -p "${DSTROOT}" || die "Could not create ${DSTROOT}"

if [ "$REMOTEBUILD" = "$SPECIALREMOTEBUILD" ]; then
    :
else
    DOINSTALLSRC=0
    REMOTE_SRCREL="./"
    BUILDTOOLSDIR="$OBJROOT"
    REMOTE_BUILDTOOLSREL="./BUILD/obj"
    BUILDSCRIPTDIR="$OBJROOT"
    REMOTE_BUILDSCRIPTREL="./BUILD/obj"
    BUILDSCRIPTNAME="build.sh"
    if [ ! -d "${OBJROOT}/SETUP" ]; then
	RSYNC_ARGS="--delete-excluded"
    else
	RSYNC_ARGS=""
    fi
    if [ ! -e "${SYMROOT}/" ]; then
	RSYNC_DELETE_SYMROOT=1
    else
	RSYNC_DELETE_SYMROOT=0
    fi
    if [ ! -e "${DSTROOT}/" ]; then
	RSYNC_DELETE_DSTROOT=1
    else
	RSYNC_DELETE_DSTROOT=0
    fi
    TARBUILDDIRS=0
fi

echo "Caching build tools..." 1>&2
mkdir -p "${BUILDTOOLSDIR}" || die "Could not create BUILDTOOLSDIR"
$MAKE print_exports "${ARGS[@]}" XCRUN="${SRC}/tools/xcrun_cache.sh -c \"${BUILDTOOLSDIR}\"" >/dev/null || die "Could not cache build tools"

# Cache the make(1) binary itself
MAKE_SDKROOT=`"${SRC}/tools/xcrun_cache.sh" -u "${BUILDTOOLSDIR}" -sdk / -show-sdk-path`
"${SRC}/tools/xcrun_cache.sh" -c "${BUILDTOOLSDIR}" -sdk "${MAKE_SDKROOT}" -find make >/dev/null || die "Could not cache make"

# Create a canned build script that can restart the build on the remote server.
mkdir -p "${BUILDSCRIPTDIR}" || die "Could not create BUILDSCRIPTDIR"
cat > "${BUILDSCRIPTDIR}/${BUILDSCRIPTNAME}" <<EOF
#!/bin/sh
mkdir -p /private/tmp
mkdir -p /private/var/tmp
mkdir -p "\${TMPDIR}"
cd "${REMOTE_SRCREL}"
mkdir -p ./BUILD/obj
mkdir -p ./BUILD/sym
mkdir -p ./BUILD/dst
MAKE=\`\$PWD/tools/xcrun_cache.sh -u "\$PWD/${REMOTE_BUILDTOOLSREL}" -sdk / -find make\`
if [ -z "\${MAKE}" ]; then exit 1; fi
\${MAKE} ${TARGET} ${REMOTEARGS[@]} XCRUN="\$PWD/tools/xcrun_cache.sh -u \"\$PWD/${REMOTE_BUILDTOOLSREL}\""
ret=\$?
if [ \$ret -eq 0 ]; then
if [ ${TARBUILDDIRS} -eq 1 ]; then
tar jcf ./BUILD/obj.tar.bz2 --exclude=\*.o --exclude=\*.cpo --exclude=\*.d --exclude=\*.cpd --exclude=\*.non_lto --exclude=\*.ctf --exclude=conf -C ./BUILD/obj . || exit 1
tar jcf ./BUILD/sym.tar.bz2 -C ./BUILD/sym . || exit 1
tar jcf ./BUILD/dst.tar.bz2 -C ./BUILD/dst . || exit 1
fi
fi
exit \$ret
EOF
chmod a+x "${BUILDSCRIPTDIR}/${BUILDSCRIPTNAME}"
#echo "Build script is:"
#cat "${BUILDSCRIPTDIR}/${BUILDSCRIPTNAME}"

mkdir -p "${BUILDTOOLSDIR}/empty"

if [ "$REMOTEBUILD" = "$SPECIALREMOTEBUILD" ]; then
    :
else

    REMOTEBUILD="$REMOTEBUILD"
    REMOTEBUILDPATH="$REMOTEBUILDPATH"

    if [ -z "$REMOTEBUILDPATH" ]; then
	WHOAMI=`whoami`
	case "${REMOTEBUILD}" in
	    *@*)
		WHOAMI=`echo "${REMOTEBUILD}" | awk -F@ '{print $1}'`
		;;
	esac
	REMOTEBUILDPATH="/tmp/$WHOAMI"
    fi

# Construct a unique remote path
    eval `stat -s "${SRC}"`

    REMOTEBUILDPATH="${REMOTEBUILDPATH}/$st_ino/${SRCNAME}/"
    echo "Remote path is ${REMOTEBUILD}:${REMOTEBUILDPATH}" 1>&2

    ssh $REMOTEBUILD "mkdir -p \"${REMOTEBUILDPATH}/BUILD/\"{obj,sym,dst}" || die "Could not make remote build directory"

    # Copy source only
    rsync -azv --delete --exclude=\*~ --exclude=.svn --exclude=.git --exclude=/BUILD . $REMOTEBUILD:"${REMOTEBUILDPATH}" || die "Could not rsync source tree"

    # Copy partial OBJROOT (just build tools and build script), and optionally delete everything else
    rsync -azv --delete $RSYNC_ARGS --include=/build.sh --include=/BuildTools --include=/BuildTools/\*\* --exclude=\* "${OBJROOT}/" $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/obj/" || die "Could not rsync build tree"

    # Delete remote SYMROOT if it has been deleted locally
    if [ "$RSYNC_DELETE_SYMROOT" -eq 1 ]; then
	rsync -azv --delete "${BUILDTOOLSDIR}/empty/" $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/sym/" || die "Could not rsync delete SYMROOT"
    fi

    # Delete remote DSTROOT if it has been deleted locally
    if [ "$RSYNC_DELETE_DSTROOT" -eq 1 ]; then
	rsync -azv --delete "${BUILDTOOLSDIR}/empty/" $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/dst/" || die "Could not rsync delete DSTROOT"
    fi

    # Start the build
    echo ssh $REMOTEBUILD "/bin/bash -c 'cd \"${REMOTEBUILDPATH}\" && ${REMOTE_BUILDSCRIPTREL}/${BUILDSCRIPTNAME}'" 1>&2
    ssh $REMOTEBUILD "/bin/bash -c 'cd \"${REMOTEBUILDPATH}\" && ${REMOTE_BUILDSCRIPTREL}/${BUILDSCRIPTNAME}'" || die "Could not complete remote build"

    # Copy back build results except for object files (which might be several GB)
    echo "Copying results back..."
    rsync -azv --no-o --no-g --exclude=\*.o --exclude=\*.cpo --exclude=\*.d --exclude=\*.cpd --exclude=\*.non_lto --exclude=\*.ctf --exclude=conf $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/obj/" "${OBJROOT}/" || die "Could not rsync build results"
    rsync -azv --no-o --no-g $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/sym/" "${SYMROOT}/" || die "Could not rsync build results"
    rsync -azv --no-o --no-g $REMOTEBUILD:"${REMOTEBUILDPATH}/BUILD/dst/" "${DSTROOT}/" || die "Could not rsync build results"

fi

exit 0
