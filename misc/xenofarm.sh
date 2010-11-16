#! /bin/sh

# Driver the xenofarm test compilation. Used together with
# lsh-server.pike, source-transform.sh and result-parser.pike in
# the lsh xenofarm project.

# Loosely based on the xenofarm.sh script in lyskom-server.

# Copyright 2002, 2003 Niels Möller, Lysator Academic Computer Association 
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

cfgargs=
makeargs=
MAKE=make

while [ $# -gt 0 ]
do
  case "$1" in
      --cfg)    shift; cfgargs="$1"; shift;;
      --make)   shift; makeargs="$1"; shift;;
      --make-program)   shift; MAKE="$1"; shift;;
      *)        echo $0: unsupported argument $1 >&2; exit 1;;
  esac
done

pfx=`pwd`/pfx

# Disable the liboop shared libraries, to avoid libtool-related
# problems on AIX. And disable all extra adapters, to workaround the
# broken --disable-shared handling in liboop-1.0.

oopcfgargs="-C --prefix=$pfx --disable-shared --without-adns --without-readline --without-glib --without-tcl --without-www $cfgargs"

gmpcfgargs="-C --prefix=$pfx --disable-shared $cfgargs"

cfgargs="-C --with-include-path=$pfx/include:/usr/local/include --with-lib-path=$pfx/lib:/usr/local/lib --prefix=$pfx $cfgargs"

# Fix PATH for system where the default environment is broken

# We may need /usr/ccs/bin for ar
if type ar >/dev/null ; then : ; else
    if [ -x /usr/ccs/bin/ar ] ; then
	PATH="$PATH:/usr/ccs/bin"
    fi
fi

# Export new value
export PATH

# Are we using GNU make? If so, nettle's dependency tracking won't work.
cfgdepargs=''

if make --version 2>/dev/null | grep GNU >/dev/null ; then : ; else
    cfgdepargs='--disable-dependency-tracking'
fi

rm -rf r
mkdir r
exec > r/shlog.txt 2>&1

BASE=`echo lsh-*.tar.gz | sed 's/.tar.gz$//'`
VERS=`echo "$BASE" | sed 's/^lsh-//'`

LIBOOPDIST=`echo liboop-*.tar.gz`
LIBGMPDIST=`echo gmp-*.tar.gz`

timeecho () {
    # FIXME: Don't depend on GNU date
    echo `LC_ALL=C TZ=UTC date '+%Y-%m-%d %H:%M:%S'`: "$@"
}

log () {
    echo "$@" >> r/mainlog.txt
    date >> r/mainlog.txt
}

logstart () {
    log "BEGIN $1"
}

logpass () {
    log "PASS"
}

logfail () {
    log "FAIL"
}

logwarn () {
    log "WARN $1"
}

dotask() {
    important="$1"
    task="$2"
    warnfunc="$3"
    cmd="$4"
    var=${5:-status}
    var_value=`eval echo '${'$var'}'`
    if test $var_value = good
    then
	logstart $task
        timeecho Begin $task
        if sh -c "$cmd" > r/${task}log.txt 2>&1
        then
	    if [ -z "$warnfunc" ]
	    then
	        logpass
	    else
	        $warnfunc
	    fi
        else
	    timeecho FAIL: $task
	    if [ $important = 1 ]
	    then
	        eval $var=${task}-failed
	    fi
	    logfail
	fi
    else
	echo status $var_value makes it impossible/unnecessary to perform this step \
	    > r/${task}log.txt
    fi
}

cfgwarn () {
    logfile="r/${task}log.txt"
    warnfile="r/${task}warn.txt"
    egrep -i 'warning|\(w\)' "$logfile" \
    | sed -e '/configure: WARNING: No scheme implementation found/d' \
    > "$warnfile"
    warnings=`wc -l < $warnfile`
    if test $warnings -gt 0
    then
	logwarn $warnings
    else
	rm "$warnfile"
	logpass
    fi
}

makewarn () {
    logfile="r/${task}log.txt"
    warnfile="r/${task}warn.txt"
    # Use sed -e /RX/d to get rid of selected warnings.
    egrep -i 'warning|\(w\)' "$logfile" \
    > "$warnfile"
    warnings=`wc -l < $warnfile`
    if test $warnings -gt 0
    then
	logwarn $warnings
    else
	rm "$warnfile"
	logpass
    fi
}

ckprgwarn () {
    logfile="r/${task}log.txt"
    warnfile="r/${task}warn.txt"
    failfile="r/${task}fail.txt"

    egrep -i 'warning|\(w\)|error' "$logfile" \
    > "$warnfile"
    warnings=`wc -l < $warnfile`
    if test $warnings -gt 0
    then
	egrep -i 'error' "$warnfile" \
	> "$failfile"
	if test `wc -l < $failfile` -gt 0
	then
	    logfail
	else
	    rm "$failfile"
	    logwarn $warnings
	fi
    else
	rm "$warnfile"
	logpass
    fi
}


status=good

echo 'FORMAT 2' > r/mainlog.txt

if [ -f $LIBOOPDIST ] ; then
  # Install liboop in $pfx, before trying lsh
  LIBOOPBASE=`echo $LIBOOPDIST | sed 's/.tar.gz$//'`
  liboopstatus=good
else
  liboopstatus=skip
fi

if [ -f $LIBGMPDIST ] ; then
  LIBGMPBASE=`echo $LIBGMPDIST | sed 's/.tar.gz$//'`
  # Crude check if gmp-3.1 or later is installed. If not, install i $pfx.
  libgmpstatus=good
  for d in /usr/local/include /usr/include/ ; do
    if [ -f $d/gmp.h ] ; then
      echo gmp.h location: $d/gmp.h
      if grep mpz_getlimbn $d/gmp.h ; then
        libgmpstatus=skip
      fi
      break
    fi
  done
else
  libgmpstatus=skip
fi

dotask 1 "oopunzip" "" "gzip -d $LIBOOPBASE.tar.gz" liboopstatus
dotask 1 "oopunpack" "" "tar xf $LIBOOPBASE.tar" liboopstatus
dotask 1 "oopcfg" "cfgwarn" "cd $LIBOOPBASE && ./configure $oopcfgargs" liboopstatus
dotask 1 "oopmake" "makewarn" "cd $LIBOOPBASE && $MAKE" liboopstatus
dotask 0 "oopcheck" "makewarn" "cd $LIBOOPBASE && $MAKE check" liboopstatus
dotask 1 "oopinstall" "makewarn" "cd $LIBOOPBASE && $MAKE install" liboopstatus

dotask 1 "gmpunzip" "" "gzip -d $LIBGMPBASE.tar.gz" libgmpstatus
dotask 1 "gmpunpack" "" "tar xf $LIBGMPBASE.tar" libgmpstatus
dotask 1 "gmpcfg" "cfgwarn" "cd $LIBGMPBASE && ./configure $gmpcfgargs" libgmpstatus
dotask 1 "gmpmake" "makewarn" "cd $LIBGMPBASE && $MAKE" libgmpstatus
dotask 0 "gmpcheck" "makewarn" "cd $LIBGMPBASE && $MAKE check" libgmpstatus
dotask 1 "gmpinstall" "makewarn" "cd $LIBGMPBASE && $MAKE install" libgmpstatus

dotask 1 "unzip" "" "gzip -d $BASE.tar.gz"
dotask 1 "unpack" "" "tar xf $BASE.tar"
dotask 1 "cfg" "cfgwarn" \
    "cd $BASE && ./configure $cfgargs $cfgdepargs"
dotask 1 "make" "makewarn" "cd $BASE && $MAKE $makeargs"

#
# "make check" requirements
#

dotask 1 "ckprg" "" "cd $BASE && $MAKE check"

# FIXME: run distcheck.
# A problem is that make distcheck leaves some write-protected directories that
# can't be deleted with rm -rf

# dotask 0 "ckdist" "" "cd $BASE && $MAKE distcheck"
dotask 1 "install" "" "cd $BASE && $MAKE install"

if test $status = cfg-failed
then
    argpstatus=good
    nettlestatus=good
else
    argpstatus=skip
    nettlestatus=skip
fi

dotask 1 "argpcfg" "cfgwarn" "cd $BASE/argp && ./configure $cfgargs" argpstatus
dotask 1 "argpmake" "makewarn" "cd $BASE/argp && $MAKE $makeargs" argpstatus
dotask 1 "ckargp" "" "cd $BASE/argp && $MAKE check" argpstatus

dotask 1 "nettlecfg" "cfgwarn" "cd $BASE/nettle && ./configure $cfgargs $cfgdepargs" nettlestatus
dotask 1 "nettlemake" "makewarn" "cd $BASE/nettle && $MAKE $makeargs" nettlestatus
dotask 1 "cknettle" "" "cd $BASE/nettle && $MAKE check" nettlestatus

find pfx -type f -print | sort > r/installedfiles.txt
if test `wc -l < r/installedfiles.txt` -eq 0
then
    rm r/installedfiles.txt
fi

# Collect stuff.

timeecho Collecting results

cp $BASE/config.cache r/configcache.txt
cp $BASE/config.log r/configlog.txt
cp $BASE/argp/config.log r/argpconfiglog.txt
cp $BASE/argp/config.h r/argpconfig-h.txt
cp $BASE/nettle/config.log r/nettleconfiglog.txt
cp $BASE/nettle/config.h r/nettleconfig-h.txt
cp $BASE/src/sftp/config.log r/sftpconfiglog.txt
cp $BASE/src/sftp/config.h r/sftpconfig-h.txt
cp $BASE/spki/config.log r/spkiconfiglog.txt
cp $BASE/spki/config.h r/spkiconfig-h.txt
cp $BASE/config.h r/config-h.txt

cp $LIBOOPBASE/config.cache r/oopconfigcache.txt
cp $LIBOOPBASE/config.log r/oopconfiglog.txt

cp $LIBGMPBASE/config.cache r/gmpconfigcache.txt
cp $LIBGMPBASE/config.log r/gmpconfiglog.txt

find $BASE -name core -print > r/corefiles.txt
if test `wc -l < r/corefiles.txt` -eq 0
then
    rm r/corefiles.txt
fi

env > r/environ.txt
echo $PATH > r/path.txt
makeinfo --version > r/makeinfo.txt
type makeinfo >> r/makeinfo.txt 2>&1

$MAKE --version > r/makeversion.txt 2>&1 
type $MAKE >> r/makeversion.txt

cp buildid.txt r/buildid.txt

(cd r && tar cf - *) > xenofarm_result.tar
gzip -1 xenofarm_result.tar

exit 0
