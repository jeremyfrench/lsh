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
while [ $# -gt 0 ]
do
  case "$1" in
      --cfg)    shift; cfgargs="$1"; shift;;
      --make)   shift; makeargs="$1"; shift;;
      *)        echo $0: unsupported argument $1 >&2; exit 1;;
  esac
done

# Fix PATH for system where the default environment is broken

# We may need /usr/local/bin to get GNU make
if make --version | grep GNU >/dev/null ; then : ; else
    if /usr/local/bin/make | grep GNU >/dev/null ; then
	PATH="/usr/local/bin:$PATH"
    fi
fi

# We may need /usr/ccs/bin for ar
if type ar >/dev/null ; then : ; else
    if [ -x /usr/ccs/bin/ar ] ; then
	PATH="$PATH:/usr/ccs/bin"
    fi
fi

rm -rf r
mkdir r
exec > r/shlog.txt 2>&1

BASE=`echo lsh-*.tar.gz | sed 's/.tar.gz$//'`
VERS=`echo "$BASE" | sed 's/^lsh-//'`

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
    if test $status = good
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
	        status=${task}-failed
	    fi
	    logfail
	fi
    else
	echo status $status makes it impossible to perform this step \
	    > r/${task}log.txt
    fi
}

cfgwarn () {
    egrep -i 'warning|\(w\)' r/cfglog.txt \
    > r/cfgwarn.txt
    warnings=`wc -l < r/cfgwarn.txt`
    if test $warnings -gt 0
    then
	logwarn $warnings
    else
	rm r/cfgwarn.txt
	logpass
    fi
}

makewarn () {
    # Use sed -e /RX/d to get rid of selected warnings.
    egrep -i 'warning|\(w\)' r/makelog.txt \
    > r/makewarn.txt
    warnings=`wc -l < r/makewarn.txt`
    if test $warnings -gt 0
    then
	logwarn $warnings
    else
	rm r/makewarn.txt
	logpass
    fi
}

ckprgwarn () {
    egrep -i 'warning|\(w\)|error' r/ckprglog.txt \
    > r/ckprgwarn.txt
    warnings=`wc -l < r/ckprgwarn.txt`
    if test $warnings -gt 0
    then
	egrep -i 'error' r/ckprgwarn.txt \
	> r/ckprgfail.txt
	if test `wc -l < r/ckprgfail.txt` -gt 0
	then
	    logfail
	else
	    rm r/ckprgfail.txt
	    logwarn $warnings
	fi
    else
	rm r/ckprgwarn.txt
	logpass
    fi
}


pfx=`pwd`/pfx

status=good

echo 'FORMAT 2' > r/mainlog.txt

dotask 1 "unzip" "" "gzip -d $BASE.tar.gz"
dotask 1 "unpack" "" "tar xf $BASE.tar"
dotask 1 "cfg" "cfgwarn" \
    "cd $BASE && ./configure -C --with-include-path=/usr/local/include --with-lib-path=/usr/local/lib --prefix=$pfx $cfgargs"
dotask 1 "make" "makewarn" "cd $BASE && make $makeargs"

#
# "make check" requirements
#

dotask 0 "ckprg" "" "cd $BASE && make check"

# FIXME: run distcheck.
# FIXME: compare the contents of the distcheck-generated tar file
# with the one we distributed.
# A problem is that make distcheck leaves some write-protected directories that
# can't be deleted with rm -rf

# dotask 0 "ckdist" "" "cd $BASE && make distcheck"
dotask 1 "install" "" "cd $BASE && make install"

find pfx -type f -print | sort > r/installedfiles.txt
if test `wc -l < r/installedfiles.txt` -eq 0
then
    rm r/installedfiles.txt
fi

# Collect stuff.

timeecho Collecting results

mv $BASE/config.cache r/configcache.txt
mv $BASE/config.log r/configlog.txt
mv $BASE/src/argp/config.log r/argpconfig.log
mv $BASE/src/nettle/config.log r/nettleconfig.log
mv $BASE/src/sftp/config.log r/sftpconfig.log
mv $BASE/src/spki/config.log r/spkiconfig.log
mv $BASE/config.h r/config-h.txt

find $BASE -name core -print > r/corefiles.txt
if test `wc -l < r/corefiles.txt` -eq 0
then
    rm r/corefiles.txt
fi


env > r/environ.txt
echo $PATH > r/path.txt
makeinfo --version > r/makeinfo.txt
type makeinfo >> r/makeinfo.txt 2>&1

mv buildid.txt r/buildid.txt

(cd r && tar cf - *) > xenofarm_result.tar
gzip -1 xenofarm_result.tar

exit 0
