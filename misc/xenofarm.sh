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

rm -rf r
mkdir r
exec > r/shlog.txt 2>&1

BASE=`echo lsh-*.tar.gz | sed 's/.tar.gz$//'`
VERS=`echo "$BASE" | sed 's/^lsh-//'`

timeecho () {
    echo `TZ=UTC date '+%Y-%m-%d %H:%M:%S'`: "$@"
}

log () {
    echo "$@" >> r/mainlog.txt
    date >> r/mainlog.txt
}

dotask() {
    important="$1"
    task="$2"
    cmd="$3"
    if test $status = good
    then
	log Begin $task
        timeecho Begin $task
        if sh -c "$cmd" > r/${task}log.txt 2>&1
        then
	    touch r/$task.pass
        else
	    timeecho FAIL: $task
	    touch r/$task.fail
	    if [ $important = 1 ]
	    then
	        status=${task}-failed
	    fi
        fi
    else
	echo status $status makes it impossible to perform this step \
	    > r/${task}log.txt
    fi
}

pfx=`pwd`/pfx

status=good

dotask 1 "unzip" "gzip -d $BASE.tar.gz"
dotask 1 "unpack" "tar xf $BASE.tar"
dotask 1 "cfg" "cd $BASE && ./configure -C --prefix=$pfx $cfgargs"
dotask 1 "make" "cd $BASE && make $makeargs"

#
# "make check" requirements
#

checkdocok=true
pdfok=true
dviok=true
checkprgok=true

dotask 0 "ckprg" "cd $BASE/src && make check"
dotask 0 "ckdist" "cd $BASE/src && make distcheck"
dotask 1 "install" "cd $BASE && make install"

if [ -f r/install.pass ]
then
    log Xenofarm OK
    find pfx -type f -print | sort > r/installedfiles.txt
fi

# FIXME: run distcheck.
# FIXME: compare the contents of the distcheck-generated tar file
# with the one we distributed.

log Begin response assembly
timeecho Collecting results

# Check for warnings

if test -f r/cfg.pass
then
    egrep -i 'warning|\(w\)' r/cfglog.txt \
    > r/cfgwarn.txt
    if test `wc -l < r/cfgwarn.txt` -gt 0
    then
	mv r/cfg.pass r/cfg.warn
    fi
fi

if test -f r/make.pass
then
    egrep -i 'warning|\(w\)' r/makelog.txt \
    > r/makewarn.txt
    if test `wc -l < r/makewarn.txt` -gt 0
    then
	mv r/make.pass r/make.warn
    else
	rm r/makewarn.txt
    fi
fi

if test -f r/ckprg.pass
then
    egrep -i 'warning|\(w\)|error' r/ckprglog.txt \
    > r/ckprgwarn.txt
    if test `wc -l < r/ckprgwarn.txt` -gt 0
    then
	mv r/ckprg.pass r/ckprg.warn
	egrep -i 'error' r/ckprgwarn.txt \
	> r/ckprgfail.txt
	if test `wc -l < r/ckprgfail.txt` -gt 0
	then
	    mv r/ckprg.warn r/ckprg.fail
	else
	    rm r/ckprgfail.txt
	fi
    else
	rm r/ckprgwarn.txt
    fi
fi

# Collect stuff.

cp $BASE/config.cache r/configcache.txt
cp $BASE/config.log r/configlog.txt
cp $BASE/src/argp/config.log r/argpconfig.log
cp $BASE/src/nettle/config.log r/nettleconfig.log
cp $BASE/src/sftp/config.log r/sftpconfig.log
cp $BASE/src/spki/config.log r/spkiconfig.log

cp $BASE/config.h r/config-h.txt
# find $BASE -name core -print
env > r/environ.txt
echo $PATH > r/path.txt
makeinfo --version > r/makeinfo.txt
type makeinfo >> r/makeinfo.txt 2>&1

cp buildid.txt r/buildid.txt

(cd r && tar cf - *) > xenofarm_result.tar
gzip -1 xenofarm_result.tar

exit 0
