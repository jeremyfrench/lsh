# Helper functions for the test scripts.

# Any error count as failure.
set -e

# echo srcdir = $srcdir

: ${TEST_HOME:=`pwd`/home}
: ${LSH_YARROW_SEED_FILE:="$TEST_HOME/.lsh/yarrow-seed-file"}

# For lsh-authorize
: ${SEXP_CONV:="`pwd`/../sexp-conv"}

export LSH_YARROW_SEED_FILE SEXP_CONV

: ${LSHD_FLAGS:='-q --enable-core'}
: ${LSH_FLAGS:=-q}
: ${LSHG_FLAGS:=-q}
: ${HOSTKEY:="$srcdir/key-1.private"}
: ${PIDFILE:="`pwd`/lshd.$$.pid"}
: ${INTERFACE:=127.0.0.1}

# Ignore any options the tester might have put in the environment.

unset LSHGFLAGS
unset LSHFLAGS

PORT=11147
ATEXIT='set +e'

# We start with EXIT_FAILURE, and changing it to EXIT_SUCCESS only if
# test_success is invoked.

test_result=1

test_fail () {
    test_result=1
    exit
}

test_success () {
    test_result=0
    exit
}

test_skip () {
    test_result=77
    exit
}

check_x11_support () {
    ../lsh --help | grep 'x11-forward' >/dev/null || test_skip
}

trap 'eval "$ATEXIT ; exit \$test_result"' 0

at_exit () {
  ATEXIT="$ATEXIT ; $1"
}

spawn_lshd () {

    # local is not available in /bin/sh
    # local delay

    # Note that --daemon not only forks into the background, it also changes
    # the cwd, uses syslog, etc.
    
    HOME="$TEST_HOME" ../lshd -h $HOSTKEY --interface=$INTERFACE \
	-p $PORT $LSHD_FLAGS \
	--pid-file $PIDFILE --daemon --no-syslog "$@"

    # lshd may catch the ordinary TERM signal, leading to timing
    # problems when the next lshd process tries to bind the port.
    # So we kill it harder.

    at_exit 'kill -9 `cat $PIDFILE`; rm -f $PIDFILE'

    # Wait a little for lshd to start
    for delay in 1 1 1 1 1 5 5 5 20 20 60 60; do
	if [ -s $PIDFILE ]; then
	    # And a little more for it to open its port
	    sleep 5
	    return
	fi
	sleep $delay
    done
    
    false
}

run_lsh () {
    cmd="$1"
    shift
    echo "$cmd" | HOME="$TEST_HOME" ../lsh $LSH_FLAGS -nt \
	--sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" localhost

}

exec_lsh () {
    HOME="$TEST_HOME" ../lsh $LSH_FLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT localhost "$@"
}

# FIXME: Use -B
spawn_lsh () {
    # echo spawn_lsh "$@"
    HOME="$TEST_HOME" ../lsh $LSH_FLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" -N localhost &
    at_exit "kill $!"
}

exec_lshg () {
    ../lshg $LSHG_FLAGS -nt -p $PORT localhost "$@"
}

spawn_lshg () {
    # echo spawn_lshg "$@"
    ../lshg $LSHG_FLAGS -p $PORT "$@" -N localhost &
    at_exit "kill $!"
}

at_connect () {
    mini-inetd -m $2 -- localhost:$1 /bin/sh sh -c "$3" &
    at_exit "kill $!"
}

compare_output() {
    if cmp test.out1 test.out2; then
	echo "$1: Ok, files match."
	test_success
    else
	echo "$1: Error, files are different."
	test_fail
    fi
}
