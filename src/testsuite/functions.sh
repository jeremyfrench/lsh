# Helper functions for the test scripts.

if [ -z "$srcdir" ] ; then
  srcdir=`pwd`
fi

if [ -z "$SERVERFLAGS" ] ; then
    SERVERFLAGS='-q --enable-core'
fi

if [ -z "$CLIENTFLAGS" ] ; then
    CLIENTFLAGS=-q
fi

# Any error count as failure.
set -e

PORT=11147
ATEXIT="res=$? ; set +e"

trap 'eval "$ATEXIT ; exit \$res"' 0

at_exit () {
  res=$?
  ATEXIT="$ATEXIT ; $1"
  return $res
}

spawn_lshd () {

    # local is not available in /bin/sh
    # local delay
    
    ../lshd -h $srcdir/key-1.private --interface=localhost \
	-p $PORT $SERVERFLAGS --pid-file lshd.$$.pid &

    at_exit 'kill `cat lshd.$$.pid`; rm -f lshd.$$.pid'

    # Wait a little for lshd to start
    for delay in 1 1 1 1 1 5 5 5 20 20 60 60; do
	if [ -s lshd.$$.pid ]; then
	    # And a little more for it to open its port
	    sleep 5
	    return
	fi
	sleep $delay
    done
    
    false
}

run_lsh () {
    cmd=$1
    shift
    echo $cmd | ../lsh $CLIENTFLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" localhost

}

exec_lsh () {
    ../lsh $CLIENTFLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT localhost "$@"
}

spawn_lsh () {
    # echo spawn_lsh "$@"
    ../lsh $CLIENTFLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" -N localhost &
    at_exit "kill $!"
}

at_connect () {
    mini-inetd -m $2 localhost:$1 -- /bin/sh sh -c "$3" &
    at_exit "kill $!"
}
