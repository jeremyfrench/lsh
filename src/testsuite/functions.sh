# Helper functions for the test scripts.

if [ -z "$srcdir" ] ; then
  srcdir=`pwd`
fi

if [ -z "$SERVERFLAGS" ] ; then
    SERVERFLAGS=-q
fi

if [ -z "$CLIENTFLAGS" ] ; then
    CLIENTFLAGS=-q
fi

PORT=11147
ATEXIT="res=$?"

trap 'eval "$ATEXIT ; exit \$res"' EXIT

function at-exit () {
  res=$?
  ATEXIT="$ATEXIT ; $1"
  return $res
}

function spawn-lshd () {

    local delay
    
    ../lshd -h $srcdir/key-1.private --interface=localhost \
	-p $PORT $SERVERFLAGS --pid-file lshd.$$.pid &

    at-exit 'kill `cat lshd.$$.pid`; rm -f lshd.$$.pid'

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

function run-lsh () {
    cmd=$1
    shift
    echo $cmd | ../lsh $CLIENTFLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" localhost

}

function spawn-lsh () {
    # echo spawn-lsh "$@"
    ../lsh $CLIENTFLAGS -nt --sloppy-host-authentication \
	--capture-to /dev/null -z -p $PORT "$@" -N localhost &
    at-exit "kill $!"
}

function at-connect () {
    mini-inetd -m $2 localhost:$1 -- /bin/sh sh -c "$3" &
    at-exit "kill $!"
}
