# Common stuff for all test scripts.

set -e

TESTHOME=home

function client () {
    cd $TESTHOME ../../sftp-test-client ../../sftp-server "$@"
}
    
