#!/bin/sh -x

# ignore other files
[ "$1" = state ] || exit 1

# trim the tails
REQ="$(echo $2)"

# ignore unsupported requests
cat $SYS_DIR/power/state | xargs -n 1 | grep -wq "$REQ" || exit 1

# delay the request to release script since fuse sync op cannot get freezed
touch /tmp/.${REQ}_pending

# bypass the real write
exit 0
