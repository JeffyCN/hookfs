#!/bin/sh -x

# ignore other files
[ "$1" = state ] || exit

# handle freeze request
mv /tmp/.freeze_pending /tmp/.freeze &>/dev/null && {
	echo freeze > $SYS_DIR/power/state
	rm -f /tmp/.freeze
}

# handle suspend request
mv /tmp/.mem_pending /tmp/.mem &>/dev/null || exit

if [ -e /var/run/pm-utils/locks/pm-suspend.lock ]; then
	# external pm-utils suspend
	echo mem > $SYS_DIR/power/state
else
	# do pm-utils suspend
	mount -B $SYS_DIR/power/state /sys/power/state
	pm-suspend
	umount /sys/power/state
fi

rm -f /tmp/.mem
