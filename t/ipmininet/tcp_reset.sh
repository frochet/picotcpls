#!/bin/bash
COMMAND=$1
LIMIT=$2
IP=$3
$COMMAND -F
while true;
do
	COUNT=$( $COMMAND -L FORWARD -n -v -x | awk '$7 ~ /^[0-9]+$/ { printf "%d", $7 }' )
	printf $COUNT 
	printf " "
	printf $LIMIT
	printf "\n"
	if [ $COUNT -gt $LIMIT ]
	then
		$COMMAND -A FORWARD -p tcp -d $IP -j REJECT --reject-with tcp-reset
		sleep 3
		$COMMAND -F
	fi
	sleep 0.05
done

