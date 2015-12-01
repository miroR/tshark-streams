#!/bin/bash
#
# Based on http://heapspray.net/post/using-tshark-to-view-raw-socket-streams/
#
# Too busy to do it now, but more complete, and cleaner, tshark-streams.sh
# program, should in the future be found at:
#
# https://github.com/miroR/tshark-streams.git
#
# I tried to post comment about my thread on Wireshark to that Matt's
# heapspray.net page, but seems there has not been sent to him or something. If
# you know Matt, tell him to try and contact me, via github, probably most
# reliable. 
#
# This will extract all, if arg *not* $2 given, or those in the arg $2, tcp/ssl
# streams from your pcap file.
#
# Apart from a recent Wireshark install, xxd (part of vim-core here) is needed.
#
# Surely for ssl streams, the $SSLKEYLOGFILE must have been set for those ole
# captures, but learn that howto elsewhere (the fact of the matter is, also
# from links in the links below --not in first links-- you can).
#
# There is a Gentoo Forums topic:
#
# How to extract content from tshark-saved streams?
# https://forums.gentoo.org/viewtopic-t-1033844.html
#
# and a wireshark-users mailing list lonely thread:
#
# [Wireshark-users] follow [tcp|ssl].stream with tshark 
# https://www.wireshark.org/lists/wireshark-users/201511/msg00033.html 
#
# (There are even bugs that I (mis)posted/(mis)reported on Gentoo and Wireshark
# Bugzilla about this! But find those in the links above, if you really wish.)
#
# For the understanding of that topic and that thread I leave the old
# tshark-streams.sh script in its original directory, where this complete
# script is too. However, that old script, in case you got here via those, is
# now named:
#
# tshark-streams-INCOMPLETE.sh
#
# and should not be used at all.
#
# I always name my PCAPs with the .pcap extension. Modify this if you don't.
#
dump=$(echo $1|sed 's/\.pcap//')
echo "\$dump.pcap: $dump.pcap"

# I like to have a log to look up. Some PCAPs are slow to work. Need to know at
# what stage the work is.
# And I was finishing lots of line with "|& tee -a $tshlog". No. Clutters too much.
# Better to add such a redirection to the very command issued when starting the script.
# Something like the commented lines below (previously written for the further
# above purpose, so adapt them, if you need such logging).
# tshlog=tsh-$(date +%y%m%d_%H%M).log
# export tshlog
# touch $tshlog
# echo "\$tshlog: $tshlog"
# ls -l $tshlog
# So after something like that, you can start this script with:
# tshark-streams.sh <pcap-file> |& tee $tshlog

if [ "$#" -lt 1 ]; then
		echo "Usage: tshark_streams.sh <pcap file> [filter rules]"
		exit
fi

if [ ! -z "$2" ]; then
	echo $2
	read FAKE
	if [ "$2" != "_" ]; then
		STREAMS=$(tshark -r "$dump.pcap" -Y "$2" -T fields -e tcp.stream | sort -n | uniq)
		echo "\$STREAMS: $STREAMS"
	elif [ ! -z "$3" ]; then
		echo "Trying to make $3 be an option to either:"
		echo "1) be the selection of streams to work instead of the entire array, or"
		echo "2) allow giving the selection of streams somehow (don't know how yet),"
		echo "after they are listed."
		echo "Only the 1) for now"
		echo "Give the text file with sole content the list of streams to process:"
		read selected_streams
		STREAMS=$(cat $selected_streams)
		else "This suboption not accounted for yet."
	fi
else
		echo "tshark -r $dump.pcap -T fields -e tcp.stream | sort -n | uniq"
		tshark -r "$dump.pcap" -T fields -e tcp.stream | sort -n | uniq
		STREAMS=$(tshark -r "$dump.pcap" -T fields -e tcp.stream | sort -n | uniq)
		echo "\$STREAMS: $STREAMS"
fi

for i in $STREAMS
do 
		# I adjust this manually. If really huge dump, I set %.4d, else %.3d is enough
		INDEX=`printf '%.3d' $i`
		echo "Processing stream $INDEX ..."

		tshark -r "$dump.pcap" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.raw

		ls -l ${dump}_s$INDEX.raw
		cat ${dump}_s$INDEX.raw \
		| grep -A1000000000 =================================================================== \
		> ${dump}_s$INDEX.raw.CLEAN ;
		wc_l=$(cat ${dump}_s$INDEX.raw.CLEAN | wc -l) ; echo $wc_l;
		wc_l_head=$(echo $wc_l-1|bc); echo $wc_l_head;
		wc_l_tail=$(echo $wc_l_head-5|bc); echo $wc_l_tail;
		cat ${dump}_s$INDEX.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s$INDEX.raw.FINAL;
		ls -l ${dump}_s$INDEX.raw.CLEAN  ${dump}_s$INDEX.raw.FINAL;
		cat ${dump}_s$INDEX.raw.FINAL | xxd -r -p > ${dump}_s$INDEX.bin
		# To see why and if tshark still does in such way that this work, maybe sometime
		# in the future, reverse the commenting of these two lines below in particular, and investigate
		rm -v ${dump}_s$INDEX.raw*
		#read FAKE

		tshark -r "$dump.pcap" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.txt

		tshark -r "$dump.pcap" -T fields -e data -qz follow,ssl,raw,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.raw

		cat ${dump}_s${INDEX}-ssl.raw \
		| grep -A1000000000 =================================================================== \
		> ${dump}_s${INDEX}-ssl.raw.CLEAN ;
		wc_l=$(cat ${dump}_s${INDEX}-ssl.raw.CLEAN | wc -l) ; echo $wc_l;
		wc_l_head=$(echo $wc_l-1|bc); echo $wc_l_head;
		wc_l_tail=$(echo $wc_l_head-5|bc); echo $wc_l_tail;
		cat ${dump}_s${INDEX}-ssl.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s${INDEX}-ssl.raw.FINAL;
		ls -l ${dump}_s${INDEX}-ssl.raw.CLEAN  ${dump}_s${INDEX}-ssl.raw.FINAL;
		cat ${dump}_s${INDEX}-ssl.raw.FINAL | xxd -r -p > ${dump}_s${INDEX}-ssl.bin
		# To see why and if tshark still does in such way that this work, maybe sometime
		# in the future, reverse the commenting of these two lines below in particular, and investigate
		rm -v ${dump}_s${INDEX}-ssl.raw*
		#read FAKE

		tshark -r "$dump.pcap" -qz follow,ssl,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.txt

done
