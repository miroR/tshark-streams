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
# If option "-Y $DISPLAYFILTER" is *not* given, this script will extract all
# tcp/ssl streams from your pcap file.
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

function show_help {
  echo "tshark-streams.sh - Extract TCP/SSL streams from $PCAP_FILE"
  echo "Usage: $0 <PCAP file> -Y <filter> -l <list-of-streams> -k <ssl.keylog_file>"
  echo ""
  echo -e "    -r $PCAP_FILE is mandatory (but may not do it alone). See below"
  echo -e "    \tfor particular uses though"
  echo -e "    -Y a display filter (see 'man tshark')"
  echo -e "    \tif neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    -l a list of streams' numbers, one per line, to extract (can use the"
  echo -e "    \${dump}_streams.ls-1 file to pick from)"
  echo -e "    \tif neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable used during"
  echo -e "    \tFirefox or some other NSS supporting browser's run, all properly set,"
  echo -e "    \tthen you don't need to set this flag"
}

if [ "$#" -lt 1 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1
DISPLAYFILTER=""
STREAMSLIST=""
KEYLOGFILE=""

while getopts "h?r:Y:l:k:" opt;
do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  PCAP_FILE=$OPTARG
    echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
    read FAKE
        ;;
    Y)  DISPLAYFILTER=$OPTARG
        ;;
    l)  STREAMSLIST=$OPTARG
    echo "gives: -l $STREAMSLIST (\$STREAMSLIST); since \$OPTARG: $OPTARG"
    read FAKE
        ;;
    k)  KEYLOGFILE=$OPTARG
    echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
    read FAKE
        ;;
    esac
done

echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
	KEYLOGFILE=$SSLKEYLOGFILE
fi
echo \$KEYLOGFILE: $KEYLOGFILE
read FAKE

#
echo -n \$PCAP_FILE: echo $PCAP_FILE
read FAKE
dump=$(echo $PCAP_FILE|cut -d. -f1)
echo -n \$dump: echo $dump
read FAKE
ext=$(echo $PCAP_FILE|cut -d. -f2)
echo -n \$ext: echo $ext
read FAKE
filename=$dump.$ext
echo -n \$filename: echo $filename
read FAKE
echo -n \$ext: echo $ext
#if [ $ext != "pcap" ]; then
#	ln -s $dump.$ext $dump.pcap
#fi
#dump=$(echo $1|sed 's/\.pcap//')
#echo "\$dump.pcap: $dump.pcap"

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

if [ ! -z "$DISPLAYFILTER" ]; then
	echo $DISPLAYFILTER
	read FAKE
	STREAMS=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -Y "$DISPLAYFILTER" -T fields -e tcp.stream | sort -n | uniq)
#	echo "\$STREAMS: $STREAMS"
	echo $STREAMS | tr ' ' '\012' > ${dump}_streams.ls-1
	read FAKE

if [ ! -z "$STREAMSLIST" ]; then
	echo \$STREAMSLIST
	read FAKE
	echo \$STREAMSLIST: $STREAMSLIST
	read FAKE
	STREAMS=$(cat $STREAMSLIST)
	echo \$STREAMS
	read FAKE
	echo "\$STREAMS: $STREAMS"
	read FAKE
fi
#	elif [ ! -z "$3" ]; then
#		echo "Trying to make $3 be an option to either:"
#		echo "1) be the selection of streams to work instead of the entire array, or"
#		echo "2) allow giving the selection of streams somehow (don't know how yet),"
#		echo "after they are listed."
#		echo "Only the 1) for now"
#		echo "Give the text file with sole content the list of streams to process:"
#		read selected_streams
#		STREAMS=$(cat $selected_streams)
#		else "This suboption not accounted for yet."
#	fi
else
	echo "tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -T fields -e tcp.stream | sort -n | uniq"
#	tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e tcp.stream | sort -n | uniq
	STREAMS=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e tcp.stream | sort -n | uniq)
#	echo "\$STREAMS: $STREAMS"

	if [ ! -z "$STREAMSLIST" ]; then
		echo \$STREAMSLIST
		read FAKE
		echo \$STREAMSLIST: $STREAMSLIST
		read FAKE
		STREAMS=$(cat $STREAMSLIST)
		echo \$STREAMS
		read FAKE
		echo "\$STREAMS: $STREAMS"
		read FAKE
	else
		echo $STREAMS | tr ' ' '\012' > ${dump}_streams.ls-1
		read FAKE
	fi
fi

for i in $STREAMS
do 
		# I adjust this manually. If really huge dump, I set %.4d, else %.3d is enough
		INDEX=`printf '%.3d' $i`
		echo "Processing stream $INDEX ..."

		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.raw

#		ls -l ${dump}_s$INDEX.raw
		cat ${dump}_s$INDEX.raw \
		| grep -A1000000000 =================================================================== \
		> ${dump}_s$INDEX.raw.CLEAN ;
		wc_l=$(cat ${dump}_s$INDEX.raw.CLEAN | wc -l) ; #echo $wc_l;
		wc_l_head=$(echo $wc_l-1|bc); #echo $wc_l_head;
		wc_l_tail=$(echo $wc_l_head-5|bc); #echo $wc_l_tail;
		cat ${dump}_s$INDEX.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s$INDEX.raw.FINAL;
#		ls -l ${dump}_s$INDEX.raw.CLEAN  ${dump}_s$INDEX.raw.FINAL;
		cat ${dump}_s$INDEX.raw.FINAL | xxd -r -p > ${dump}_s$INDEX.bin
		# To see why and if tshark still does in such way that this work, maybe sometime
		# in the future, reverse the commenting of these two lines below in particular, and investigate
		rm ${dump}_s$INDEX.raw*
		echo "Extracted:"
		ls -l ${dump}_s$INDEX.bin

		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.txt
		echo "Extracted:"
		ls -l ${dump}_s$INDEX.txt

		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,ssl,raw,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.raw

		cat ${dump}_s${INDEX}-ssl.raw \
		| grep -A1000000000 =================================================================== \
		> ${dump}_s${INDEX}-ssl.raw.CLEAN ;
		wc_l=$(cat ${dump}_s${INDEX}-ssl.raw.CLEAN | wc -l) ; #echo $wc_l;
		wc_l_head=$(echo $wc_l-1|bc); #echo $wc_l_head;
		wc_l_tail=$(echo $wc_l_head-5|bc); #echo $wc_l_tail;
		cat ${dump}_s${INDEX}-ssl.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s${INDEX}-ssl.raw.FINAL;
#		ls -l ${dump}_s${INDEX}-ssl.raw.CLEAN  ${dump}_s${INDEX}-ssl.raw.FINAL;
		cat ${dump}_s${INDEX}-ssl.raw.FINAL | xxd -r -p > ${dump}_s${INDEX}-ssl.bin
		# To see why and if tshark still does in such way that this work, maybe sometime
		# in the future, reverse the commenting of these two lines below in particular, and investigate
		rm ${dump}_s${INDEX}-ssl.raw*
		echo "Extracted:"
		ls -l ${dump}_s$INDEX-ssl.bin
		#read FAKE

		tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,ssl,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.txt
		echo "Extracted:"
		ls -l ${dump}_s$INDEX-ssl.txt

done

echo "The list of stream numbers is in:"
ls -l ${dump}_streams.ls-1
