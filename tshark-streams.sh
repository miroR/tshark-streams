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
# you know Matt, tell him to please try and contact me, via github, probably
# most reliable. The credit I do give here...
#
# Apart from a recent Wireshark install, xxd (part of vim-core here) is needed.
#
# If neither of the options "-Y $DISPLAYFILTER" or -l "$STREAMSLIST" is given,
# but only the -r "$PCAP_FILE" (and -k "$KEYLOGFILE" if there are SSL streams
# in the $PCAP_FILE), this script will extract all tcp(/ssl) streams from your
# pcap file.
#
# For the basics of SSL decryption see:
# https://wiki.wireshark.org/SSL
#
# As far as decrypting your own captures (setting the $SSLKEYLOGFILE
# environment variable etc.), you may try and see how I do it at:
# https://github.com/miroR/uncenz
#
# Less important links follow (but if any of the links died by the time you
# read here, do try and tell me --use the uncenz above to be able to prove you
# tried to contact me by posting the screencast and traffic dump in public (the
# only way to fight censorship; in Croatia we are still not done at all with
# the remnants and progenie and metamorphoids of the communist UDBA; UDBA is
# something like a tiny local NSA, for a short description; and emails/phone
# calls/other to me/from me have for years been filtered by those subjects and
# allowed through or disallowed and cut off and thrown out instead)--, and I
# may be able to post, the information about it, or even the TCP/SSL-extracted
# streams, with tshark-streams.sh, id est: the same information that previously
# was in that location, from my uncenz archives, on
# http://www.CroatiaFidelis.hr):
#
# My first acquainting myself with SSL decryption was at:
# SSL Decode & My Hard-Earned Advice for SPDY/HTTP2 in Firefox
# https://forums.gentoo.org/viewtopic-t-1029408.html
#
# How I started this script is all in this Gentoo Forums topic:
# How to extract content from tshark-saved streams?
# https://forums.gentoo.org/viewtopic-t-1033844.html
#
# and in a wireshark-users mailing list lonely thread:
# [Wireshark-users] follow [tcp|ssl].stream with tshark 
# https://www.wireshark.org/lists/wireshark-users/201511/msg00033.html 
#
# (There are even bugs that I (mis)posted/(mis)reported on Gentoo and Wireshark
# Bugzilla about this! But find those in the links above, if you really wish.)
#
# For the understanding of that topic and that thread I leave the old
# tshark-streams.sh script in its original directory, where the first improved
# version of this script is too:
#
# http://www.CroatiaFidelis.hr/foss/cap/cap-150927-TLS-why-js/Add-151119/
#
# However, neither of those two old scripts, in case you got here via those,
# not the initial one, that is now named:
#
# tshark-streams-INCOMPLETE.sh
#
# and not either the first improved version, should be used anymore at all.
#
# On the other hand, I work so slowly, that I'm currently out of time to clean
# up this script (and my head already aches from strain to figure out how to do
# it), which I intend to tag version 0.18 of tshark-streams.sh ...
#
# Ah, I've only managed to get it to work with Bash's own getopts, after
# pondering over NetMinecraft (thanks Jonathan Racicot!):
#
# https://github.com/InfectedPacket/NetMinecraft
#
# (but NetMinecraft was done for the pre-2.0 Wireshark it seems to me, and some
# of the functionality does not seem to work, or is incomplete as this
# tshark-streams.sh is)
#
# Use this script absolutely at your own risk! ...However, it works for me (mostly).
#
# I guarrantee nothing to you regarding anything at all, usefulness or goodness
# or anything in/from/connected to this script.
#
# Released under BSD license, pls. see LICENSE, attached to this script (if
# not, it's under a generic BSD GNU-compatible license)
#
# Copyright (c) 2016 Croatia Fidelis, Miroslav Rovis, www.CroatiaFidelis.hr
#

function show_help {
  echo "tshark-streams.sh - Extract TCP/SSL streams from $PCAP_FILE"
  echo "Usage: $0 <PCAP file> -Y <filter> -l <list-of-streams> -k <ssl.keylog_file>"
  echo ""
  echo -e "    This script is very dirty and in testing phase. No warrnties."
  echo -e "    Advanced users or very careful and very hardworking newbies only!"
  echo -e "    \t\t\t!!!! You have been warned !!!!"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone). See below"
  echo -e "    \tfor particular uses though"
  echo -e "    -Y a simple display filter (see 'man tshark', example"
  echo -e "    \tempty) -Y \"tcp.stream==N\" where N is number from among available"
  echo -e "    \tfor your \$PCAP_FILE"
  echo -e "    \tNOTE: just checked: can't get an filter as above to work at this time,"
  echo -e "    \t single tcp.stream==N[N][N] works though)"
  echo -e "    \tIf neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    \tNOTE: the -Y and -l probably don't work together"
  echo -e "    -l a list of streams' numbers, one per line, to extract (can use the"
  echo -e "    \t\${dump}_streams.ls-1 file gotten from say partial all-extraction run"
  echo -e "    \tto pick from)"
  echo -e "    \tif neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    \tNOTE: the -Y and -l probably don't work together"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable (currently"
  echo -e "    \thard-wired to value: /home/<you>/.sslkey.log) used during"
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
    read FAKE # This isn't really used for reading any. But for the user to see
	# how the sript is faring and hit Enter (or Ctrl-C if something went wrong)!
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

# I like to have a log to look up. Some PCAPs are slow to work. Need to know at
# what stage the work is. (UPDATE: There is however the ${dump}_streams.ls-1 that gets created
# at the start though, so maybe this tip is not needed.)
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
	echo "############################################################"
	echo "( The list of stream numbers is in:"
	ls -l ${dump}_streams.ls-1
	echo "############################################################"
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

for i in $STREAMS; do 
	# This can be adjusted manually. If really huge dump, I set %.4d, else %.3d is enough.
	INDEX=`printf '%.3d' $i`
	echo "Processing stream $INDEX ..."

	tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.raw

#	ls -l ${dump}_s$INDEX.raw
	cat ${dump}_s$INDEX.raw \
	| grep -A1000000000 =================================================================== \
	> ${dump}_s$INDEX.raw.CLEAN ;
	wc_l=$(cat ${dump}_s$INDEX.raw.CLEAN | wc -l) ; #echo $wc_l;
	wc_l_head=$(echo $wc_l-1|bc); #echo $wc_l_head;
	wc_l_tail=$(echo $wc_l_head-5|bc); #echo $wc_l_tail;
	cat ${dump}_s$INDEX.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s$INDEX.raw.FINAL;
#	ls -l ${dump}_s$INDEX.raw.CLEAN  ${dump}_s$INDEX.raw.FINAL;
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
#	ls -l ${dump}_s${INDEX}-ssl.raw.CLEAN  ${dump}_s${INDEX}-ssl.raw.FINAL;
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
