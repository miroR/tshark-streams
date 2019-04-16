#!/bin/bash
#
# You should probably be able to find this program now at:
#
# https://github.com/miroR/tshark-streams.git
#
# Based on http://heapspray.net/post/using-tshark-to-view-raw-socket-streams/
#
# tshark-streams may not work in case your Wireshark has not been patched,
# in >wireshark-2.0.2, tshark follow ssl stream segfaults
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12616
# (applies to older versions only, by now).
#
# I tried unsuccessfully to contact Matt whose idea I have further developed by
# posting comments at his heapspray.net page. If you know Matt, tell him please
# to try and contact me, via github, probably most reliable.
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
# where you can learn about setting the $SSLKEYLOGFILE environment variable
# etc.).
#
# As far as decrypting your own captures, first you have to make them. You may
# be interested to see how I do it at:
# https://github.com/miroR/uncenz
#
# Less important links follow (but if any of the links died by the time you
# read here, do try and tell me --use the uncenz above to be able to show how
# you tried to contact me, if unsuccessful, by posting the screencast and
# traffic dump in public [[after longer wait for my reply, see below how I'm
# very slow]] (the publishing may be the only way to fight censorship; exampli
# gratia in Croatia we are still not done at all with the remnants and progenie
# and metamorphoids of the communist UDBA; UDBA is something like a tiny local
# NSA, for a short description; and emails/phone calls/other to me/from me have
# for years been filtered by those subjects and allowed through or disallowed
# and cut off and thrown out instead)--, and if I get your notice I may be able
# to post, the information about it, or even the TCP/SSL-extracted streams,
# with this tshark-streams.sh, id est: the same information that previously was
# in that/those location(s), from my uncenz archives, [I may be able to post
# it] on http://www.CroatiaFidelis.hr) So, the less important links:
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
# neither the initial one, that is now named:
#
# tshark-streams-INCOMPLETE.sh
#
# and not either the first improved version, should be used anymore at all.
#
# On the other hand, I work so *slowly* (pls. do notice!; e.g. be patient if
# you try and contact me, could be my slowliness), that I'm currently
# absolutely out of time to clean up this script very much at all which I
# intend to tag version 0.18 of tshark-streams.sh ...
#
# Ah, must not foget to tell: I've only just managed to get it to work with
# Bash's own getopts builtin, after pondering over NetMinecraft (thanks
# Jonathan Racicot!):
#
# https://github.com/InfectedPacket/NetMinecraft
#
# (but NetMinecraft was done for the pre-2.0 Wireshark it seems to me, and some
# of the functionality does not seem to work, or is incomplete as just like this
# tshark-streams.sh is. The tshark-streams.sh is, in contrast to NetMinecraft,
# only dealing with the record layer, at least for now. The two could be
# complimentary.)
#
# Use this script absolutely at your own risk! I guarrantee nothing to you
# regarding anything at all, usefulness or goodness or anything
# in/from/connected to this script.
#
# That said, I stress that it works fine for me (in most if not all the testing
# so far, which however hasn't been intensive).
#
# And one more thing: this script is just a systematic first step. The next
# thing to do is harder: sort the data extracted (get the htmls, css, gifs,
# pngs etc. extracted and sorted from those streams; Perl is to be employed
# with its regexps), and troubleshoot the eventual problems. In particular the
# latter can not be done without the various dissections, the certificates and
# handshakes, and plethora of other things and aspects, that are not dealt with
# by this script at all ;-) ...
#
# And all those things actually exist in the, nowadays huge, surveillance
# industry. But we, the honest users who do not want neither to control others
# nor to be controled, have to make those for us, and publish them for our
# brothers in *nix ...  Redoing the steps of the secret (and filthy by intended
# and applied use) knowledge and technology that already exist... What dirty
# business, such controling of people, the brainwashing, the hiding of events,
# causes and the realities beyond, but which would traspire to the eyes of the
# weak had they not been so oppressed... By all that industry of lying and
# worse!...
#
# Released under BSD license, pls. see LICENSE, attached to this script (if
# not, it's under a generic BSD license, which is completely GNU-compatible)
#
# Copyright (c) 2016 Croatia Fidelis, Miroslav Rovis, www.CroatiaFidelis.hr
#
# TIP: If you issue a redirection to the very command issued when starting the
# script, something like these commented-out lines:
# tshlog=tsh-$(date +%y%m%d_%H%M).log # (tshlog for "tshark log")
# export tshlog
# touch $tshlog
# echo "\$tshlog: $tshlog"
# ls -l $tshlog
# and then start this script with:
# tshark-streams.sh -r <pcap-file> <...> |& tee $tshlog
# you get it all logged, Could be useful, if I echoed all the commands before
# they ran, as it would be a boon for newbies to learn: the commands from the
# logs could then be copied and pasted and run separately. Too much work,
# echoed only some...

function show_help {
  echo "tshark-streams.sh - Extract TCP/SSL streams from \$PCAP_FILE"
  echo "Usage: $0 -r <PCAP file> -k <ssl.keylog_file> -l <list-of-streams> -Y <single-stream>"
  echo ""
  echo -e "    This script is very dirty and in testing phase. No warranties."
  echo -e "    Advanced users or very careful and very hardworking newbies only!"
  echo -e "    \t\t!!!! You have been warned !!!!"
  echo ""
  echo -e "    \tIf neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    \tNOTE: the -Y and -l are mutually exclusive"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo -e "    \tfor particular uses though"
  echo -e "    -k give the filename with the CLIENT_RANDOM... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable (currently"
  echo -e "    \thard-wired to value: /home/<you>/.sslkey.log) used during"
  echo -e "    \tFirefox or some other NSS supporting browser's run, all properly set,"
  echo -e "    \tthen you don't need to set this flag"
  echo -e "    -l a list of streams' numbers, one per line, to extract (can use the"
  echo -e "    \t\${dump}_streams.ls-1 file gotten from, maybe interrupted (for now,"
  echo -e "    \t I'm really out of time) all-extraction run to pick from)"
  echo -e "    -Y a single stream number display filter (see 'man tshark', exampli gratia:"
  echo -e "    \t -Y \"tcp.stream==N\" where N is a number from among the available"
  echo -e "    \tfor your \$PCAP_FILE (you need to enter the whole expression, no time"
  echo -e "    \tto fix this)"
  echo ""
#  echo -e "    \tThere's a few times for you to hit Enter, to get going, to allow you"
#  echo -e "    \tto view this script and what it is doing in another terminal..."
#  echo -e "    \tPls. read more explanation in the script."
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1	# Frankly, don't understand yet the OPTIND, nor if it is needed here.
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
    #echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
        ;;
    Y)  DISPLAYFILTER=$OPTARG
    #echo "gives: -Y $DISPLAYFILTER (\$DISPLAYFILTER); since \$OPTARG: $OPTARG"
    ##read FAKE
        ;;
    l)  STREAMSLIST=$OPTARG
    #echo "gives: -l $STREAMSLIST (\$STREAMSLIST); since \$OPTARG: $OPTARG"
    ##read FAKE
        ;;
    k)  KEYLOGFILE=$OPTARG
    #echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
    ##read FAKE
        ;;
    esac
done

echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
	KEYLOGFILE=$SSLKEYLOGFILE
fi
echo \$KEYLOGFILE: $KEYLOGFILE
##read FAKE

echo \$PCAP_FILE: $PCAP_FILE
##read FAKE
# Files can have a few dots, this is how I'll take the last as separator.
num_dots=$(echo $PCAP_FILE|sed 's/\./\n/g'| wc -l)
num_dots_min_1=$(echo $num_dots - 1 | bc)
#echo \$num_dots: $num_dots
#echo \$num_dots_min_1: $num_dots_min_1
ext=$(echo $PCAP_FILE|cut -d. -f $num_dots)
echo \$ext: $ext
##read FAKE
#echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/"
dump=$(echo $PCAP_FILE|sed "s/\(.*\)\.$ext/\1/")
echo \$dump: $dump
##read FAKE
filename=$dump.$ext
echo \$filename: $filename
#read FAKE # The 'read FAKE' lines aren't really used for reading anything.
# It's for the user to follow and decide how the sript is faring and hit
# Enter (or Ctrl-C if something went wrong)! Teach me a better trick
# instead!
# They are also there for uncommenting (a particular 'read FAKE' line along
# with the, usually, 'echo ...' line just above it, when you need to manually
# debug the script to see what may have gone wrong. The uncommenting of the
# 'read FAKE' lines can be done simply with, say:
# cat <script>|sed 's/#readme FAKE/readme FAKE/' > <script_tmp> etc.
# This is not a completed and polished script.

# I like to have a log to look up. Some PCAPs are slow to work. Need to know at
# what stage the work is.

if [ ! -z "$DISPLAYFILTER" ]; then
	echo \$DISPLAYFILTER: $DISPLAYFILTER
	#read FAKE
	STREAMS=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -Y "$DISPLAYFILTER" -T fields -e tcp.stream | sort -n | uniq)
	if [ -e "${dump}_streams.ls-1" ]; then
		# backing up the list of stream numbers if previously made
		cp -av ${dump}_streams.ls-1 ${dump}_streams.ls-1_$(date +%s)
	fi
	echo $STREAMS | tr ' ' '\012' > ${dump}_streams.ls-1
	echo "############################################################"
	echo "The list of stream numbers contained in the \$PCAP_FILE:"
	echo "$PCAP_FILE is listed in:"
	ls -l ${dump}_streams.ls-1
	echo "Hit Enter to continue!"
	echo "############################################################"
	#read FAKE

	if [ ! -z "$STREAMSLIST" ]; then
		#echo \$STREAMSLIST
		##read FAKE
		echo \$STREAMSLIST: $STREAMSLIST
		##read FAKE
		STREAMS=$(cat $STREAMSLIST)
		#echo \$STREAMS
		##read FAKE
		#echo "\$STREAMS: $STREAMS"
		#read FAKE
	fi
else
	echo "tshark -o \"ssl.keylog_file: $KEYLOGFILE\" -r $dump.$ext -T fields -e tcp.stream | sort -n | uniq"
	STREAMS=$(tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e tcp.stream | sort -n | uniq)

	if [ ! -z "$STREAMSLIST" ]; then
		#echo \$STREAMSLIST
		##read FAKE
		echo \$STREAMSLIST: $STREAMSLIST
		##read FAKE
		STREAMS=$(cat $STREAMSLIST)
		#echo \$STREAMS
		##read FAKE
		#echo "\$STREAMS: $STREAMS"
		##read FAKE
		if [ -e "${dump}_streams.ls-1" ]; then
			# backing up the list of stream numbers if previously made
			cp -av ${dump}_streams.ls-1 ${dump}_streams.ls-1_$(date +%s)
		fi
	else
		if [ -e "${dump}_streams.ls-1" ]; then
			# backing up the list of stream numbers if previously made
			cp -av ${dump}_streams.ls-1 ${dump}_streams.ls-1_$(date +%s)
		fi
		echo $STREAMS | tr ' ' '\012' > ${dump}_streams.ls-1
		echo "############################################################"
		echo "The list of stream numbers contained in the \$PCAP_FILE:"
		echo "$PCAP_FILE is listed in:"
		ls -l ${dump}_streams.ls-1
		echo "Hit Enter to continue!"
		echo "############################################################"
		#read FAKE
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
	##read FAKE

	tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,ssl,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.txt
	echo "Extracted:"
	ls -l ${dump}_s$INDEX-ssl.txt
done
