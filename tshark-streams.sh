#!/bin/bash
#
# You should probably be able to find the old version this program at:
#
# https://github.com/miroR/tshark-streams.git
# I'll publish the current version somewhere libre-place, some day.
#
# I initially figured out how to extract streams reading:
# http://heapspray.net/post/using-tshark-to-view-raw-socket-streams/
#
# Apart from a recent Wireshark install, xxd (part of vim-core here) is needed.
#
# If neither of the options "-Y $DISPLAYFILTER" or -l "$STREAMSLIST" is given,
# but only the -r "$PCAP_FILE" (and -k "$KEYLOGFILE" if there are TLS streams
# in the $PCAP_FILE), this script will extract all tcp(/tls) streams from your
# pcap file.
#
# For the basics of TLS decryption see:
# https://wiki.wireshark.org/TLS
#
# where you can learn about setting the $SSLKEYLOGFILE environment variable
# etc.).
#
# As far as decrypting your own captures, first you have to make them. You may
# be interested to see how I do it at:
# https://github.com/miroR/uncenz
# although that's an old version of uncenz that I don't use anymore. I'll
# publish improved uncenz which I use daily somewhere libre-place, some day.
#
# How I started this script is all in this Gentoo Forums topic:
# How to extract content from tshark-saved streams?
# https://forums.gentoo.org/viewtopic-t-1033844.html
#
# and in a wireshark-users mailing list lonely thread:
# [Wireshark-users] follow [tcp|ssl].stream with tshark 
# https://www.wireshark.org/lists/wireshark-users/201511/msg00033.html 
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
# Released under BSD license, pls. see LICENSE, attached to this script (if
# not, it's under a generic BSD license, which is completely GNU-compatible)
#
# Copyright (c) 2016, 2021, 2022 Croatia Fidelis, Miroslav Rovis, www.CroatiaFidelis.hr
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
  echo "Usage: ${0##*/} -r <PCAP file> -k <tls.keylog_file> -l <list-of-streams> -Y <single-stream>"
  echo ""
  echo -e "    \tIf neither -Y nor -l are given, attempt is made to extract all streams"
  echo -e "    \tNOTE: the -Y and -l are mutually exclusive"
  echo ""
  echo -e "    -r \$PCAP_FILE is mandatory (but may not do it alone); see below"
  echo -e "    \tfor particular uses though"
  echo -e "    -k give the filename with the CLIENT_RANDOM or"
  echo -e "    \tCLIENT_HANDSHAKE_TRAFFIC_SECRET and related... lines that belong to"
  echo -e "    \tthe sessions in the PCAP. If those have been logged in the file"
  echo -e "    \tdesignated by the \$SSLKEYLOGFILE environment variable (which can be"
  echo -e "    \t/home/<you>/.sslkey.log or some other) used during"
  echo -e "    \tFirefox or some other NSS supporting browser's run, all properly set,"
  echo -e "    \tthen you don't need to set this flag"
  echo -e "    -l a list of streams' numbers, one per line, to extract (can use the"
  echo -e "    \t\${dump}_streams.ls-1 file gotten from, maybe interrupted"
  echo -e "    \tall-extraction run to pick from)"
  echo -e "    -Y a single stream number display filter (see 'man tshark', exampli gratia:"
  echo -e "    \t -Y \"tcp.stream==N\" where N is a number from among the available"
  echo -e "    \tfor your \$PCAP_FILE (you need to enter the whole expression)"
  echo ""
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1
DISPLAYFILTER=""
STREAMSLIST=""
KEYLOGFILE=""

while getopts "h?r:Y:l:k:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  PCAP_FILE=$OPTARG
    echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
        ;;
    Y)  DISPLAYFILTER=$OPTARG
    echo "gives: -Y $DISPLAYFILTER (\$DISPLAYFILTER); since \$OPTARG: $OPTARG"
        ;;
    l)  STREAMSLIST=$OPTARG
    echo "gives: -l $STREAMSLIST (\$STREAMSLIST); since \$OPTARG: $OPTARG"
        ;;
    k)  KEYLOGFILE=$OPTARG
    echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
        ;;
    esac
done

echo \$SSLKEYLOGFILE: $SSLKEYLOGFILE
if [ "$KEYLOGFILE" == "" ]; then
    KEYLOGFILE=$SSLKEYLOGFILE
fi
echo \$KEYLOGFILE: $KEYLOGFILE

echo \$PCAP_FILE: $PCAP_FILE
ext=${PCAP_FILE##*.}
dump=${PCAP_FILE%*.pcap}
echo \$ext: $ext
echo \$dump: $dump
filename=$dump.$ext
echo \$filename: $filename

# Used to be (2 ln):
#   WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
#   TSHARK=/some-place/wireshark-ninja/run/tshark
#   Replacing it with:
. shark2use

# In case of interrupted runs (of say huge PCAPs):
if [ ! -n "$STREAMSLIST" ]; then
    if [ -e "${dump}_streams.ls-1" ]; then
        STREAMSLIST=${dump}_streams.ls-1
        ls -l ${dump}_streams.ls-1
        echo "(ls -l ${dump}_streams.ls-1)"
        ls -l $STREAMSLIST
        echo "(ls -l $STREAMSLIST)"
    else
        echo "There is no:"
        echo "              ${dump}_streams.ls-1"
    fi
fi
#read NOP
if [ ! -z "$DISPLAYFILTER" ]; then
    echo "if start 005"
    echo \$DISPLAYFILTER: $DISPLAYFILTER
    #read NOP
    if [ -e "$STREAMSLIST" ] && [ ! -s "$STREAMSLIST" ]; then
       echo "We'll be using the existing \$STREAMSLIST:" 
        ls -l $STREAMSLIST
        echo "(ls -l $STREAMSLIST)"
    else
        STREAMS=$($TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -Y "$DISPLAYFILTER" -T fields -e tcp.stream | sort -n | uniq)
    fi 
    if [ -e "${dump}_streams.ls-1" ] && [ -s "${dump}_streams.ls-1" ]; then
        # backing up the list of stream numbers if previously made
        cp -av ${dump}_streams.ls-1 ${dump}_streams.ls-1_$(date +%s)
    fi
    echo $STREAMS | tr ' ' '\012' > ${dump}_streams.ls-1
    echo "############################################################"
    echo "The list of stream numbers contained in the \$PCAP_FILE:"
    echo "$PCAP_FILE is listed in:"
    ls -l ${dump}_streams.ls-1
    echo tail -2 ${dump}_streams.ls-1
    tail -2 ${dump}_streams.ls-1
    echo "Hit Enter to continue!"
    echo "############################################################"
    #read NOP

    if [ ! -z "$STREAMSLIST" ]; then
        echo \$STREAMSLIST: $STREAMSLIST
        STREAMS=$(<$STREAMSLIST)
    fi
else
    if [ -e "${dump}_streams.ls-1" ]; then
        ls -l ${dump}_streams.ls-1
        echo "(ls -l \${dump}_streams.ls-1)"
    fi
    if [ -e "$STREAMSLIST" ]; then
        ls -l $STREAMSLIST
        echo "(ls -l \$STREAMSLIST)"
    fi
    echo "else start 005"
    #read NOP
    if [ -e "$STREAMSLIST" ] && [ -s "$STREAMSLIST" ]; then
       echo "We'll be using the existing \$STREAMSLIST:" 
        ls -l $STREAMSLIST
        echo "(ls -l $STREAMSLIST)"
        STREAMS=$(<$STREAMSLIST)
    else
        echo "\$TSHARK -o \"tls.keylog_file: $KEYLOGFILE\" -r $dump.$ext -T fields -e tcp.stream | sort -n | uniq"
        STREAMS=$($TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e tcp.stream | sort -n | uniq)
    fi

    # $STREAMSLIST and ${dump}_streams.ls-1 are not always the same thing.
    if [ ! -z "$STREAMSLIST" ]; then
        echo \$STREAMSLIST: $STREAMSLIST
        STREAMS=$(<$STREAMSLIST)
        if [ -e "${dump}_streams.ls-1" ]; then
            # backing up the list of stream numbers if previously made
            cp -av ${dump}_streams.ls-1 ${dump}_streams.ls-1_$(date +%s)
        fi
        echo "In if 010"
        #read NOP
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
        echo tail -2 ${dump}_streams.ls-1
        tail -2 ${dump}_streams.ls-1
        echo "Hit Enter to continue!"
        echo "############################################################"
        echo "In else 011"
    fi
    #read FAKE
fi

> ${dump}_streams.ls-1_PREV #truncate, just in case
# One loop to list existing streams if any
for i in $STREAMS; do 
    INDEX=`printf '%.3d' $i`
    for stream_file in ${dump}_s$INDEX.raw ${dump}_s$INDEX.raw.CLEAN ${dump}_s$INDEX.raw.FINAL ${dump}_s$INDEX.bin \
        ${dump}_s$INDEX.txt ${dump}_s$INDEX-ssl.txt ; do
        if [ -e "$stream_file" ]; then
            if ( echo $stream_file|grep '\.raw' ); then
                rm -vi $stream_file
            else
                echo $stream_file >> ${dump}_streams.ls-1_PREV
            fi
        fi
    done
done
cat ${dump}_streams.ls-1_PREV
echo "(cat ${dump}_streams.ls-1_PREV)"
ls -l ${dump}_streams.ls-1_PREV
echo "(ls -l ${dump}_streams.ls-1_PREV)"
#read NOP 
#rm -v .skip_non-TLS_stream .skip_TLS_stream
echo "You can now set either:"
echo ".skip_non-TLS_stream (type nt)"
echo ".skip_TLS_stream (type st)"
#read skipping
if [ "$skipping" == "nt" ]; then touch .skip_non-TLS_stream ; ls -l .skip_non-TLS_stream ; fi
if [ "$skipping" == "st" ]; then touch .skip_TLS_stream ; ls -l .skip_TLS_stream ; fi
#read NOP
for i in $STREAMS; do 
    # This can be adjusted manually. If really huge dump, I set %.4d, else %.3d is enough.
    INDEX=`printf '%.3d' $i`
    echo "Processing stream $INDEX ..."
    if [ ! -e  ".skip_non-TLS_stream" ]; then
        echo "$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.raw"
        $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.raw
    
        #ls -l ${dump}_s$INDEX.raw
        cat ${dump}_s$INDEX.raw \
        | grep -A1000000000 =================================================================== \
        > ${dump}_s$INDEX.raw.CLEAN ;
        wc_l=$(cat ${dump}_s$INDEX.raw.CLEAN | wc -l) ; #echo $wc_l;
        wc_l_head=$(echo $wc_l-1|bc); #echo $wc_l_head;
        wc_l_tail=$(echo $wc_l_head-5|bc); #echo $wc_l_tail;
        cat ${dump}_s$INDEX.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s$INDEX.raw.FINAL;
        #ls -l ${dump}_s$INDEX.raw.CLEAN  ${dump}_s$INDEX.raw.FINAL;
        cat ${dump}_s$INDEX.raw.FINAL | xxd -r -p > ${dump}_s$INDEX.bin
        # To see why and if tshark still does in such way that this work, maybe sometime
        # in the future, reverse the commenting of these two lines below in particular, and investigate
        rm ${dump}_s$INDEX.raw*
        echo "Extracted:"
        ls -l ${dump}_s$INDEX.bin
    
        echo "$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.txt"
        $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s$INDEX.txt
        echo "Extracted:"
        ls -l ${dump}_s$INDEX.txt
    fi
    if [ ! -e  ".skip_TLS_stream" ]; then
        echo "$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,ssl,raw,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.raw"
        $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,ssl,raw,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.raw

        cat ${dump}_s${INDEX}-ssl.raw \
        | grep -A1000000000 =================================================================== \
        > ${dump}_s${INDEX}-ssl.raw.CLEAN ;
        wc_l=$(cat ${dump}_s${INDEX}-ssl.raw.CLEAN | wc -l) ; #echo $wc_l;
        wc_l_head=$(echo $wc_l-1|bc); #echo $wc_l_head;
        wc_l_tail=$(echo $wc_l_head-5|bc); #echo $wc_l_tail;
        cat ${dump}_s${INDEX}-ssl.raw.CLEAN | head -$wc_l_head|tail -$wc_l_tail > ${dump}_s${INDEX}-ssl.raw.FINAL;
        #ls -l ${dump}_s${INDEX}-ssl.raw.CLEAN  ${dump}_s${INDEX}-ssl.raw.FINAL;
        cat ${dump}_s${INDEX}-ssl.raw.FINAL | xxd -r -p > ${dump}_s${INDEX}-ssl.bin
        # To see why and if tshark still does in such way that this work, maybe sometime
        # in the future, reverse the commenting of these two lines below in particular, and investigate
        rm ${dump}_s${INDEX}-ssl.raw*
        echo "Extracted:"
        ls -l ${dump}_s$INDEX-ssl.bin
        #read FAKE

        echo "$TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,ssl,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.txt"
        $TSHARK -o "tls.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,ssl,ascii,$i | grep -E '[[:print:]]' > "${dump}"_s${INDEX}-ssl.txt
        echo "Extracted:"
        ls -l ${dump}_s$INDEX-ssl.txt
    fi
done
