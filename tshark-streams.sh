#!/bin/bash
#
# You should probably be able to find this program at:
#
# https://github.com/miroR/tshark-streams.git
#
# Apart from a recent Wireshark/tshark install, xxd is needed.
#
#TO_DO update this text
# If neither of the options "-Y $DISPLAYFILTER" or -l "$STREAMSLIST" is given,
# but only the -r "$PCAP_FILE" (and -k "$KEYLOGFILE" if there are TLS streams
# in the $PCAP_FILE), this script will extract all tcp(/tls) streams from your
# pcap file (-k "$KEYLOGFILE" may by implied if you $SSLKEYLOGILE is set right).
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
#
# Checkout some previous version up to early 2026 for some old less important
# links and tips related to this script.
#
# Released under BSD license, pls. see LICENSE, attached to this script (if
# not, the license is generic BSD)
#
# Copyright (c) 2016,2021,2022,2023,2026 Croatia Fidelis, Miroslav Rovis, <https://www.CroatiaFidelis.hr>
#

#TO_DO update this text
# Traces that, relative to available computing power, are too large, need to be
# split to be worked. Today all is mostly TLS, so mostly only splitting by
# streams allows for analysis. This script allows only for limiting traces to
# be worked to those under $pcap_size_limit set to some value (e.g.
# pcap_size_limit=1000000000 works only traces that are less than 1G in size),
# on the command line or in:
if [ -e "/home/$USER/.tshark_streams.conf" ]; then
    . /home/$USER/.tshark_streams.conf
fi

function ask()
{
    echo -n "$@" '[y/n] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

function ls_head_tail () {
    # we check $2 that it greps on any decimal number
    if [ ! -e "$1" ]; then
        echo "###########################################"
        echo "$1 non extant (fix the script if wrong)"
        sleep 5
        echo "###########################################"
    fi
    echo \$2: $2
    if [ -n "$2" ]; then
        echo pass _n \$2
    fi
    if ( echo $2 | grep -q '[0-9]' ); then
        echo pass grep on \$2
    else
        echo fail grep on \$2
    fi
    if [ -n "$2" ] && ( echo $2 | grep -q '[0-9]' ); then
        lines="$2"
    else
        echo in else
        lines="4"
    fi
    echo \$lines: $lines
    cat $1|head -n$lines
    echo "[...]"
    cat $1|tail -n$lines
    echo "(cat $1 head/tail $lines"
}

function show_help {
  echo "tshark-streams.sh - Extract TCP/TLS streams from \$PCAP_FILE"
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
  echo -e "    \t/home/<you>/.sslkey.log or some other) used during Pale Moon,"
  echo -e "    \tFirefox or some other NSS supporting browser's run, all properly set,"
  echo -e "    \tthen you don't need to set this flag"
  echo -e "    -l a list of streams' numbers, one per line, to extract (can use the"
  echo -e "    \t\${dump}_streams.ls-1 file gotten from, maybe interrupted"
  echo -e "    \tall-extraction run to pick from)"
  echo -e "    -Y a single stream number display filter (see 'man tshark', exampli gratia:"
  echo -e "    \t -Y \"tcp.stream==N\" where N is a number from among the available"
  echo -e "    \tfor your \$PCAP_FILE (you need to enter the whole expression)"
  echo -e "    -d primitive debugging hooks come to work, pls. read the script"
  echo ""
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Reset in case getopts has been used previously in the shell.
OPTIND=1
DISPLAYFILTER=""
#STREAMSLIST=""
KEYLOGFILE=""

while getopts "h?r:dY:l:k:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  PCAP_FILE=$OPTARG
        echo "gives: -r $PCAP_FILE (\$PCAP_FILE); since \$OPTARG: $OPTARG"
        ;;
    d)  export DEBUG="y"
        echo \$DEBUG: $DEBUG
        non_int_q $non_int_d/0005-debug-set
        ;;
    #TO_DO add code to use this? or remove?
    #Y)  DISPLAYFILTER=$OPTARG
    #    echo "gives: -Y $DISPLAYFILTER (\$DISPLAYFILTER); since \$OPTARG: $OPTARG"
    #    ;;
    #l)  STREAMSLIST=$OPTARG
    #    echo "gives: -l $STREAMSLIST (\$STREAMSLIST); since \$OPTARG: $OPTARG"
    #    ;;
    k)  KEYLOGFILE=$OPTARG
    echo "gives: -k $KEYLOGFILE (\$KEYLOGFILE); since \$OPTARG: $OPTARG"
        ;;
    esac
done

# Hardwired:
script_name=${0##*/}
script_name_d=$(echo $script_name|sed 's/\.sh//'|sed 's/\(.*\)/.\1-non-int/')
non_int_d=/home/$USER/${script_name_d}
echo \$non_int_d: $non_int_d
non_int_chk=$(ls -1 $non_int_d)
if [ -d "$non_int_d" ]; then
    if [ "X${non_int_chk}" != "X" ]; then
        echo -n "NOTIFICATION: "
        echo "ls -l/d \$non_int_d | head/tail -2"
        ls -l $non_int_d | head -2
        ls -l $non_int_d | tail -2
        ls -ld $non_int_d
    else
        echo "I.e.: \$non_int_d is empty. "
        echo "You might be asked at each single non_int_q's line of ${0##*/}."
    fi
    echo "We wait 1 sec for visibility of above."
    sleep 1
    # Here user can issue Ctrl-Z and manually manipulate $non_int_d, then issue fg,
    # or can quit and revise action to do.
fi

function non_int_q () {
    if [ "$DEBUG" == "y" ]; then
        mkdir -p $non_int_d
        if [ ! -e "$1" ]; then
            echo "$1 ?"
            ask
            if [ "$?" == 0 ]; then
                touch $1
                ls -l $1
                sleep 0.8 # enough to notify the user of $1
            fi
        fi
    fi
}

non_int_q $non_int_d/000-initial-non-interactive

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

# may not be needed:
#TMP="$(mktemp -d "/tmp/$dump.$$.XXXXXXXX")"
#ls -ld $TMP

pcap_size=$(ls -lL --time-style=posix-long-iso $dump.$ext | awk '{print $5}')
echo \$pcap_size: $pcap_size
non_int_q $non_int_d/001-variables-echoed
if [ "$pcap_size_limit_do_anyway" == "y" ]; then
    : # user decided to work this large $dump.$ext
else
    if [ "$pcap_size" -gt "$pcap_size_limit" ]; then
        echo "\$pcap_size larger then $pcap_size_limit (set in /home/$USER/.tshark_hosts_conv.conf):"
        echo "############################################################"
        echo "Generally it is better to preprocess/filter larger \$dump.\$ext before work"
        echo "I.e. we won't work this file: "
        ls -l $dump.$ext
        echo "set pcap_size_limit_do_anyway to y and run ${0##*/} on $dump.$ext again"
        echo "          if you really want to work it.              "
        echo "          (${0##*/} is exiting)              " |& tee -a $tHostsConvLog
        exit 0
        echo "############################################################"
    fi
fi
non_int_q $non_int_d/002-past-size-limit

# Used to be (2 ln):
#   WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
#   TSHARK=/some-place/wireshark-ninja/run/tshark
#   Replacing it with:
. shark2use

# previously here: if [ ! -n "$STREAMSLIST" ]; then...
# However, recently the changes have gone global: tls.streams do not necessarily
# correspond to tcp.streams, as used to be the case. So vars/files STREAMSLIST,
# STREAMS need to be replaced per tcp.stream, per tls.stream and per
# http2.streamid lists.
# To be complete, there is also ip.stream, but I'm not sure it is needed so
# I'll leave it out.
# in "_fno_tcps_tlss_http2s_http2sid" fno is for frame.number, s is for streams
if [ ! -e "${dump}_fno_tcps_tlss_http2s_http2sid.txt" ]; then 
    touch ${dump}_fno_tcps_tlss_http2s_http2sid.txt.lock
    $TSHARK -r $dump.$ext -T fields -e frame.number -e tcp.stream -e tls.stream -e http2.stream \
        -e http2.streamid | grep '[[:print:]]' > ${dump}_fno_tcps_tlss_http2s_http2sid.txt
    ls -l ${dump}_fno_tcps_tlss_http2s_http2sid.txt
    rm -v ${dump}_fno_tcps_tlss_http2s_http2sid.txt.lock
else
    while [ -e "${dump}_fno_tcps_tlss_http2s_http2sid.txt.lock" ]; do
        ls -l ${dump}_fno_tcps_tlss_http2s_http2sid.txt.lock
        echo sleep 5
        sleep 5
    done
fi

#NOTE 'sort -n -u' would say no stream when only one stream! Because it is
#+ number 0. So 'sort -g -u'
# If PCAP has no tcp.stream we will not work it
#debug 3ln
#awk 'BEGIN {FS="\t"; OFS="\t"} {print $2}' ${dump}_fno_tcps_tlss_http2s_http2sid.txt \
#    | sort -g -u | grep '[[:print:]]'
#read NOP
awk 'BEGIN {FS="\t"; OFS="\t"} {print $2}' ${dump}_fno_tcps_tlss_http2s_http2sid.txt \
    | sort -g -u | grep '[[:print:]]' > $dump-tcp.ls-1
ls_head_tail $dump-tcp.ls-1 3
echo \$dump_tcp_check: $dump_tcp_check
dump_tcp_check=$(<$dump-tcp.ls-1)
echo \$dump_tcp_check: $dump_tcp_check
non_int_q $non_int_d/00201-dump-tcp-check
if [ "X$dump_tcp_check" == "X" ]; then
    echo "########################################################################"
    echo "########################################################################"
    echo "$dump.$ext has no tcp.stream's. sleep 5 and exit 0"
    echo "########################################################################"
    echo "########################################################################"
    sleep 5
    rm -v $dump-tcp.ls-1
    exit 0
fi

# If PCAP has no tls.stream we will not work it
#debug 3ln
#awk 'BEGIN {FS="\t"; OFS="\t"} {print $3}' ${dump}_fno_tcps_tlss_http2s_http2sid.txt \
#    | sort -g -u | grep '[[:print:]]'
#read NOP
awk 'BEGIN {FS="\t"; OFS="\t"} {print $3}' ${dump}_fno_tcps_tlss_http2s_http2sid.txt \
    | sort -g -u | grep '[[:print:]]' > $dump-tls.ls-1
ls_head_tail $dump-tls.ls-1 3
echo \$dump_tls_check: $dump_tls_check
dump_tls_check=$(<$dump-tls.ls-1)
echo \$dump_tls_check: $dump_tls_check
non_int_q $non_int_d/00202-dump-tls-check
if [ "X$dump_tls_check" == "X" ]; then
    echo "########################################################################"
    echo "########################################################################"
    echo "$dump.$ext has no tls.stream's. sleep 5 and exit 0"
    echo "########################################################################"
    echo "########################################################################"
    sleep 5
    rm -v $dump-tls.ls-1
    exit 0
fi

# This sed inline produces exact copy of the ${dump}_fno_tcps_tlss_http2s_http2sid.txt it worked.
# (tested on 100+ PCAPs with various kind of traffic)
sed 's/\([1-9][0-9]\{,9\}\x09\([0-9]\{1,9\}\)\?\x09\)\([0-9]\{1,9\}\?\)\(,\3\)*\x09\([0-9]\{1,9\}\?\)\(\(,\5\)*\)\x09\(.*\)/\1\3\4\x09\5\6\x09\8/g' \
    ${dump}_fno_tcps_tlss_http2s_http2sid.txt > ${dump}_fno_tcps_tlss_http2s_http2sid-SED.txt
ls -l ${dump}_fno_tcps_tlss_http2s_http2sid-SED.txt
if ( diff ${dump}_fno_tcps_tlss_http2s_http2sid.txt ${dump}_fno_tcps_tlss_http2s_http2sid-SED.txt ); then
    rm -v ${dump}_fno_tcps_tlss_http2s_http2sid-SED.txt
else
    echo "We exit here, the method applied does NOT work right with:"
    ls -l $dump.$ext
    echo "Because the sed script (read the source did not work right."
    echo "These files should be identical, and they differ:"
    ls -l ${dump}_fno_tcps_tlss_http2s_http2sid.txt \
        ${dump}_fno_tcps_tlss_http2s_http2sid-SED.txt
    exit 1
fi
# sed offers only 9 backreferences. Need to work in stages.
# The backreference \4 that matches  '\(,\3\)*' in the sed debugging can now be
# freely left out.  Namely, if the sed script hadn't produced identical copy
# above, that would mean there were other tls.stream numbers on that same line
# in that field, and there are none.
# The same holds for \6 matching '\(\(,\5\)*\)' and http2.stream numbers.
#
sed 's/\([1-9][0-9]\{,9\}\x09\([0-9]\{1,9\}\)\?\x09\)\([0-9]\{1,9\}\?\)\(,\3\)*\x09\([0-9]\{1,9\}\?\)\(\(,\5\)*\)\x09\(.*\)/\1\3\x09\5\x09\8/g' \
    ${dump}_fno_tcps_tlss_http2s_http2sid.txt > ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt
ls -l ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt # C is for clean
non_int_q $non_int_d/00203-SED-C
# In the tshark produced file, and reamins in the above results there is only
# one tcp.stream per frame.number.
# Now we've made that also only one tls.stream number is listed per frame number
# And there's one http2.stream number per frame number.
# I expect that http2.streamid's of any http2.stream come from same unique tls.stream.
# So far I haven't seen the http2.stream would have any other number than 1.
# I.e. no multiple http2 streams per tls stream.
# Let's check if that is so with this PCAP:
echo "awk '{print \$4}' \${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt | sort -u | grep '[[:print:]]'"
awk '{print $4}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt | sort -u | grep '[[:print:]]'
awk 'BEGIN {FS="\t"; OFS="\t"} {print $4}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt \
    | sort -g -u | grep '[[:print:]]' > $dump-http2.ls-1
dump_http2_check=$(<$dump-http2.ls-1)
echo \$dump_http2_check: $dump_http2_check
echo X\$dump_http2_checkX: X${dump_http2_check}X
if [ "X$dump_http2_check" == "X" ]; then
    echo "There are no http2.streams in this PCAP"
    non_int_q $non_int_d/00204-no-http2-streams
else
    if [ "$dump_http2_check" == "1" ]; then
        echo "There's only http2.stream==1 ever from any number tls.stream."
    else
        echo "########################################################################"
        echo "########################################################################"
        echo "We exit here, the method applied does NOT work right with:"
        ls -l $dump.$ext
        echo "Because there are either more than 1 http2.stream's per some tls.streams."
        echo "See:"
        echo "awk '{print \$4}' \${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt | sort -u | grep '[[:print:]]'"
        awk '{print $4}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt | sort -u | grep '[[:print:]]'
        echo "sleep 5 and exit 1"
        echo "########################################################################"
        echo "########################################################################"
        sleep 5
        exit 1
    fi
fi
rm -v $dump-http2.ls-1

awk 'BEGIN {FS="\t"; OFS="\t"} {print $1,$2,$3,$5}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-C.txt \
    > ${dump}_fno_tcps_tlss_http2s_http2sid-SED-Cr.txt # Cr for [C]LEAN [r]eally
# And we now have only 4 fields per any frame.number for the PCAP.
ls -l ${dump}_fno_tcps_tlss_http2s_http2sid-SED-Cr.txt

non_int_q $non_int_d/00207-SED-Cr
# temporary: remove the below:
#exit 0

# We now from ...-SED-Cr.txt create lists $STREAMS-tcp and $STREAMS-tls.
# Used to be what recently failed to apply. Big Tech were the first to introduce the said changes (see above):
# STREAMS=$($TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -Y "$DISPLAYFILTER" -T fields -e tcp.stream | sort -n | uniq)
STREAMS_tcpf="$dump-tcps.ls-1" # f is for file
STREAMS_tlsf="$dump-tlss.ls-1"
echo \$STREAMS_tcpf: $STREAMS_tcpf
echo \$STREAMS_tlsf: $STREAMS_tlsf
awk 'BEGIN {FS="\t"; OFS="\t"} {print $2}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-Cr.txt \
    | sort -g -u | grep '[[:print:]]' > $STREAMS_tcpf
awk 'BEGIN {FS="\t"; OFS="\t"} {print $3}' ${dump}_fno_tcps_tlss_http2s_http2sid-SED-Cr.txt \
    | sort -g -u | grep '[[:print:]]' > $STREAMS_tlsf
ls_head_tail $STREAMS_tcpf 3
ls_head_tail $STREAMS_tlsf 3
non_int_q $non_int_d/003-STREAMS-tcp-tls-files
STREAMS_tcp=$(<$STREAMS_tcpf)
echo \$STREAMS_tcp: $STREAMS_tcp
STREAMS_tls=$(<$STREAMS_tlsf)
echo \$STREAMS_tls: $STREAMS_tls
non_int_q $non_int_d/00303-STREAMS-tcp-tls-vars
> ${dump}_streams.ls-1_DONE #truncate, just in case
# One loop to list existing streams if any
for i in $STREAMS_tls; do 
    INDEX=`printf '%.3d' $i`
    for stream_file in ${dump}_s$INDEX.raw ${dump}_s$INDEX.raw.CLEAN ${dump}_s$INDEX.raw.FINAL ${dump}_s$INDEX.bin \
        ${dump}_s$INDEX.txt ${dump}_s$INDEX-tls.txt ; do
        # not checking for -s $stream_file here, as if HTTP, the empty -tls.{bin,txt} may already been worked
        if [ -e "$stream_file" ]; then
            if ( echo $stream_file|grep '\.raw' ); then
                rm -iv $stream_file
            else
                echo $stream_file >> ${dump}_streams.ls-1_DONE
            fi
        fi
    done
    non_int_q $non_int_d/022-stream-file-raw
done
ls_head_tail ${dump}_streams.ls-1_DONE 3
non_int_q $non_int_d/030-streams-ls-1-done
echo "You can now set either:"
echo ".skip_non-TLS_stream (type nt)"
echo ".skip_TLS_stream (type st)"
#TO_DO make this work but only in non-interactive
non_int_q $non_int_d/040-befor-set-skip
if [ "$skipping" == "nt" ]; then touch .skip_non-TLS_stream ; ls -l .skip_non-TLS_stream ; fi
if [ "$skipping" == "st" ]; then touch .skip_TLS_stream ; ls -l .skip_TLS_stream ; fi
for i in $STREAMS_tcp; do 
    # This can be adjusted manually. If really huge dump, I set %.4d, else %.3d is enough.
    INDEX=`printf '%.3d' $i`
    echo "Processing stream $INDEX ..."
    if [ ! -e  ".skip_non-TLS_stream" ]; then
        if [ ! -e "${dump}_s$INDEX.raw" ] && [ ! -e "${dump}_s$INDEX.bin" ]; then
            echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > ${dump}_s$INDEX.raw"
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i | grep -E '[[:print:]]' > ${dump}_s$INDEX.raw
        
            cat ${dump}_s$INDEX.raw \
            | grep -A1000000000 =================================================================== \
            > ${dump}_s$INDEX.raw.CLEAN ;
            cat ${dump}_s$INDEX.raw.CLEAN | tail -n+6|head -n-1 > ${dump}_s$INDEX.raw.FINAL;
            cat ${dump}_s$INDEX.raw.FINAL | xxd -r -p > ${dump}_s$INDEX.bin
            # To see why and if tshark still does in such way that this work, maybe sometime
            # in the future, comment out the line below, and investigate
            non_int_q $non_int_d/050-befor-rm-index-raw
            rm ${dump}_s$INDEX.raw*
            echo "Extracted:"
            ls -l ${dump}_s$INDEX.bin
        fi
    
        if [ ! -e "${dump}_s$INDEX.txt" ]; then
            echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > ${dump}_s$INDEX.txt"
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -qz follow,tcp,ascii,$i | grep -E '[[:print:]]' > ${dump}_s$INDEX.txt
            echo "Extracted:"
            ls -l ${dump}_s$INDEX.txt
        fi
    fi
done
for i in $STREAMS_tls; do 
    # This can be adjusted manually. If really huge dump, I set %.4d, else %.3d is enough.
    INDEX=`printf '%.3d' $i`
    echo "Processing stream $INDEX ..."
    if [ ! -e  ".skip_TLS_stream" ]; then
        if [ ! -e "${dump}_s${INDEX}-tls.raw" ] && [ ! -e "${dump}_s${INDEX}-tls.bin" ]; then
            echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -T fields -e data -qz follow,tls,raw,$i | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls.raw"
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -T fields -e data -qz follow,tls,raw,$i | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls.raw
            cat ${dump}_s${INDEX}-tls.raw | sed 's/^Follow: .*\|^Filter: .*\|Node 0: .*\|Node 1: .*\|===================================================================//g' \
                | grep '[[:print:]]' > ${dump}_s${INDEX}-tls.raw.FINAL
            #ls -l ${dump}_s${INDEX}-tls.raw.CLEAN  ${dump}_s${INDEX}-tls.raw.FINAL;
            cat ${dump}_s${INDEX}-tls.raw.FINAL | xxd -r -p > ${dump}_s${INDEX}-tls.bin
            # To see why and if tshark still does in such way that this work, maybe sometime
            # in the future, comment out the line below, and investigate
            non_int_q $non_int_d/060-befor-rm-index-raw-all
            rm ${dump}_s${INDEX}-tls.raw*
            echo "Extracted:"
            ls -l ${dump}_s$INDEX-tls.bin
            non_int_q $non_int_d/070-tls-bin
        fi

        if [ ! -e "${dump}_s${INDEX}-tls.txt" ]; then
            echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -qz follow,tls,ascii,$i | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls.txt"
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -qz follow,tls,ascii,$i | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls.txt
            echo "Extracted:"
            ls -l ${dump}_s$INDEX-tls.txt
            non_int_q $non_int_d/080-tls-txt
        fi
        if ( grep ${dump}_s${INDEX}_h2.ls-1 ${dump}_streams_h2_EMPTY.ls-1 ); then
            echo "(grep ${dump}_s${INDEX}_h2.ls-1 ${dump}_streams_h2_EMPTY.ls-1)"
            echo "is sempty, not working it"
            continue
        fi
        echo \$INDEX: $INDEX
        #echo \$PREVIOUS_h2: $PREVIOUS_h2
        #read NOP
        #if [ -e "${dump}_s${INDEX}_h2.ls-1" ]; then
        #    cp -av ${dump}_s${INDEX}_h2.ls-1 ${dump}_s${INDEX}_h2.ls-1_$(date +%s)
        #fi
        #touch .${dump}_s${INDEX}_h2.ls-1.lock
        if [ ! -e "${dump}_s${INDEX}_h2.ls-1" ] && !( grep -q ${dump}_s${INDEX}_h2.ls-1 ${dump}_streams_h2_EMPTY.ls-1 ) && \
            [ ! -e ".${dump}_s${INDEX}_h2.ls-1.lock" ]; then
            touch .${dump}_s${INDEX}_h2.ls-1.lock
            non_int_q $non_int_d/090-h2-lock-work-index
            echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -Y \"tcp.stream==$i\" -T fields -e http2.streamid | tr ',' '\12' | sort -n | grep '[[:print:]]' | uniq"
            $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -Y "tcp.stream==$i" -T fields -e http2.streamid | tr ',' '\12' | sort -n | grep '[[:print:]]' | uniq > ${dump}_s${INDEX}_h2.ls-1
            if [ ! -s "${dump}_s${INDEX}_h2.ls-1" ]; then
                echo ${dump}_s${INDEX}_h2.ls-1 >> ${dump}_streams_h2_EMPTY.ls-1
                rm -v ${dump}_s${INDEX}_h2.ls-1
                non_int_q $non_int_d/092-h2-empty
            fi
            rm -v .${dump}_s${INDEX}_h2.ls-1.lock
        fi
        if [ -s "${dump}_s${INDEX}_h2.ls-1" ] && [ ! -e ".${dump}_s${INDEX}_h2.ls-1.lock" ]; then
            H2_STREAMS=$(<${dump}_s${INDEX}_h2.ls-1)
            echo \$H2_STREAMS: $H2_STREAMS
            for h2 in $H2_STREAMS; do 
                echo \$i: $i
                echo \$h2: $h2
                H2INDEX=`printf '%.3d' $h2`
                echo \$H2INDEX: $H2INDEX
                if [ ! -e "${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw" ] && [ ! -e "${dump}_s${INDEX}-tls-h2-${H2INDEX}.bin" ] && [ ! -e ".${dump}_s${INDEX}-tls-h2-${H2INDEX}.lock" ]; then
                    touch .${dump}_s${INDEX}-tls-h2-${H2INDEX}.lock
                    non_int_q $non_int_d/094-h2index-lock
                    echo "$TSHARK -otls.keylog_file:$KEYLOGFILE -r \"$dump.$ext\" -T fields -e data -qz \"follow,http2,raw,$i,$h2\" | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw"
                    $TSHARK -otls.keylog_file:$KEYLOGFILE -r "$dump.$ext" -T fields -e data -qz "follow,http2,raw,$i,$h2" | grep -E '[[:print:]]' > ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw
                    ls -l ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw
                    cat ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw \
                    | grep -A1000000000 =================================================================== \
                    > ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.CLEAN ;
                    cat ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.CLEAN | tail -n+6|head -n-1 > ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.FINAL
                    ls -l ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.CLEAN  ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.FINAL
                    cat ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw.FINAL | xxd -r -p > ${dump}_s${INDEX}-tls-h2-${H2INDEX}.bin
                    # To see why and if tshark still does in such way that this work, maybe sometime
                    # in the future, comment out the line below, and investigate
                    rm ${dump}_s${INDEX}-tls-h2-${H2INDEX}.raw*
                    echo "Extracted:"
                    ls -l ${dump}_s$INDEX-tls-h2-${H2INDEX}.bin
                    rm -v .${dump}_s${INDEX}-tls-h2-${H2INDEX}.lock
                fi
            done
        fi
    fi
    non_int_q $non_int_d/099-befor-loop-item-end
done
# vim: set tabstop=4 expandtab:
