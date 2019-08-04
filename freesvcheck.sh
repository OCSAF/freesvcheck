#!/bin/bash

#####################################################################
################### OCSAF FREE SURVEILLANCE CHECK ###################
#####################################################################


###############################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org                 #
#  This script helps to find out via network sniffing if the traffic can be monitored and                     # 
#  what connections your device has to the outside world.                                                     #
#                                                                                                             #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!                    #
#                                                                                                             #
#  This script is based on the basic idea of Tore (cr33y). Together we have further defined the functions.    #
#  Script coding by Mathias Gut Netchange Informatik GmbH under GNU-GPLv3                                     #
#  Special thanks to the community and also for your personal project support.                                #
###############################################################################################################


#######################
### Preparing tasks ###
#######################

#Check if TSHARK is installed.
program=(tshark)
for i in "${program[@]}"; do
	if [ -z $(command -v ${i}) ]; then
		echo "${i} is not installed."
		count=1
	fi

	if [[ $count -eq 1 ]]; then
		exit
	fi
done
unset program
unset count


####################
###  TOOL USAGE  ###
####################

usage() {
	echo "From the Free OCSAF project"
	echo "OCSAF FREESVCHECK v0.1 - GPLv3 (https://freecybersecurity.org)"
	echo "Use only with legal authorization and at your own risk!"
       	echo "ANY LIABILITY WILL BE REJECTED!"
       	echo ""	
	echo "USAGE:" 
	echo "  ./freesvcheck.sh -i <argument1>"
       	echo ""	
	echo "EXAMPLE:"
       	echo "  ./freesvcheck.sh -i eth0"
       	echo "  ./freesvcheck.sh -i eth0 -t 10.10.10.10"
       	echo "  ./freesvcheck.sh -i eth0 -m 00:00:00:00:00:00 -d"
       	echo ""	
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -i, interface (mandatory)"
	echo "  -d, Filters DNS instead of default SNI sniffing"
	echo "  -m, <mac> - target mac address"
	echo "  -t, <ip> - target ip address"
	echo "  -f, <file> - path to pcap file for analysis"
	echo "  -c, no color scheme set"
       	echo ""
	echo "NOTES:"
	echo "#See also the MAN PAGE - https://freecybersecurity.org"
}


###############################
### GETOPTS - TOOL OPTIONS  ###
###############################

while getopts "t:i:m:f:hcd" opt; do
	case ${opt} in
		h) usage; exit 1;;
		i) interface="$OPTARG"; opt_arg1=1;;
		m) mac="$OPTARG"; opt_arg2=1;;
		t) ip="$OPTARG"; opt_arg2=1;;
		f) file="$OPTARG"; opt_arg1=1;;
		d) dns=1;;
		c) nocolor=1;;
		\?) echo "**Unknown option**" >&2; echo ""; usage; exit 1;;
        	:) echo "**Missing option argument**" >&2; echo ""; usage; exit 1;;
		*) usage; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if opt_arg1 or opt_arg2 is set
if [ "$opt_arg1" == "" ] && [ "$opt_arg2" == "" ]; then
	echo "**No argument set**"
	echo ""
	usage
	exit 1
fi


###############
### COLORS  ###
###############

greenON=""
redON=""
colorOFF=""

if [[ $color -eq 1 ]]; then
	colorOFF='\e[39m'
	greenON='\e[92m'
	redON='\e[91m'
fi


#################
### FUNCTIONS ###
#################

funcFilter() {
	local _date_time
	local _interface
	local _file
	local _filter
	local _filter_ip
	local _filter_mac
	local _fields
	local _input
	local _dns

	_date_time=$(date +%Y-%m-%d_%H:%M:%S)
	_interface=$interface
	_file=$file
	_dns=$dns
	
	#interface or file
	if [ "${_interface}" != "" ]; then
		_input="-i ${_interface}"
	elif [ "${_file}" != "" ]; then
		_input="-r ${_file}"
	fi

	#ip filter
	if [ "${ip}" != "" ]; then
		_filter_ip="&& (ip.src == ${ip})"
	fi

	#mac filter
	if [ "${mac}" != "" ]; then
		_filter_mac="&& (eth.src == ${mac})"
	fi

	#SNI or DNS filtering
	if ! [[ ${_dns} -eq 1 ]]; then
		_filter="(ssl.handshake.type == 1 && ssl.handshake.extension.type == "server_name")"
		_fields="-e frame.time -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name"
	elif [[ ${_dns} -eq 1 ]]; then
		_filter="(dns.qry.name) && (dns.flags.response == 0)"
		_fields="-e frame.time -e ip.src -e ip.dst -e dns.qry.name"
	fi

	#time
	echo "Start-Time: ${_date_time}"

	#TSHARK command
	tshark ${_input} -T fields ${_fields} \
		-Y "${_filter} ${_filter_ip} ${_filter_mac}"

}


############
### MAIN ###
############

echo ""
echo "#############################################"
echo "####  OCSAF FreeSurveillanceCheck GPLv3  ####"
echo "####  https://freecybersecurity.org      ####"
echo "#############################################"
echo ""

if [ "$opt_arg1" == "1" ]; then             #Query only one value
	funcFilter
fi

################### END ###################