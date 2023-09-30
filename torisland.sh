#!/usr/bin/bash

stty -echoctl

BRed='\033[1;31m' 
NC='\033[0m'
BBlue='\033[1;34m'
BGreen='\033[1;32m'

trap '' INT
trap ''  QUIT
trap ''  TSTP
trap 'echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} GoodBye! ${NC}"' EXIT

readonly homeCountry='<your_country>' 
readonly virtual_address="10.192.0.0/10" 
readonly trans_port="9040" 
readonly dns_port="5353" 
readonly tor_uid="$(id -u debian-tor)" 
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" 
starTime=$(date +%s%N)

banner(){
clear
sleep 0.5
echo -e "${BRed}

	▄▄▄█████▓ ▒█████   ██▀███      ██▓  ██████  ██▓    ▄▄▄       ███▄    █ ▓█████▄ 
	▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒   ▓██▒▒██    ▒ ▓██▒   ▒████▄     ██ ▀█   █ ▒██▀ ██▌
	▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒   ▒██▒░ ▓██▄   ▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒░██   █▌
	░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄     ░██░  ▒   ██▒▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█▄   ▌
	  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒   ░██░▒██████▒▒░██████▒▓█   ▓██▒▒██░   ▓██░░▒████▓ 
	  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░   ░▓  ▒ ▒▓▒ ▒ ░░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒▓  ▒ 
	    ░      ░ ▒ ▒░   ░▒ ░ ▒░    ▒ ░░ ░▒  ░ ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░ ░ ▒  ▒ 
	  ░      ░ ░ ░ ▒    ░░   ░     ▒ ░░  ░  ░    ░ ░    ░   ▒      ░   ░ ░  ░ ░  ░ 
		     ░ ░     ░         ░        ░      ░  ░     ░  ░         ░    ░    
		                                                                ░      

${NC}"
sleep 0.5
echo -e "${BBlue} [+] ${NC} ${BGreen} $(date +"%A %d %B %Y") ${NC}"
}

check_packages(){
	nCount=0
	if ! dpkg -s iptables >/dev/null 2>&1; then 
		echo -e "${BRed} [-] iptables is not installed ${NC}"; echo -e "${BRed} [-] Install using: sudo apt-get install -y iptables ${NC}"; ((nCount++)); fi
	if ! dpkg -s tor >/dev/null 2>&1; then 
		echo -e "${BRed} [-] tor is not installed ${NC}"; echo -e "${BRed} [-] Install using: sudo apt-get install -y tor ${NC}"; ((nCount++)); fi	
	if ! dpkg -s curl >/dev/null 2>&1; then 
		echo -e "${BRed} [-] curl is not installed ${NC}"; echo -e "${BRed} [-] Install using: sudo apt-get install -y curl ${NC}"; ((nCount++)); fi	
	if [ $nCount -gt 0 ]; then exit; fi
}

check_ip(){
	torStatus=$(systemctl is-active tor.service)
	if [ $torStatus = 'failed' ]; then echo -e "${BRed} [$(date +"%T")] Connectivity error detected  ${NC}"; reboot; return; 
	elif [ $torStatus = 'inactive' ]; then tor_start; return;
	else 
		checkOnline=$(curl -Is http://www.google.com | head -1 | grep 200)
		if [ -z "$checkOnline" ]; then 
			echo -e "${BRed} [$(date +"%T")] Clearnet connectivity error detected  ${NC}";
			if [ $torStatus = 'active' ]; then
				checkTor=$(curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -Is https://check.torproject.org | head -1 | grep 200)
				if [ -z "$checkTor" ]; then 
					echo -e "${BRed} [$(date +"%T")] Please check your internet connectivity ${NC}"
					return 
				else
					echo -e "${BRed} [$(date +"%T")] Tor connectivity error detected  ${NC}"; reboot; return;
				fi
			else	
				echo -e "${BRed} [$(date +"%T")] Please check your internet connectivity or speed  ${NC}"
				return 
			fi
		fi	
	fi	
	
	echo -e "${BBlue} [$(date +"%T")] Checking Public ip address........  ${NC}"
	publicIp=$(curl -s https://api.ipify.org) 
	if [ -z "$publicIp" ]; then 
		echo -e "${BRed} [$(date +"%T")] Unable to retrieve public address ${NC}"	
		change_ip
		return
	else
		echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} Public ip address is:${NC} ${BBlue} $publicIp  ${NC}";
		countryName=$(curl -s http://ip-api.com/json/$publicIp | jq -r '.country') 
		if [ -z "$countryName" ]; then echo -e "${BRed} [$(date +"%T")] Unable to retrieve public address country ${NC}"; change_ip; return;		
		else 
			echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} Current Public Ip Country is:${NC} ${BBlue} $countryName ${NC}"; 
			if [ "$countryName" = "$homeCountry" ]; then 
				echo -e "${BRed} [$(date +"%T")] Your anonimity is at risk, your ip address points back to $homeCountry ${NC}"
				if [ $torStatus = 'active' ] || [ $torStatus = 'failed' ]; then  
					echo -e "${BRed} [$(date +"%T")] Connectivity error detected  ${NC}"; reboot; return;
				else echo -e "${BBlue} [$(date +"%T")] Activating Tor Network ${NC}"; tor_start; return; fi	
			fi
		fi	
	fi
}

change_ip(){
	echo -e "${BBlue} [$(date +"%T")] Changing Public ip address........  ${NC}"; systemctl restart tor.service; sleep 2;  starTime=$(date +%s%N); check_ip;
}

reboot(){
	sleep 0.5; echo -e "${BRed} [$(date +"%T")] Rebooting Tor connectivity........  ${NC}"; tor_stop; sleep 0.5; 
	echo -e "${BRed} [$(date +"%T")] booting Tor connectivity........  ${NC}"; tor_start; starTime=$(date +%s%N); sleep 0.5;
}

tor_start(){
	systemctl start tor.service 
	torStatus=$(systemctl is-active tor.service)
	if [ $torStatus = 'inactive' ]; then systemctl start tor.service;  fi
	echo nameserver 127.0.0.1 > /etc/resolv.conf 
	systemctl --system daemon-reload
	sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 
	sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 
	iptables -F 
	iptables -X 
	iptables -Z
	iptables -t nat -F 
	iptables -t nat -X 
	iptables -P INPUT ACCEPT 
	iptables -P FORWARD ACCEPT 
	iptables -P OUTPUT ACCEPT 
	iptables -t nat -A OUTPUT -d $virtual_address -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port 
	iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $dns_port 
	iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN  
	iptables -t nat -A OUTPUT -o lo -j RETURN   
	for lan in $non_tor; do iptables -t nat -A OUTPUT -d $lan -j RETURN; done 
	iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port 
	iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT 
	iptables -A INPUT -i lo -j ACCEPT 
	iptables -A INPUT -j DROP 
	iptables -A FORWARD -j DROP
	iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP 
	iptables -A OUTPUT -m state --state INVALID -j DROP 
	iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT 
	iptables -A OUTPUT -m owner --uid-owner $tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT 
	iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT  
	iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT  
	iptables -A OUTPUT -j DROP 
	iptables -P INPUT DROP 
	iptables -P FORWARD DROP 
	iptables -P OUTPUT DROP
	check_ip
	echo -e "${BGreen} [$(date +"%T")] Tor Booted successfull ${NC}";
}

tor_stop(){
	iptables -F 
	iptables -X 
	iptables -t nat -F 
	iptables -t nat -X 
	iptables -Z
	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
	iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport 22 -j DROP
	iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	systemctl stop tor.service 
	echo nameserver 192.168.31.202 > /etc/resolv.conf 
	sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 
	sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 
	echo "VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
DNSPort 5353" > /etc/tor/torrc
	echo -e "${BGreen} [$(date +"%T")] Tor Shutdown successfull ${NC}";
}

checkConnectivity(){
	checkOnline=$(curl -Is http://www.google.com | head -1 | grep 200)
	if [ -z "$checkOnline" ]; then 
		if [ $torStatus = 'active' ]; then
			echo -e "${BRed} [$(date +"%T")] Clearnet connectivity error detected  ${NC}";
			checkTor=$(curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -Is https://check.torproject.org | head -1 | grep 200)
			if [ -z "$checkTor" ]; then echo -e "${BRed} [$(date +"%T")] Please check your internet connectivity ${NC}"; return 
			else echo -e "${BRed} [$(date +"%T")] Connectivity error detected  ${NC}"; reboot; return; fi
		else echo -e "${BRed} [$(date +"%T")] Please check your internet connectivity ${NC}"; return 
		fi
	else echo -e "${BGreen} [$(date +"%T")] Connectivity test successfull ${NC}"; fi	
}

auto_tor_check(){
	echo -e "${BGreen} [$(date +"%T")] Running Automatic Tor Network Bot ${NC}"; 
	while :
	do
		localIp=$(ifconfig | grep broadcast | awk '{print $2}')
		if [ -z "$localIp" ]; then echo -e "${BRed} [$(date +"%T")] You are not connected to the Internet ${NC}";  break; 
		else 
			endDate=$(date +%s%N); diffTime=$((endDate-starTime)); timerC=$(( diffTime / 1000000000 ));
			random_ip=$(shuf -i 3600-21600 -n 1); random_no=$(shuf -i 60-900 -n 1);
			if [ $timerC -gt $random_ip ]; then change_ip; 
			else checkConnectivity; fi
			
			read -t $random_no  -p "stop bot? (y/n) > " autoCheck
			echo ''
			if [[ $autoCheck = "y" || $autoCheck = "yes"  ]]; then break; fi
		fi	
	done
}

help(){
	echo ""
	echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} List of Useful Commands ${NC}"
	echo ""
	echo -e "${BBlue} [$(date +"%T")] start, boot, darknet		Start Tor Network  ${NC}"
	echo -e "${BBlue} [$(date +"%T")] stop, shutdown, clearnet		Stop Tor Network  ${NC}"
	echo -e "${BBlue} [$(date +"%T")] restart, reboot			Restart Tor Network  ${NC}"
	echo -e "${BBlue} [$(date +"%T")] check				Check Tor Network Ip Address ${NC}"
	echo -e "${BBlue} [$(date +"%T")] test				Test Tor Network Connectivity Status ${NC}"
	echo -e "${BBlue} [$(date +"%T")] change				Change Tor Network Ip Address ${NC}"
	echo -e "${BBlue} [$(date +"%T")] auto				Test Tor Network Connectivity and debug automatically using time range ${NC}"
	echo -e "${BBlue} [$(date +"%T")] exit				Stop Running The Script  ${NC}"
	echo -e "${BBlue} [$(date +"%T")] sexit				Stop Tor Network and Stop Running The Script  ${NC}"
	echo -e "${BBlue} [$(date +"%T")] help				Get List Of All Useful Commands  ${NC}"
	echo ""
	echo ""
	echo -e "${BBlue} [$(date +"%T")] Incase of network issues you can also debug using: sudo service NetworkManager restart ${NC}"
	echo ""
	echo ""
}

##########################################################################################
##########################################################################################
##########################################################################################
check_packages
localIp=$(ifconfig | grep broadcast | awk '{print $2}')
if [ -z "$localIp" ]; then echo -e "${BRed} [-] You are not connected to the Internet ${NC}"; echo -e "${BRed} [-] Internet access is required ${NC}"; exit; fi
if [ "$EUID" -ne 0 ]; then echo -e "${BRed} [-] Please run as root ${NC}"; exit; fi
banner
echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} Internet Access Detected ${NC}"
echo -e "${BBlue} [$(date +"%T")] ${NC} ${BGreen} Local ip address is:${NC} ${BBlue}$localIp ${NC}"
echo -e "${BBlue} [$(date +"%T")] ${BRed} use the 'help' command to get a list of useful commands. ${NC}"
check_ip
starTime=$(date +%s%N);
while :
do
	read -p "└─(command)─> " commandLine
	if [[ $commandLine = "start" || $commandLine = "boot" || $commandLine = "darknet"  ]]; then tor_start;
	elif [[ $commandLine = "stop" || $commandLine = "shutdown" || $commandLine = "clearnet" ]]; then tor_stop;
	elif [[ $commandLine = "reboot" || $commandLine = "restart" ]]; then reboot;
	elif [[ $commandLine = "check" ]]; then check_ip; 
	elif [[ $commandLine = "test" ]]; then checkConnectivity;
	elif [[ $commandLine = "change" ]]; then change_ip;
	elif [[ $commandLine = "auto" ]]; then auto_tor_check;
	elif [[ $commandLine = "exit" ]]; then break;
	elif [[ $commandLine = "sexit" ]]; then tor_stop; break;
	elif [[ $commandLine = "help" ]]; then help;
	else
		echo -e "${BRed} [$(date +"%T")] Command not found, use the 'help' command to get a list of useful commands ${NC}";
	fi
done
