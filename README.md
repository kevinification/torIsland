## Tor Island

### Requirements

#### iptables, curl, tor

#### if not installed, install using:

#### sudo apt-get install -y iptables tor curl

#### Before running the script edit your home country to your country of origin,
#### this homecountry feature allows your device not to reflect back to that country
#### and if a public ip address does it is changed automatically.

#### readonly homeCountry=<your_country>

#### you can use https://dnsleaktest.com/ to retrieve the correct spellings

## Before running the script make sure you backup these 2 file:
### /etc/tor/torrc
### /etc/resolv.conf


## Kelvinification
### torIsland
#### https://github.com/kevinification/torIsland.git
### Version 7.4