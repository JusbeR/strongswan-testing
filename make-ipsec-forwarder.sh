#!/usr/bin/env bash

set -eu

insert_if_not_exists() {
  grep -qe "^$1" "$2" || echo "$1" >> "$2"
}

# Read IP address
SERVER_IP_ADDR=$(ifconfig enp0s8 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
echo "Using server address $SERVER_IP_ADDR"
USER=teppo
PASS=pass

apt-get update
apt-get install -y strongswan strongswan-plugin-eap-mschapv2 moreutils 
# iptables-persistent

# Cert creation

mkdir -p vpn-certs
cd vpn-certs

## Root key
ipsec pki --gen --type rsa --size 4096 --outform pem > server-root-key.pem
chmod 600 server-root-key.pem

## Root CA cert
ipsec pki --self --ca --lifetime 3650 \
--in server-root-key.pem \
--type rsa --dn "C=US, O=VPN Server, CN=VPN Server Root CA" \
--outform pem > server-root-ca.pem

## Server key + cert. Sign with root cert
ipsec pki --gen --type rsa --size 4096 --outform pem > vpn-server-key.pem
ipsec pki --pub --in vpn-server-key.pem \
--type rsa | ipsec pki --issue --lifetime 1825 \
--cacert server-root-ca.pem \
--cakey server-root-key.pem \
--dn "C=US, O=VPN Server, CN=$SERVER_IP_ADDR" \
--san $SERVER_IP_ADDR \
--flag serverAuth --flag ikeIntermediate \
--outform pem > vpn-server-cert.pem

cp ./vpn-server-cert.pem /etc/ipsec.d/certs/vpn-server-cert.pem
cp ./vpn-server-key.pem /etc/ipsec.d/private/vpn-server-key.pem
cp ./server-root-ca.pem /etc/ipsec.d/cacerts/.

sudo chown root /etc/ipsec.d/private/vpn-server-key.pem
sudo chgrp root /etc/ipsec.d/private/vpn-server-key.pem
sudo chmod 600 /etc/ipsec.d/private/vpn-server-key.pem

## Client cert. Also sign with root cert
ipsec pki --gen --type rsa --size 2048 --outform pem > client-key.pem
chmod 600 client-key.pem

ipsec pki --pub --in client-key.pem --type rsa | ipsec pki --issue --lifetime 730 --cacert server-root-ca.pem --cakey server-root-key.pem --dn "C=US, O=VPN Server, CN=$USER@$SERVER_IP_ADDR" --san "$USER@$SERVER_IP_ADDR" --outform pem > client-cert.pem

## p12 pkg for client usage
openssl pkcs12 -export -passout pass:pass -inkey client-key.pem -in client-cert.pem -name "$USER's VPN Certificate" -certfile server-root-ca.pem -caname "VPN Server Root CA" -out client.p12

# Strongswan configuration
cd ..
cp /etc/ipsec.conf /etc/ipsec.conf.original
CMD="s/##SERVER_IP##/$SERVER_IP_ADDR/g"

sed -i -e "$CMD" ipsec.conf
cp ipsec.conf /etc/ipsec.conf

## Set server IP + usernames
insert_if_not_exists "$SERVER_IP_ADDR : RSA \"/etc/ipsec.d/private/vpn-server-key.pem\"" "/etc/ipsec.secrets"
insert_if_not_exists "$USER %any% : EAP \"$PASS\"" "/etc/ipsec.secrets"

ipsec reload

# Firewall & forwarding

# Clear everything
ufw disable
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -Z

# Leave current connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# localhost
iptables -A INPUT -i lo -j ACCEPT
#IPSec ports
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
# Gets cryptic...
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.10/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.10/24 -j ACCEPT
# NAT VPN subnet traffic to eth0
iptables -t nat -A POSTROUTING -s 10.10.10.10/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.10/24 -o eth0 -j MASQUERADE
# Skip NAT rules for rest of the matching packets https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling#General-NAT-problems
iptables -t nat -I POSTROUTING -m policy --pol ipsec --dir out -j ACCEPT
# MSS clamping
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.10/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
# Drop everything else
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP

# TODO: Rules are not permanent
#netfilter-persistent save
#netfilter-persistent reload

# Kernel IP packet forwarding
insert_if_not_exists "net.ipv4.ip_forward = 1" "/etc/sysctl.conf"
insert_if_not_exists "net.ipv4.conf.all.accept_redirects = 0" "/etc/sysctl.conf"
insert_if_not_exists "net.ipv4.conf.all.send_redirects = 0" "/etc/sysctl.conf"
insert_if_not_exists "net.ipv4.ip_no_pmtu_disc = 1" "/etc/sysctl.conf"
sysctl -p

# Copy files for the host(client usage)
cp vpn-certs/server-root-ca.pem /vagrant/.
cp vpn-certs/client.p12 /vagrant/.
echo "Server root CA cert can be found from ./server-root-ca.pem"
echo "Client certs can be found from ./client.p12"
echo "Client username/pass $USER/$PASS"
echo "Server IP address is $SERVER_IP_ADDR"
echo "DONE"

