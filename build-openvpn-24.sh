#!/bin/bash
# Build OpenVPN 2.4 from source code

# install dependentcy packages
yum install epel-release -y
yum install gcc gcc-c++ systemd-devel lzo-devel lz4-devel openssl openssl-devel pkcs11-helper-devel pam-devel perl-macros systemd-units make net-tools unzip -y

# Create new user
useradd -d /etc/openvpn -s /sbin/nologin openvpn

# Download source code and build
cd /usr/local/src
wget https://swupdate.openvpn.org/community/releases/openvpn-2.4.6.tar.gz
tar xzvf openvpn-2.4.6.tar.gz
cd openvpn-2.4.6
./configure --enable-iproute2 \
	--with-crypto-library=openssl \
	--enable-pkcs11 \
	--enable-selinux \
	--enable-systemd \
	--enable-x509-alt-username \
	--enable-lzo \
	--docdir="/usr/share/doc/openvpn-2.4.6"

make && make install
wget -O /usr/lib/systemd/system/openvpn@.service https://raw.githubusercontent.com/vynt-kenshiro/build-openvpn-24/master/openvpn%40.service
systemctl daemon-reload

# Install EasyRSA-3.0.4
cd ../
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.zip
unzip EasyRSA-3.0.4.zip
mkdir /etc/openvpn/clients
mv EasyRSA-3.0.4 /etc/openvpn/easy-rsa
chown -R root:root /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa
echo '
set_var EASYRSA_REQ_COUNTRY	"VN"
set_var EASYRSA_REQ_PROVINCE	"HoChiMinh"
set_var EASYRSA_REQ_CITY	"HoChiMinh"
set_var EASYRSA_REQ_ORG	"Copyleft Certificate Co"
set_var EASYRSA_REQ_EMAIL	"ntv1090@gmail.com"
set_var EASYRSA_REQ_OU		"Technical"
set_var EASYRSA_KEY_SIZE	2048
set_var EASYRSA_ALGO		rsa
set_var EASYRSA_CURVE		secp384r1
set_var EASYRSA_CA_EXPIRE	3650
set_var EASYRSA_CERT_EXPIRE	3650
set_var EASYRSA_CRL_DAYS	3650
set_var EASYRSA_REQ_CN		"ambient-tech-server"' > vars

# Create the PKI, set up the CA, the DH params and the server + client certificates
./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full ambient-technical-server nopass
./easyrsa build-client-full ambient-technical-client nopass
./easyrsa gen-crl
cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/ambient-technical-server.crt pki/private/ambient-technical-server.key pki/crl.pem /etc/openvpn
chown openvpn:openvpn /etc/openvpn/crl.pem
# Generate key for tls-auth
openvpn --genkey --secret /etc/openvpn/ta.key

# Create server profile
echo 'port 6443
proto tcp
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert ambient-technical-server.crt
key ambient-technical-server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "route 10.8.0.0 255.255.255.0"
push "route 1.1.1.1 255.255.255.255"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
user openvpn
group openvpn
persist-key
persist-tun
status openvpn-ambient-technical-status.log
verb 3
crl-verify crl.pem
ifconfig-pool-persist ipp-ambient-technical.txt' > /etc/openvpn/ambient-technical-server.conf

# Create client sample profile
echo "client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote 149.28.100.29 6443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
#setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/ambient-technical-client-common.txt

# configure Iptables
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i eth0 -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp -m state --state NEW -m tcp --dport 6443 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A FORWARD -s 127.0.0.0/8 -d 127.0.0.0/8 -i lo -m state --state NEW -j ACCEPT
iptables -A FORWARD -s 127.0.0.0/8 -d 127.0.0.0/8 -o lo -m state --state NEW -j ACCEPT
iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to 149.28.100.29

# Enable IPv4 forward
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Start OpenVPN 
systemctl enable openvpn@"ambient-technical-server"
systemctl start openvpn@"ambient-technical-server"
