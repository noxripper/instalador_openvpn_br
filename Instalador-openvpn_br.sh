#!/bin/bash
#
# https://github.com/noxripper/instalador-openvpn
#
# Copyright (c) 2013 Nox Ripper. Lançado sob a licença MIT.


# Detectar usuários Debian que executam o script com "sh" em vez de bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "Este script precisa ser executado com bash, não sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "desculpe, você precisa rodar isso como root"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "O dispositivo TUN não está disponível Você precisa ativar o TUN antes de executar este script"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Parece que você não está executando este instalador no Debian, Ubuntu ou CentOS"
	exit
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Parece que o OpenVPN já está instalado."
		echo
		echo "O que você quer fazer?"
		echo "   1) Adicione um novo usuário"
		echo "   2) Revogar um usuário existente"
		echo "   3) Remover o OpenVPN"
		echo "   4) Sair"
		read -p "Selecione uma opção [1-4]: " option
		case $option in
			1) Select an option [1-4]
			echo
			echo "Diga-me um nome para o certificado do cliente."
			echo "Por favor, use apenas uma palavra, sem caracteres especiais."
			read -p "Client name: " -e CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo
			echo "Client $CLIENT adicionado, configuração está disponível em:" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# Esta opção pode ser documentada um pouco melhor e talvez até simplificada
			# ... mas o que posso dizer, também quero dormir um pouco
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo
				echo "Você não tem clientes existentes!"
				exit
			fi
			echo
			echo "Selecione o certificado de cliente existente que você deseja revogar:"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Selecione um cliente [1]: " CLIENTNUMBER
			else
				read -p "Selecione um cliente [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			echo
			read -p "Você realmente quer revogar o acesso para o cliente $CLIENT? [y/N]: " -e REVOKE
			if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
				cd /etc/openvpn/easy-rsa/
				./easyrsa --batch revoke $CLIENT
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f pki/reqs/$CLIENT.req
				rm -f pki/private/$CLIENT.key
				rm -f pki/issued/$CLIENT.crt
				rm -f /etc/openvpn/crl.pem
				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:$GROUPNAME /etc/openvpn/crl.pem
				echo
				echo "Certificado para o cliente $CLIENT revogado!"
			else
				echo
				echo "Revogação de certificado para o cliente $CLIENT abortado!"
			fi
			exit
			;;
			3) 
			echo
			read -p "Você realmente quer remover o OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					#Usando regras permanentes e não permanentes para evitar um recarregamento do firewall.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				echo
				echo "OpenVPN removida!"
			else
				echo
				echo "Remoção cancelada!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Bem-vindo a este instalador "road warrior" do OpenVPN!'
	echo
	# Configuração do OpenVPN e criação do primeiro usuário
	echo "Preciso fazer algumas perguntas antes de iniciar a configuração."
	echo "Você pode deixar as opções padrão e simplesmente pressionar enter se estiver ok com elas."
	echo
	echo "Primeiro, forneça o endereço IPv4 da interface de rede que você deseja que o OpenVPN"
	echo "ouvindo".
	# Autodetectar endereço IP e pré-preencher para o usuário
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Este servidor está por trás do NAT. Qual é o endereço IPv4 público (LINK EXTERNO-IP) ou o nome do host?"
		read -p "Endereço IP público / hostname: " -e PUBLICIP
	fi
	echo
	echo "Qual protocolo você deseja para conexões OpenVPN?"
	echo "   1) UDP (recomendado)"
	echo "   2) TCP"
	read -p "Protocolo [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "Qual porta você quer que o OpenVPN ouça?"
	read -p "Port: " -e -i 1194 PORT
	echo
	echo "Qual DNS você quer usar com a VPN?"
	echo "   1) Resolvedores de sistema atuais"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Finalmente, diga-me seu nome para o certificado do cliente."
	echo "Por favor, use apenas uma palavra, sem caracteres especiais."
	read -p "Client name: " -e -i client CLIENT
	echo
	echo "Ok, isso era tudo que eu precisava. Estamos prontos para configurar seu servidor OpenVPN agora."
	read -n1 -r -p "Pressione qualquer tecla para continuar..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	# Get easy-rsa
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/easy-rsa/
	# Crie a PKI, configure a CA, os parâmetros DH e os certificados server + client
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Mova as coisas que precisamos
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# A CRL é lida com cada conexão do cliente, quando o OpenVPN é descartado para ninguém
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Gerar chave para o tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Gerar server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.10.10.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	# echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf (comentado pois remove iternet do cliente quando conectada).
	# colocar ip da rede (aprimorar este para poder editar na instalaçao)
	echo 'push "route 10.1.1.1 255.255.255.0"' >> /etc/openvpn/server.conf
	echo 'client-config-dir /etc/openvpn/ccd' >> /etc/openvpn/server.conf
	echo 'ccd-exclusive' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Localize o resolv.conf apropriado
		# Necessário para sistemas executando o systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtenha os resolvedores do resolv.conf e use-os para o OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 0
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Ativar net.ipv4.ip_forward para o sistema
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Ativar sem aguardar uma reinicialização ou reinicialização do serviço
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Usando regras permanentes e não permanentes para evitar um firewalld
	# recarregar.
	# Nós não usamos --add-service = openvpn porque isso só funcionaria com
	# a porta e o protocolo padrão.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		#Definir NAT para a sub-rede da VPN
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		#Necessário usar o rc.local com algumas distribuições systemd
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Definir NAT para a sub-rede da VPN
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# Se o iptables tiver pelo menos uma regra REJECT, assumimos que isso é necessário. 
			# Não é a melhor abordagem, mas não consigo pensar em outra e isso não deve 
			# causar problemas.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# Se o SELinux estiver habilitado e uma porta personalizada for selecionada, precisamos
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Instalar semanage se ainda não estiver presente
		if ! hash semanage 2>/dev/null; then
			yum install policycoreutils-python -y
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# E finalmente, reinicie o OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Pequeno hack para verificar para systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Se o servidor estiver atrás de um NAT, use o endereço IP correto
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# client-common.txt é criado, por isso temos um modelo para adicionar outros usuários mais tarde
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
;setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Gereda customizado client.ovpn
	newclient "$CLIENT"
	echo
	echo "Concluído!"
	echo
	echo "Sua configuração do cliente está disponível em:" ~ / "$ CLIENT.ovpn"
	echo "Se você quiser adicionar mais clientes, basta executar este script novamente!"
fi
