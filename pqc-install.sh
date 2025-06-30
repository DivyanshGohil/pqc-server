#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

STATUS_FILE="/var/log/pqc_install_status.log"
touch "$STATUS_FILE"

# Validation for sudo/root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root or with sudo${NC}"
    exit 1
fi

log_status() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$STATUS_FILE"
}

run_cmd() {
    echo -e "${YELLOW}$2...${NC}"
    log_status "$2"
    eval "$1"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Success: $2${NC}"
        log_status "Success: $2"
    else
        echo -e "${RED}Failed: $2${NC}"
        log_status "Failed: $2"
        exit 1
    fi
}

run_cmd "apt update" "Updating package lists"
run_cmd "apt install -y make" "Installing make"
run_cmd "apt install -y gcc" "Installing gcc"

echo -e "${YELLOW}Installing OpenSSL from source${NC}"
log_status "Installing OpenSSL from source"
run_cmd "wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz" "Downloading OpenSSL tarball"
run_cmd "wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz.asc" "Downloading OpenSSL signature"

echo -e "${YELLOW}Verifying OpenSSL code signature${NC}"
log_status "Verifying OpenSSL code signature"
run_cmd "apt -y install gnupg" "Installing gnupg"
echo -e "${YELLOW}Next step will prompt you to select a key, press '1' key followed by 'Enter' to choose the key from openssl@openssl.org${NC}"
gpg --search-keys openssl@openssl.org
run_cmd "gpg --fingerprint openssl@openssl.org" "Verifying the fingerprint of the imported key"
run_cmd "gpg --verify openssl-3.5.0.tar.gz.asc openssl-3.5.0.tar.gz" "Verifying the openssl-3.5.0.tar.gz file"

run_cmd "tar zxf openssl-3.5.0.tar.gz" "Extracting OpenSSL"
cd openssl-3.5.0 || { echo -e "${RED}Extraction not done perfectly${NC}"; log_status "Extraction not done perfectly"; exit 1; }
run_cmd "./Configure --prefix=/opt '-Wl,-rpath,\$(LIBRPATH)'" "Configuring OpenSSL"
run_cmd "make" "Building OpenSSL"
run_cmd "make install" "Installing OpenSSL"
echo -e "${GREEN}Correct path of new openssl is /opt/bin/openssl${NC}"
log_status "Correct path of new openssl is /opt/bin/openssl"
echo -e "${YELLOW}Verifying Openssl:${NC}"
/opt/bin/openssl version | tee -a "$STATUS_FILE"

echo "export PATH=/opt/bin:\$PATH" >> ~/.bashrc
export PATH=/opt/bin:$PATH

run_cmd "apt remove -y nginx nginx-common" "Removing existing NGINX"
run_cmd "wget https://nginx.org/download/nginx-1.27.4.tar.gz" "Downloading NGINX tarball"
run_cmd "wget https://nginx.org/download/nginx-1.27.4.tar.gz.asc" "Downloading NGINX signature"
run_cmd "wget https://nginx.org/keys/pluknet.key" "Downloading NGINX GPG key"
run_cmd "gpg --import pluknet.key" "Importing NGINX GPG key"
run_cmd "gpg --verify nginx-1.27.4.tar.gz.asc nginx-1.27.4.tar.gz" "Verifying NGINX tarball signature"

run_cmd "apt install -y zlib1g-dev libpcre3 libpcre3-dev" "Installing NGINX dependencies"
run_cmd "tar zxf nginx-1.27.4.tar.gz" "Extracting NGINX"
cd nginx-1.27.4 || { echo -e "${RED}Nginx extraction not done perfectly${NC}"; log_status "Nginx extraction not done perfectly"; exit 1; }

configure_args=(
    "--with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2'"
    "--with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC'"
    "--prefix=/opt"
    "--conf-path=/opt/nginx/nginx.conf"
    "--http-log-path=/var/log/nginx/access.log"
    "--error-log-path=/var/log/nginx/error.log"
    "--lock-path=/var/lock/nginx.lock"
    "--pid-path=/run/nginx.pid"
    "--modules-path=/opt/lib/nginx/modules"
    "--http-client-body-temp-path=/var/lib/nginx/body"
    "--http-fastcgi-temp-path=/var/lib/nginx/fastcgi"
    "--http-proxy-temp-path=/var/lib/nginx/proxy"
    "--http-scgi-temp-path=/var/lib/nginx/scgi"
    "--http-uwsgi-temp-path=/var/lib/nginx/uwsgi"
    "--with-compat"
    "--with-debug"
    "--with-http_ssl_module"
    "--with-http_stub_status_module"
    "--with-http_realip_module"
    "--with-http_auth_request_module"
    "--with-http_v2_module"
    "--with-http_dav_module"
    "--with-http_slice_module"
    "--with-threads"
    "--with-http_addition_module"
    "--with-http_gunzip_module"
    "--with-http_gzip_static_module"
    "--with-http_sub_module"
    "--with-pcre"
    "--with-openssl-opt=enable-tls1_3"
    "--with-ld-opt=-L/opt/lib64 -Wl,-rpath,/opt/lib64"
    "--with-cc-opt=-I/opt/include"
)
run_cmd "./configure \"\${configure_args[@]}\"" "Configuring NGINX"
run_cmd "make" "Building NGINX"
run_cmd "make install" "Installing NGINX"

echo -e "${YELLOW}Creating the necessary directories for temporary file storages${NC}"
log_status "Creating the necessary directories for temporary file storages"
mkdir -p /var/lib/nginx
mkdir -p /opt/nginx/conf.d

sed -i '1i user www-data;' /opt/nginx/nginx.conf
sed -i '/http {/a \    '"include /opt/nginx/conf.d/pqc.conf;" /opt/nginx/nginx.conf

ip=$(hostname -I | awk '{ print $1 }')
cat <<EOL > /opt/nginx/conf.d/pqc.conf
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $ip;

    root /var/www/;
    index index.html index.php;

    ssl_certificate /opt/certs/pqc.crt;
    ssl_certificate_key /opt/certs/pqc.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519MLKEM768;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOL

mkdir -p /opt/certs
run_cmd "openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/certs/pqc.key -out /opt/certs/pqc.crt -subj '/CN=Cybervertical'" "Creating a self-signed certificate"

cat <<EOL > /etc/systemd/system/nginx.service
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/opt/sbin/nginx -t
ExecStart=/opt/sbin/nginx
ExecReload=/opt/sbin/nginx -s reload
ExecStop=/opt/sbin/nginx -s stop
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOL

mkdir -p /var/www/pqc-example.com
cat <<EOL > /var/www/pqc-example.com/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC Example</title>
</head>
<body>
    <h1>This is PQC setup with Nginx</h1>
</body>
</html>
EOL

run_cmd "service nginx start" "Starting NGINX"
echo -e "${GREEN}Installation completed. Check $STATUS_FILE for details.${NC}"
log_status "Installation completed"

echo -e "${GREEN}NGINX is installed at /opt/sbin/nginx${NC}"
echo -e "${GREEN}OpenSSL is installed at /opt/bin/openssl${NC}"
echo -e "${GREEN}To verify post-quantum TLS, open https://$ip/pqc-example.com/ in a browser that supports post-quantum key exchange${NC}"
echo -e "${GREEN}Status log file: $STATUS_FILE${NC}"