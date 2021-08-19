#!/bin/bash
# trojan-install.sh
# font color
blue() {
  echo -e "\033[34m\033[01m$1\033[0m"
}
green() {
  echo -e "\033[32m\033[01m$1\033[0m"
}
red() {
  echo -e "\033[31m\033[01m$1\033[0m"
}
# check sys
if [[ -f /etc/redhat-release ]]; then
  release="centos"
  systemPackage="yum"
  systempwd="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
  systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
  systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
  systempwd="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
  systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
  systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
  systempwd="/usr/lib/systemd/system/"
fi
if [ "$release" != "ubuntu" ] && [ "$release" != "debian" ]; then
  red " ==============="
  red "       当前系统不受支持"
  red " ==============="
  exit
fi
red " ==============="
echo
red "        检测sudo是否安装，注意以下输出信息"
red "        如果提示 sudo: command not found 之类的，说明 sudo 没安装"
sudo -V >/dev/null
red "        注意以上输出信息"
echo
red " ==============="
if [ -s /usr/bin/sudo ]; then
  green " ==============="
  echo
  green "       当前系统已安装 sudo"
  echo
  green " ==============="
else
  red " ==============="
  echo
  red "       当前系统未安装 sudo，直接回车安装 sudo，按0退出"
  echo
  red " ==============="
  read -p "请输入数字:" num
  case "$num" in
  0)
    green " ==============="
    echo
    green "       手动安装 sudo ，请复制"
    blue "        $systemPackage update"
    blue "        $systemPackage install sudo"
    echo
    green " ==============="
    exit
    ;;
  esac
  $systemPackage update >/dev/null
  $systemPackage install sudo >/dev/null
fi
function usr_exists() { id $1 $2 &>/dev/null; }
function create_user() {
  green " ======================="
  echo
  blue "        请设置 trojanuser 用户密码，直接回车将随机生成"
  echo
  green " ======================="
  read trojanuser_passwd
  if [ -z "$trojanuser_passwd" ]; then
    trojanuser_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
  fi
  if usr_exists -u trojanuser; then
    echo "trojanuser:$trojanuser_passwd" | sudo chpasswd
    green " ==============="
    echo
    blue "       trojanuser 用户已存在，重设密码为：$trojanuser_passwd"
    red "       $trojanuser_passwd"
    blue "       请牢记！！！待会儿要用到"
    echo
    # red " ==============="
  else
    sudo useradd -m -s /bin/bash trojanuser
    echo "trojanuser:$trojanuser_passwd" | sudo chpasswd
    sudo usermod -G sudo trojanuser
    green " ==============="
    echo
    green "       trojanuser 用户已创建，密码为：$trojanuser_passwd"
    echo
    # green " ==============="
  fi
  if egrep "^certusers" /etc/group &>/dev/null; then
    red " ==============="
    echo
    red "       certusers 用户组已存在"
    echo
    # red " ==============="
  else
    sudo groupadd certusers
    green " ==============="
    echo
    green "       certusers 用户组已创建"
    echo
    # green " ==============="
  fi
  if usr_exists -u trojan; then
    red " ==============="
    echo
    red "       trojan 用户已存在"
    echo
    # red " ==============="
  else
    sudo useradd -r -M -G certusers trojan
    green " ==============="
    echo
    green "       trojan 用户已创建"
    echo
    # green " ==============="
  fi
  if usr_exists -u acme; then
    red " ==============="
    echo
    red "       acme 用户已存在"
    echo
    # red " ==============="
  else
    sudo useradd -r -m -G certusers acme
    green " ==============="
    echo
    green "       acme 用户已创建"
    echo
    # green " ==============="
  fi
  green " ======================="
  echo
  red "        是否立即切换至 trojanuser，切换后请复制："
  blue "        bash /tmp/trojan_install.sh"
  red "        按 0 退出，其他按键继续"
  echo
  green " ======================="
  read -p "请输入数字:" num
  case "$num" in
  0)
    exit
    ;;
  esac
  sudo su -l -s /bin/bash trojanuser
}
function start_install() {
  sudo $systemPackage update >/dev/null
  sudo $systemPackage install -y socat cron curl >/dev/null
  sudo systemctl start cron
  sudo systemctl enable cron
  sudo $systemPackage install -y libcap2-bin xz-utils vim >/dev/null
  sudo $systemPackage install -y nginx >/dev/null
  sudo systemctl enable nginx
  sudo systemctl stop nginx
  green " ======================="
  echo
  blue "        请输入绑定到本VPS的域名，输入0退出脚本"
  echo
  green " ======================="
  read your_domain
  case "$your_domain" in
  0)
    exit
    ;;
  esac
  real_addr=$(ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
  local_addr=$(curl ipv4.icanhazip.com)
  if [ $real_addr == $local_addr ]; then
    green " =========================================="
    echo
    green "       域名解析正常，开始配置NGINX"
    echo
    green " =========================================="
    sleep 1s
    sudo mkdir -p /var/www/helloToday
    sudo bash -c "cat >/var/www/helloToday/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Hello, today</title>
</head>
<body>
    <div class="time" id="time"></div>
</body>
</html>
<script>
const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
let timeDiv = document.getElementById('time');
setInterval(function () {
    let date = new Date();
    timeDiv.innerHTML = date.toLocaleDateString('en-US', options) + ' ' + date.toLocaleTimeString("en-US");
}, 1000);
</script>
EOF
    sudo chown -R acme:acme /var/www/helloToday
    [ -s /etc/nginx/sites-enabled/default ] && sudo rm /etc/nginx/sites-enabled/default
    [ -s /etc/nginx/sites-enabled/$your_domain ] && sudo rm /etc/nginx/sites-enabled/$your_domain
    [ -s /etc/nginx/sites-available/$your_domain ] && sudo rm /etc/nginx/sites-available/$your_domain
    sudo bash -c "cat >/etc/nginx/sites-available/$your_domain" <<EOF
server {
    listen 127.0.0.1:80 default_server;

    server_name $your_domain;

    location / {
        root /var/www/helloToday;
    }

}

server {
    listen 127.0.0.1:80;

    server_name $local_addr;

    return 301 https://$your_domain\$request_uri;
}

server {
    listen 0.0.0.0:80;
    listen [::]:80;

    server_name _;

    location / {
        return 301 https://\$host\$request_uri;
    }

    location /.well-known/acme-challenge {
       root /var/www/acme-challenge;
    }
}
EOF
    sudo ln -s /etc/nginx/sites-available/$your_domain /etc/nginx/sites-enabled/
    sudo systemctl restart nginx
    sudo systemctl --no-pager status nginx
    green " =========================================="
    echo
    red "        NGINX是否正在运行？直接回车继续下一步，按0退出"
    echo
    read -p "请输入数字:" num
    case "$num" in
    0)
      exit
      ;;
    esac
    green " =========================================="
    echo
    green "       配置NGINX完成，开始申请证书"
    echo
    green " =========================================="
    sleep 1s
    sudo mkdir -p /etc/letsencrypt/live
    sudo chown -R acme:acme /etc/letsencrypt/live
    ps -eo user,command | grep nginx
    blue " =========================================="
    echo
    red "      第二行第一列即为nginx: worker process所属用户，然后根据实际情况，运行下面三个命令之一："
    echo
    blue " =========================================="
    red " 0. 退出"
    green " 1. sudo usermod -G certusers www-data"
    green " 2. sudo usermod -G certusers nginx"
    green " 3. sudo usermod -G certusers nobody"
    read -p "   请输入数字:" num
    case "$num" in
    0)
      exit
      ;;
    1)
      sudo usermod -G certusers www-data
      ;;
    2)
      sudo usermod -G certusers nginx
      ;;
    3)
      sudo usermod -G certusers nobody
      ;;
    esac
    sudo mkdir -p /var/www/acme-challenge
    sudo chown -R acme:certusers /var/www/acme-challenge
    sudo bash -c "su -l -s /bin/bash acme" <<EOF
curl https://get.acme.sh | sh >/dev/null
~/.acme.sh/acme.sh --register-account -m my@example.com >/dev/null
~/.acme.sh/acme.sh --issue -d $your_domain -w /var/www/acme-challenge >/dev/null
~/.acme.sh/acme.sh --installcert -d $your_domain \
    --key-file /etc/letsencrypt/live/private.key \
    --fullchain-file /etc/letsencrypt/live/certificate.crt
~/.acme.sh/acme.sh  --upgrade  --auto-upgrade
chown -R acme:certusers /etc/letsencrypt/live
chmod -R 750 /etc/letsencrypt/live
EOF
    if sudo test -s /etc/letsencrypt/live/certificate.crt; then
      green " =========================================="
      echo
      red "       申请证书完成，开始安装Trojan"
      echo
      green " =========================================="
      sleep 1s
      sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
      sudo chown -R trojan:trojan /usr/local/etc/trojan
      green " ======================="
      echo
      blue "        请设置客户端连接 trojan 密码，直接回车将随机生成"
      echo
      green " ======================="
      read trojan_passwd
      if [ -z "$trojan_passwd" ]; then
        trojan_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
      fi
      sudo mv /usr/local/etc/trojan/config.json /usr/local/etc/trojan/config.json.bak
      sudo bash -c "cat >/usr/local/etc/trojan/config.json" <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/letsencrypt/live/certificate.crt",
        "key": "/etc/letsencrypt/live/private.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "alpn_port_override": {
            "h2": 81
        },
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF
      sudo mv ${systempwd}trojan.service ${systempwd}trojan.service.bak
      sudo bash -c "cat >${systempwd}trojan.service" <<-EOF
[Unit]
Description=trojan
Documentation=https://trojan-gfw.github.io/trojan/config https://trojan-gfw.github.io/trojan/
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service

[Service]
Type=simple
StandardError=journal
User=trojan
ExecStart="/usr/local/bin/trojan" "/usr/local/etc/trojan/config.json"
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=51200
Restart=on-failure
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF
      sudo systemctl daemon-reload
      sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/trojan
      sudo systemctl enable trojan
      sudo systemctl restart trojan
      sudo systemctl --no-pager status trojan
      green " =========================================="
      echo
      red "        Trojan是否正在运行？直接回车继续下一步，按0退出"
      echo
      read -p "请输入数字:" num
      case "$num" in
      0)
        exit
        ;;
      esac
      sudo systemctl enable trojan
      sudo systemctl enable nginx
      green " =========================================="
      echo
      red "       配置Trojan完成，开始启动bbr"
      echo
      green " =========================================="
      sleep 1s
      sudo bash -c 'echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf'
      sudo bash -c 'echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf'
      sudo sysctl -p
      sudo sysctl net.ipv4.tcp_congestion_control
      green " ======================="
      echo
      blue "        请设置节点名称，直接回车将随机生成"
      echo
      green " ======================="
      read node_name
      if [ -z "$node_name" ]; then
        node_name=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
      fi
      green " =========================================="
      echo
      green "       安装成功，复制下面的链接即可使用"
      blue "       trojan://$trojan_passwd@$your_domain:443#$node_name"
      echo
      green " =========================================="
      sleep 1s
    else
      red " ==================================="
      echo
      red "       https证书没有申请成果，自动安装失败"
      echo
      red " ==================================="
    fi
  else
    red " ================================"
    echo
    red "       域名解析地址与本VPS IP地址不一致"
    red "       本次安装失败，请确保域名解析正常"
    echo
    red " ================================"
  fi

}
function uninstall() {
  clear
  green " =========================================="
  echo
  green "       正在卸载Trojan"
  echo
  green " =========================================="
  sudo systemctl stop trojan
  sudo systemctl disable trojan
  sudo rm -rf /usr/local/bin/trojan
  sudo rm -rf /usr/local/etc/trojan
  sudo rm ${systempwd}trojan.service
  sudo systemctl daemon-reload
  green " =========================================="
  echo
  green "       卸载Trojan完成，即将卸载NGINX"
  # red "        直接回车继续下一步，按0退出"
  # read -p "请输入数字:" num
  # case "$num" in
  # 0)
  #   exit
  #   ;;
  # esac
  echo
  green " =========================================="
  if [ "$release" == "centos" ]; then
    sudo yum remove -y nginx
  else
    sudo apt autoremove -y nginx
  fi
  sudo rm -rf /etc/nginx/sites-enabled/*
  green " =========================================="
  echo
  green "       卸载成功"
  echo
  green " =========================================="
}

function start_menu() {
  clear
  green " ===================================="
  green " Trojan 一键安装自动脚本 2021-08-14      "
  green " 系统：debian9+/ubuntu16.04+"
  green " ===================================="
  blue " 声明："
  red " *安装失败可以尝试先输入 2 立即卸载"
  green " ======================================="
  echo
  green " 1. 开始安装"
  green " 2. 立即卸载"
  red " 0. 退出脚本"
  echo
  read -p "请输入数字:" num
  case "$num" in
  1)
    start_install
    ;;
  2)
    uninstall
    ;;
  *)
    exit 1
    ;;
  esac
}
if [ "$USER" == "trojanuser" ]; then
  start_menu
else
  green " ======================================="
  red "        出于安全考虑，本脚本仅在 trojanuser 用户下使用，"
  if usr_exists -u trojanuser; then
    green "        您已创建 trojanuser ，请输入1"
  else
    red "       似乎没有创建 trojanuser ，正在自动创建 trojanuser 用户"
    create_user
    exit
  fi
  red "        如您忘记 trojanuser 密码，请输入2"
  red "        直接回车将退出脚本"
  green " ======================================="
  read -p "请输入数字:" num
  case "$num" in
  1)
    green " ======================================="
    green "        下面这行是切换用户到 trojanuser"
    blue "        sudo su -l -s /bin/bash trojanuser"
    green "        下面这行是在 trojanuser 下运行一键脚本"
    blue "        bash /tmp/trojan_install.sh"
    green " ======================================="
    ;;
  2)
    create_user
    ;;
  *)
    exit 1
    ;;
  esac
fi
