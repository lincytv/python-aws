#!/bin/bash

## Lincy wordpress install shell script

#name of the wesite
website='example.com'
mysql_password='root'
site_admin='lincytv'
site_admin_password='lincytv'
site_admin_email='lincy.varghese@reancloud.com'
release=trusty 
web_port=80
web_root=/var/www/html
db_name=wp
db_user='root'

#sudo apt-get install deb -y
#sudo deb http://nginx.org/packages/ubuntu/ $release nginx
sudo echo $mysql_password | sudo debconf-set-selections
sudo echo $mysql_password | sudo debconf-set-selections
sudo apt-get update
sudo apt-get install unzip nginx mysql-server php5-mysql php5 libapache2-mod-php5 php5-mcrypt -y
sudo apt-get install -f
sudo mysql -u root -p $mysql_password -e "create databases wordpress; create user 'wordpress' @ 'localhost' identified by 'wordpress' ; grand all on 'wordpress' to 'wordpress'"  
sudo mkdir $web_root/$website
sudo cat <<EOF > /etc/nginx/sites-avaliable/$website.conf
server { 
    listen       80;
    server_name  $website www.$wesite.com;
    access_log   logs/$website.access.log  main;

    # serve static files
    location ~ ^/(images|javascript|js|css|flash|media|static)/  {
      root    $web_root/$website;
    } 
}
EOF
sudo ln -s /etc/nginx/sites-avaliable/$website.conf /etc/nginx/sites-enabled/$website.conf
sudo service nginx restart
#sudo chkconfig nginx on
#sudo chkconfig mysql-server on

sudo wget https://wordpress.org/latest.zip -O /tmp/latest.zip
sudo unzip /tmp/latest.zip
sudo mv /tmp/wordpress/* $web_root/$website/
sudo cp $web_root$/website/wp-config-sample.php $web_root/$website/wp-config.php
sudo sed -i  -e 's/DB_NAME/$db_name/g' $web_root/$website/wp-config.php
sudo sed -i  -e 's/DB_USER/$db_user/g' $web_root/$website/wp-config.php
sudo sed -i  -e 's/DB_PASSWORD/$mysql_password/g' $web_root/$website/wp-config.php
crul http://localhost/index.php?step=2\ ----data-urlencode "weblog_title=$website" ----data-urlencode "user_name=$site_admin" ----data-urlencode "admin_email=$site_admin_email" ----data-urlencode "admin_password=$site_admin_password" ----data-urlencode "admin_password2=$site_admin_password"  --data-urlencode "pw_weak=1"
