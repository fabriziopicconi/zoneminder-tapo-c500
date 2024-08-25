#!/bin/bash
# Tested on Ubuntu 24.04 with default db name and credentials

sudo apt update
sudo apt -y dist-upgrade
sudo apt -y install zoneminder
sudo chmod 740 /etc/zm/zm.conf
sudo chown root:www-data /etc/zm/zm.conf
sudo mysql -e "CREATE DATABASE zm;"
sudo mysql -e "CREATE USER'zmuser'@'localhost' IDENTIFIED BY 'zmpass'"
sudo mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'zmuser'@'localhost'"
sudo mysql < /usr/share/zoneminder/db/zm_create.sql
sudo zmupdate.pl -f
sudo a2enmod cgi
sudo a2enmod rewrite
sudo a2enconf zoneminder
sudo a2enmod expires
sudo a2enmod headers
sudo systemctl enable zoneminder
sudo systemctl start zoneminder
sudo systemctl reload apache2
