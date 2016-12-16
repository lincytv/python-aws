#!/bin/bash

line_num=10
email='lincy.varghese@reancloud.com'
instanceid=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`;
host_name=`curl -s http://169.254.169.254/latest/meta-data/hostname`;

for i in $(sudo ls -R -I *.gz /var/log/*)
#for i in $(sudo find /var/log/* -type f \( -iname "*.*" ! -iname "*.gz" \))
do
	sudo echo -n "Filename : $i" >> /tmp/grep_error
    sudo tail -n $line_num $i >> /tmp/tail_temp
    sudo tail -n $line_num $i >> /tmp/grep_error
    sudo echo -n "Error : ################" >>/tmp/grep_error
    sudo grep -R 'error' /tmp/tail_temp >> /tmp/grep_error
    sudo echo -n "Warning : #################" >>/tmp/grep_error
    sudo grep -R 'warning' /tmp/tail_temp >> /tmp/grep_error
    sudo echo -n "failed : #################" >>/tmp/grep_error
    sudo grep -R 'failed' /tmp/tail_temp >> /tmp/grep_error
done
cat /tmp/grep_error
if [ -s /tmp/grep_error ]
then
# sendmail $email < /tmp/grep_error
#mail -s "Log analyis report for $host_name $instanceid" $email < /tmp/grep_error
fi

