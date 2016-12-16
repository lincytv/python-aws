#!/bin/bash

#log_name=/var/log/httpd/error.log
line_num=10
email='ms@reancloud.com'
INSTANCE_ID=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`;

if [ -f /tmp/tail_temp ]
then
rm -rf /tmp/tail_temp /tmp/grep_error
fi

if [ -s log_name ]
	then
	  sudo tail -n $line_num $log_name >> /tmp/tail_error
      sudo grep -e 'error' /tmp/tail_error >> /tmp/grep_error
      sudo grep -e 'warning' /tmp/tail_error >> /tmp/grep_error
fi 

#for i in $(sudo ls -R -I *.gz /var/log/)
for i in $(sudo find /var/log -type f \( -iname "*.*" ! -iname "*.gz" \))
do
 sudo tail -n $line_num $i >> /tmp/tail_temp
 sudo grep -e 'error' /tmp/tail_temp >> /tmp/grep_error
 sudo grep -e 'warning' /tmp/tail_temp >> /tmp/grep_error
done

#if [ -s /tmp/grep_error ]
#then
# sendmail $email < /tmp/grep_error
#mail -s "Log analyis report for $HOSTNAME $INSTANCE_ID" $email < /tmp/grep_error
#fi
