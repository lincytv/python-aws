#!/bin/bash
line_num=10
email='lincy.varghese@reancloud.com'
data=sudo find /var/log -type f \( -iname "*.*" ! -iname "*.gz" \)
#for i in $(sudo ls -R -I *.gz /var/log/)
if [ -f /tmp/tail_temp ]
then
rm -rf /tmp/tail_temp /tmp/grep_error
fi
for i in $data
do
 sudo tail -n $line_num $i >> /tmp/tail_temp
 sudo grep -e 'error' /tmp/tail_temp >> /tmp/grep_error
 sudo grep -e 'warning' /tmp/tail_temp >> /tmp/grep_error
done
if [ -s /tmp/grep_error ]
then
sendmail $email < /tmp/grep_error
fi
