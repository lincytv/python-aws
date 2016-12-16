#!/bin/bash
line_num=10
email='lincy.varghese@reancloud.com'
instanceid=`curl --silent http://169.254.169.254/latest/meta-data/instance-id`;
host_name=`curl -s http://169.254.169.254/latest/meta-data/hostname`;
temp_tail=/tmp/tail_temp
temp_grep=/tmp/grep_error

rm -rf $temp_grep $temp_tail
echo "Instance ID: ********** $instanceid *********" > $temp_grep
echo "Hostname : *********** $host_name **********" >> $temp_grep
#for i in $(sudo ls -R -I *.gz /var/log/)
for i in $(sudo find /var/log -type f \( -iname "*.*" ! -iname "*.gz" \))
do
 sudo echo "-----------------------------------------------------------------" >>$temp_grep
 sudo echo "Log FileName: -----------$i" >> $temp_grep
 sudo echo  "----------------------------------------------------------------" >>$temp_grep
 sudo tail -n $line_num $i >> $temp_tail
 sudo echo  "Error : ##########################################" >>$temp_grep
 sudo grep -R 'error' $temp_tail >> $temp_grep
 sudo echo  "Warning : ########################################" >>$temp_grep
 sudo grep -R 'warning' $temp_tail >> $temp_grep
 sudo echo  "Failed : #########################################" >> $temp_grep
 sudo grep -R 'failed' $temp_tail >> $temp_grep
done

if [ -s $temp_grep ]
then
# sendmail $email < /tmp/grep_error
mail -s "Log analyis report for $host_name $instanceid" $email < $temp_grep
fi
