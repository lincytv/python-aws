### Script  for log analysis ###
#!/bin/bash
logfile=/var/log/syslog
line=10
email='lincy.varghese@reancloud.com'

sudo tail -n $line $logfile >> /tmp/tail_error
sudo grep -R 'error' /tmp/tail_error >> /tmp/grep_error
sudo grep -R 'warning' /tmp/tail_error >> /tmp/grep_error 

sendmail $email < /tmp/grep_error

