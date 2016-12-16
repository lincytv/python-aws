# AML / Rhel 6X
service httpd status
if [ $?==0 ]
	echo "/var/log/httpd/*.log 
	 { 
	   weekly 
	   rotate 4 
	   compress 
	   missingok 
	   notifempty 
	   sharedscripts 
	   delaycompress 
	   postrotate 
	      /sbin/service httpd reload > /dev/null 2>/dev/null || true 
	   endscript 
	  }" > /etc/logrotate.d/httpd
fi
# ubuntu
service apache2 status
if [ $?==0 ]
	echo " /var/log/apache2/*.log 
	       { 
	            weekly 
	            missingok 
	            rotate 52 
	            compress 
	            delaycompress 
	            notifempty 
	            create 640 root adm 
	            sharedscripts 
	            postrotate if /etc/init.d/apache2 status > /dev/null ; then \
                    /etc/init.d/apache2 reload > /dev/null; \
                fi;	
                endscript
	    prerotate
		if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
			run-parts /etc/logrotate.d/httpd-prerotate; \
		fi; \	
		endscript }" > /etc/logrotate.d/apache2
fi
# nginx
service nginx status
if [ $?==0 ]
	echo "/var/log/nginx/*log 
	{ 
		create 0644 nginx nginx 
	    weekly 
	    rotate 4  
	    missingok 
	    notifempty 
	    compress 
	    sharedscripts 
	    postrotate 
	        /etc/init.d/nginx reopen_logs 
	    endscript }" > /etc/logrotate.d/httpd
fi