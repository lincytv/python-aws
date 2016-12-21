import boto
import boto.ec2

conn = boto.ec2.connect_to_region('us-east-1')
get_ami = conn.get_all_images()
for i in get_ami:
   print i.description
   van = conn.copy_ami(source_region='us-east-1', source_ami_id=, )
