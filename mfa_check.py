import boto
from boto import iam
from boto.iam.connection import IAMConnection
from boto.iam.connection import MFADevices

conn= IAMConnection()
summary= conn.get_all_users();

for user in summary.users:
   name=user['user_name']
   print get_all_mfa_devices(name)

