#!/usr/bin/python
import boto3
import time
from boto3.session import Session
import datetime
import pprint
import pdb
import botocore
import csv

###CSV
f=open('phenompeople.csv','w')

c2=','
c3=' '+','+' '+','
c4=' '+','
c5=' '+','+' '+','+' '+','+' '+','
c6=' '+','+' '+','+' '+','+' '+','+' '+','
f.write('S.No'+','+'Service'+','+'Report Type'+','+'Description'+','+'Output'+','+'Pass/Fail'+'\n')
f.write('1')
f.write(c2+'IAM'+'\n')
iamclient = boto3.client('iam')
iam = boto3.resource('iam')
users = iamclient.list_users()
#IAM users with MFA not enabled
print "\n****Report on IAM users with MFA not enabled: ****"
f.write(c3+'Report on IAM users with MFA not enabled')
f.write(c4+'It is strongly recommended that MFA should be enabled for IAM users.'+'\n')
userslist=[]
usersall = []
iamclient = boto3.client('iam')
for user in users['Users']:
    getuser = iamclient.get_user(UserName=user['UserName'])
    usersall.append(user['UserName'])
    getmfa = iamclient.list_mfa_devices(UserName=user['UserName'])
    mfalen = len(getmfa['MFADevices'])
    if mfalen != 0:
        for mfa in getmfa['MFADevices']:
            mfauser=mfa['UserName']
            userslist.append(mfauser)
for us in userslist:
    usersall.remove(us)
print "The users below do not have MFA Enabled. Please Enable MFA for the following users."
f.write(c5+'The users below do not have MFA Enabled. Please Enable MFA for the following users.'+'\n')
for finlist in  usersall:
    print finlist
    f.write('\n'+c5+finlist+'\n')

#MFA enabled/disabled for IAM root user
print "\n****Report on MFA policy of root account: ****"
f.write('\n'+c3+'Report on MFA policy of root account:')
f.write(c4+'To ensure security of the AWS account it is strongly recommended that MFA is enabled for ROOT account.'+'\n')
accsummary = iamclient.get_account_summary()
mfaval = accsummary['SummaryMap']['AccountMFAEnabled']
print "Value of MFA: %s"%mfaval+" which indicates if MFA has been enabled/disabled for the root account. 1-MFA enabled and 0-MFA Disabled."
f.write(c5+"Value of MFA: %s"%mfaval+" which indicates if MFA has been enabled/disabled for the root account. 1-MFA enabled and 0-MFA Disabled."+'\n')
if mfaval == 1:
    print "MFA has been enabled for the root account."
    f.write(c5+'MFA has been enabled for the root account.'+'\n')
else:
    print "MFA has been disabled for the root account."
    f.write(c5+'MFA has been disabled for the root account.'+'\n')

#Passowrd account policy rotation
account_password_policy = iam.AccountPasswordPolicy()
#print "Allow_Users_To_Change_Password :", account_password_policy.allow_users_to_change_password
try:
   age=account_password_policy.max_password_age

   print "\n****Report on IAM Password rotation policy: ****"
   f.write('\n'+c3+'Report on IAM Password rotation policy:')
   f.write(c4+'It is recommended that IAM users change their passwords in every 90 days.'+'\n')
   if age >= 90:
        print "The Password rotation policy has been enabled for 90 days or a greated value of 90 days. The number of days that is has been set is:%s."%age
        f.write(c5+"The Password rotation policy has been enabled for 90 days or a greated value of 90 days. The number of days that is has been set is:%s."%age+'\n')
   elif age == None:
    print "Password rotation has not been set. Please set a password expiration value(Number of days).Recommended number of days are 90 days."
    f.write(c5+"Password rotation has not been set. Please set a password expiration value(Number of days).Recommended number of days are 90 days."+'\n')
   else:
        print "Password rotation has been set for %s days. The recommended number of days is 90"%age
        f.write(c5+"Password rotation has been set for %s days. The recommended number of days is 90"%age+'\n')
except Exception as e:
    print "No password policy has been found. Error is: %s"%e
    
#List of users who remained inactive for 60 days or more
print "\n****Report on the users that have been inactive for 60 days or more: ****"
f.write('\n'+c3+'Report on the users that have been inactive for 60 days or more:')
f.write(c4+'All dormant IAM users who have not used their AWS account from last 60 days should be deleted.'+'\n')
print "The following users have not used their AWS account for more than 60 days. Please delete the users if they no longer require access."
f.write(c5+'The following users have not used their AWS account for more than 60 days. Please delete the users if they no longer require access.'+'\n')
lastday = datetime.datetime.utcnow() - datetime.timedelta(days=60)
dateformat = '%Y/%m/%d %H:%M:%S'
getusers = iamclient.list_users()['Users']
for users in getusers:
    # Get details of a specific user
    lastlogin = iamclient.get_user(UserName=users['UserName'])['User']
    # check vlaue for password last used presend or not
    if lastlogin.has_key('PasswordLastUsed'):
        getdate=lastlogin['PasswordLastUsed']
        # print user name and last accessed date of the password
        if  getdate.strftime(dateformat) < lastday.strftime(dateformat):
            print "%s .Last login: %s"%(lastlogin['UserName'],getdate.strftime(dateformat))
            f.write(c5+"%s .Last login: %s"%(lastlogin['UserName'],getdate.strftime(dateformat))+'\n')

#List of users who haven't used their Access keys in the last 30 days
print "\n****Report of users who haven't used their Access Keys in the last 30 days: ****"
f.write('\n'+c3+'Report of users who have not used their Access Keys in the last 30 days:')
f.write(c4+'All the users who have not rotated their keys in the last 30 days should delete their Access Keys'+'\n')
print "The following users have not been using their Access Keys from the last 30 days. Please delete the access keys if they are not in use."
f.write(c5+"The following users have not been using their Access Keys from the last 30 days. Please delete the access keys if they are not in use."+'\n')
last30days = datetime.datetime.utcnow() - datetime.timedelta(days=30)
DATEFORMAT = '%Y/%m/%d %H:%M:%S'
for user in getusers:
    accesskey = iamclient.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
    for key in accesskey:
        lastused = iamclient.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])['AccessKeyLastUsed']
        if lastused.has_key('LastUsedDate'):
                getdate=lastused['LastUsedDate']
                if  getdate.strftime(DATEFORMAT) < last30days.strftime(DATEFORMAT):
                    print "User:|%s| has not used their Access Keys from %s"%(iamclient.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])['UserName'],getdate.strftime(DATEFORMAT))
                    f.write(c5+'%s has not used their Access Keys in the last 30 days.'%(iamclient.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])['UserName'])+'\n')


#List of all IAM users
print "\n****List of all the users in the IAM account: ****"
f.write('\n'+c3+'Report on list of all the users with generic usernames in the IAM account:')
f.write(c4+'It is recommended to have IAM user names in email format. There should not be any generic usernames.'+'\n')
allusers = iamclient.list_users()
for username in allusers['Users']:
    print username['UserName']
    f.write(c5+username['UserName']+'\n')

#List of users whose AccessKeys have not been rotated for over 90 days
print "\n****Report of Users who have not rotated their access keys for 90 or more days: ****"
f.write('\n'+c3+'Report of Users who have not rotated their access keys for 90 or more days:')
f.write(c4+'It is recommended to ensure API keys are rotated in every 90 days to ensure security of API keys.'+'\n')
AKuserlist=[] # created empty UserList
allusers = iamclient.list_users()
# To get current time
timenow = datetime.datetime.utcnow()
# Current time into string format and in valied format
timenowstr =timenow.strftime("%Y-%m-%dT%H:%M")
# To get From current time onwards, before 90 days time
req=timenow-datetime.timedelta(days=90)
# before 90 days time Convert into string format and in valied format
current=req.strftime("%Y-%m-%dT%H:%M")
# This methods returns a string formatted in the object's format
reqtime=datetime.datetime.strptime(current,"%Y-%m-%dT%H:%M")
# To get list of users from the IAM 
for user in allusers['Users']:
          AKuserlist.append(user['UserName']) # append users into UserList
          access=iamclient.list_access_keys(UserName=user['UserName']) # From IAM to fetch users
          accesslen=len(access['AccessKeyMetadata']) # TO get the meata data

# condition: from the meata data, for each user getting the creation time 
          if accesslen!= 0:
               utime=access['AccessKeyMetadata'][0]['CreateDate']
               userf=datetime.datetime.strftime(utime,"%Y-%m-%dT%H:%M")
               crtdt =datetime.datetime.strptime(userf,"%Y-%m-%dT%H:%M")
# condition: Fetching above 90 days users 
               if userf < current:
                    dayspassed = datetime.datetime.strptime(timenowstr,"%Y-%m-%dT%H:%M")
                    dayspassd=dayspassed - crtdt
                    daysp = str(dayspassd)
                    dates,times= daysp.split(',')
                    print("User:|%s|"%user['UserName']+" has not changed the Access keys for %s"%dates) 
                    f.write(c5+"%s"%user['UserName']+" has not changed the Access keys for %s"%dates+'\n')

#Password Policy validation
print "\n****Report of the Password Policy enabled on the AWS account: ****"
f.write('\n'+c3+'Report of the Password Policy enabled on the AWS account:')
f.write(c4+'To ensure security of our account, it is recommended that we have at least 10 alphanumeric character password for IAM users.'+'\n')
try:
   passpolicy = iamclient.get_account_password_policy()

   #print passpolicy['PasswordPolicy']
   pols = passpolicy['PasswordPolicy']
   lcase =  pols['RequireLowercaseCharacters']
   Ucase = pols['RequireUppercaseCharacters']
   passlen = pols['MinimumPasswordLength']
   renum = pols['RequireNumbers']
   reqsym = pols['RequireSymbols']
   exppass = pols['ExpirePasswords']
   if 'PasswordReusePrevention' not in pols:
    print "Password Reuse policy has not been set."
    f.write(c5+"Password Reuse policy has not been set."+'\n')
   elif 'PasswordReusePrevention' in pols:
    if pols['PasswordReusePrevention'] <= 4:
        print "The Password resuse policy that has been set reached the expectations."
        f.write(c5+"The Password resuse policy that has been set reached the expectations."+'\n')
    else:
        print "Password Resuse has been set and the value is %s.Avoid reuse for 5 passwords."%pols['PasswordReusePrevention']
        f.write(c5+"Password Resuse has been set and the value is %s.Avoid reuse for 5 passwords."%pols['PasswordReusePrevention']+'\n')
   if passlen >= 10:
    print "The minimum password length has reached expectations. The Password Length set is %s"%passlen
    f.write(c5+"The minimum password length has reached expectations. The Password Length set is %s"%passlen+'\n')
    if lcase == True and Ucase == True and renum == True and reqsym == True:
        print "The current password policy satisfies all the following conditions: Lowercase,Uppercase,Numbers and Symbols"
        f.write(c5+"The current password policy satisfies all the following conditions: Lowercase-Uppercase-Numbers and Symbols"+'\n')
    elif lcase == True and Ucase == False and renum == True and reqsym == True:
        print "Please enable use of Uppercase letters in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase, Numerics and Symbols"
        f.write(c5+"Please enable use of Uppercase letters in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase-Numerics and Symbols"+'\n')
    elif lcase == True and Ucase == False and renum == True and reqsym == False:
        print "Please enable use of Uppercase letters and Symbols in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase and Numerics"
        f.write(c5+"Please enable use of Uppercase letters and Symbols in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase and Numerics"+'\n')
    elif lcase == True and Ucase == False and renum == True and reqsym == True:
        print "Please enable use of Uppercase letters in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase, Numerics and Symbols"
        f.write(c5+"Please enable use of Uppercase letters in the password policy to strengthen the password. The current password policy satisfies the following conditions: Lowercase-Numerics and Symbols"+'\n')
    else:
        print "Please ensure that the following password policy is implemented.Password should include Lowercase letters, Uppercase letters, Numbers and Symbols."
        f.write(c5+"Please ensure that the following password policy is implemented.Password should include: Lowercase letters-Uppercase letters-Numbers and Symbols."+'\n')

   else:
    print "Please ensure that the minimum length for passwords is 10. The current lenth is %s"%passlen
    f.write(c5+"Please ensure that the minimum length for passwords is 10. The current lenth is %s"%passlen+'\n')
   if exppass == True:
    print "Password exipiration is being enforced."
    f.write(c5+"Password exipiration is being enforced."+'\n')
   else:
    print "Password expiration is not being enforced. Please enable Password Expiration."
    f.write(c5+"Password expiration is not being enforced. Please enable Password Expiration."+'\n')
except Exception as e:
    f.write(c5+"Password policy has not been enabled in the account. Please enable password policy.")
    print e
#Users without passwords
print "\n****Report on list of users with passwords never created: ****"
f.write('\n'+c3+'Report on list of users with passwords never created:')
f.write(c4+'Users without Passwords should have Passwords enabled.'+'\n')
userswopass=[]
for users in allusers['Users']:
    getuser = iamclient.get_user(UserName=users['UserName'])
#    print getuser
#    print getuser['User']
#    for pasword in getuser['User']:
    if 'PasswordLastUsed' not in  getuser['User']:
            userswopass.append(users['UserName'])
print "The following users do not have passwords." 
for finlist in userswopass:
    print "Username: %s"%finlist
    f.write(c5+"Username: %s"%finlist+'\n') 

#Users with individual user IAM permissions.
print "\n****Report on list of users with IAM permissions assigned to them as indiviudal policies: ****"
f.write('\n'+c3+'Report on list of users with IAM permissions assigned to them as indiviudal policies:')
f.write(c4+'All privileges to IAM users should be granted using IAM groups. This makes permissions management easy and ensure transparency in the system.'+'\n')
for indiuser in allusers['Users']:
    policy = iamclient.list_user_policies(UserName=indiuser['UserName'])['PolicyNames']
    exd = iamclient.list_groups_for_user(UserName=indiuser['UserName'])
    exclude = exd['Groups']
    if len(exclude)==0:
        print "UserName: %s"%indiuser['UserName']
        f.write(c5+"UserName: %s"%indiuser['UserName']+'\n')
        if len(policy)>0:
            for i in policy:
                getpolicy = iamclient.get_user_policy(UserName=indiuser['UserName'],PolicyName=i)
                print "Policy Name: %s"%getpolicy['PolicyName']
                f.write(c5+"Policy Name: %s"%getpolicy['PolicyName']+'\n')
                print "Policy Resource Details:"
                f.write(c5+"Policy Resource Details:"+'\n')
                try:
                    print "%s"%getpolicy['PolicyDocument']['Statement'][0]['Action']
                    #f.write(c3+"%s"%getpolicy['PolicyDocument']['Statement'][0]['Action']+'\n')
                    f.write(c5+"To find the list of permissions added please check the o/p in the shell."+'\n') 
                except Exception as e:
                    print "%s"%getpolicy['PolicyDocument']['Statement']['Action']
                    # f.write(c3+"%s"%getpolicy['PolicyDocument']['Statement']['Action']+'\n')

########################
#EC2 Assessment
f.write('2')
ec2conn = boto3.client('ec2')
regions = ec2conn.describe_regions()['Regions']
#Verify if there are instances using role.
f.write(c2+'EC2'+'\n')
print "\n****Report on the list of instances that do not use roles.****"
f.write('\n'+c3+'Report on the list of instances that do not use roles:')
f.write(c4+'To ensure EC2 instances can connect to other AWS services, it is recommended to use IAM roles over API keys.'+'\n')
ec2roles=[]
ec2woroles=[]
for region in regions:
    ec2client = boto3.client('ec2',region_name=region['RegionName'])
    ec2describe = ec2client.describe_instances()
    for instances in  ec2describe['Reservations']:
        for ins in instances['Instances']:
#            print ins['Tags'][0]['Key']
            if 'IamInstanceProfile' in ins:
                rolearn=(ins['IamInstanceProfile']['Arn'])
                rolename=rolearn.split('/')[-1]
                inst=ins['InstanceId'],ins['Tags'][0]['Value'],rolename
                ec2roles.append(inst)
            else:
                instwo=ins['InstanceId']+' '+ins['Tags'][0]['Value']
                ec2woroles.append(instwo)
                veri = ec2client.describe_instances(InstanceIds=[ins['InstanceId']])
#                print veri
#print "\nList of EC2 instances with roles attached to them:"
#for role in ec2roles:
#    print role
#    f.write(c3+role+'\n')

print "\nList of EC2 instances with no roles attached to them:"
f.write(c5+"List of EC2 instances with no roles attached to them:"+'\n')
for worole in ec2woroles:
    print worole
    wrole=str(worole)
    f.write(c5+wrole.strip('()')+'\n')

#Check if the instances use default tenancy
print "\n****Report on the instance tenancy:****"
f.write('\n'+c3+"Report on the instance tenancy:")
f.write(c4+'If there is any protected health information stored on your EC2 instances, it is recommended to use EC2 instances with dedicated tenancy.'+'\n')
for region in regions:
    ec2clientten = boto3.client('ec2',region_name=region['RegionName'])
    ec2describeten = ec2clientten.describe_instances()
    for instances in  ec2describeten['Reservations']:
        for ins in instances['Instances']:
            if ins['Placement']['Tenancy']=='default':
                print "The instance with ID: %s has default tenancy."%ins['InstanceId']
                f.write(c5+"%s has default tenancy."%ins['InstanceId']+'\n')
            else:
                print "The following instance does not have Default tenancy.Instance Id: %s"%ins['InstanceId']
                f.write(c5+"Instance %s does not have default tenancy."%ins['InstanceId'])

#Check instances that have been launched with public IPs or Elastic IPs
print "\n****Report on the list of instances that have public IPs.****"
f.write('\n'+c3+'Report on the list of instances that have public IPs:')
f.write(c4+'Public IPs or Elastic IPs should be assigned to EC2 instances under specific use-cases.'+'\n')
pubips=[]
elasticips=[]
for region in regions:
    ec2clientpub = boto3.client('ec2',region_name=region['RegionName'])
    ec2describepub = ec2clientpub.describe_instances()
    ec2addresses = ec2clientpub.describe_addresses()
    for add in  ec2addresses['Addresses']:
        if 'InstanceId' in add:
            elasticips.append(add['PublicIp'])
        else:
            print "The EIP: %s does not have an instance attached to it. Plese verify if the EIP is required."%add['PublicIp']
            f.write(c5+"The EIP: %s does not have an instance attached to it. Plese verify if the EIP is required."%add['PublicIp']+'\n')
#    print ec2describe['Reservations']
    for res in ec2describepub['Reservations']:
        insdes = res['Instances']
        if insdes[0]['PublicDnsName'] != '':
            pubinsdes = ec2clientpub.describe_instances(InstanceIds=[insdes[0]['InstanceId']])
            netint = pubinsdes['Reservations']
            for net in netint:
                insnet = net['Instances']
                for interface in insnet:
                    inter = interface['NetworkInterfaces']
                    for associations in inter:
                      try:
                        association_details = associations['Association']
                        instanceip = pubinsdes['Reservations'][0]['Instances'][0]['Tags']
                        for ins in instanceip:
                            if ins['Key'] == 'Name':
                               pubinst = association_details['PublicIp']+" "+ins['Value']
#                    print pubinst
                               pubips.append(pubinst)
                        #print i['Association']
                      except Exception as e:
                        print "The instance does not have 'Association'. Moving on..."

            #netint= pubinsdes['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['Association']
            instanceip = pubinsdes['Reservations']
            for iip in instanceip:
                iip_instance = iip['Instances']
                for ins_iip in iip_instance:
                    instags = ins_iip['Tags']
                    inter_enis = interface['NetworkInterfaces']
                    for ins in instags:
                        if ins['Key'] == 'Name':
                            try:
                                for eni in inter_ntw:
                                    associ = eni['Association']

                                    pubinst = associ['PublicIp']+" "+ins['Value']
#                    print pubinst
                                    pubips.append(pubinst)
                            except Exception as e:
                                print "The instance does not have 'Association' or 'Tags'. Moving on..."
print "\nInstances with Public IPs:"
f.write(c5+'Instances with Public IPs:'+'\n')
for tes in pubips:
    ip,nam= tes.split(None,1)
    if ip in elasticips:
        print "%s is an elastic IP and the instance name is %s."%(ip,nam)
        f.write(c5+"%s is an elastic IP and the instance name is %s."%(ip,nam)+'\n')
    else:
        print "%s is a public IP and the instance name is %s."%(ip,nam)   
        f.write(c5+"%s is a public IP and the instance name is %s."%(ip,nam)+'\n')

#Check ports on the SGs
print "\n****Report on the instances with security group ports open to the world: ****"
f.write('\n'+c3+'Report on the instances with security group ports open to the world:')
f.write(c4+'To ensure security of linux EC2 instances it is recommended to restrict their access to either whitelisted IP addresses or VPN for ports 22 and 3389.  To maximize security of applications running over ports 80 & 443, ensure they are only accessible via ELB or UTM layer. Ports 80 & 443 on EC2 instances should be only opened up for ELB or UTM layer.'+'\n')
port_22=[]
port_80=[]
port_443=[]
port_3389=[]
final=[]
for region in regions:
    ec2clientport = boto3.client('ec2',region_name=region['RegionName'])
    ec2describeport = ec2clientport.describe_instances()
    ec2sgdesport = ec2clientport.describe_security_groups()
    for secgrps in ec2sgdesport['SecurityGroups']:
        for ips in secgrps['IpPermissions']:
            if len(ips['IpRanges'])>0:
                for cidr in ips['IpRanges']:
                    ipcidr = cidr['CidrIp']
                    if ipcidr == '0.0.0.0/0':
                        try:
                          fromport = ips['FromPort']
                          toport = ips['ToPort']
                          if fromport == 80:
#                            print " The security group with ID %s is opened to world for traffic to port 80."%secgrps['GroupId']
                            port_80.append(secgrps['GroupId'])
                          if fromport == 22:
                             port_22.append(secgrps['GroupId'])
#                             print " The security group with ID %s is opened to world for traffic to port 22."%secgrps['GroupId']
                          if fromport == 3389:
#                            print " The security group with ID %s is opened to world for traffic to port 3389."%secgrps['GroupId']
                            port_3389.append(secgrps['GroupId'])
                          if fromport == 443:
#                            print " The security group with ID %s is opened to world for traffic to port 443."%secgrps['GroupId']
                            port_443.append(secgrps['GroupId'])
                          if fromport != 80 and fromport != 443 and fromport != 22 and fromport != 3389:
                            print "The security Group with ID %s is opened to the world for the port %s."%(secgrps['GroupId'],fromport)
                        except Exception as b:
                            pass
print "\nSecurity Groups with port 80 open to the world:"
f.write(c5+'Security Groups with port 80 open to the world:'+'\n')
for p80 in port_80:
    print p80
    f.write(c5+p80+'\n')
print "Security Groups with port 22 open to the world:"
f.write('\n'+c5+'Security Groups with port 22 open to the world:'+'\n')
for p22 in port_22:
    print p22
    f.write(c5+p22+'\n')
print "Security Groups with port 443 open to the world:"
f.write('\n'+c5+"Security Groups with port 443 open to the world:"+'\n')
for p443 in port_443:
    print p443
    f.write(c5+p443+'\n')
print "Security Groups with port 3389 open to the world:"
f.write('\n'+c5+"Security Groups with port 3389 open to the world:"+'\n')
for p3389 in port_3389:
    print p3389
    f.write(c5+p3389+'\n')

#Report on the Unused SGs. CHecks EC2, ELB, RDS
f.write('3')
f.write(c2+'Security Groups and Network ACLs'+'\n')
print "\n****Report with list of unused security groups: ****"
f.write('\n'+c3+'Report with list of unused security groups:')
f.write(c4+'It is recommended to delete any un-used security groups in order to avoid confusion or accidental mistakes.'+'\n')
print "The Security Groups below are unused. Please verify and delete the security groups that are no longer requred."
f.write(c5+"The Security Groups below are unused. Please verify and delete the security groups that are no longer requred."+'\n')
dbsg=[]
elbid=[]
allsgs=[]
inssg=[]
sgsinsgs=[]
final=[]
for region in regions:
#    print region['RegionName']
    ec2sgs = boto3.client('ec2',region_name=region['RegionName'])
    secgrps = ec2sgs.describe_security_groups()
    for sginsg in secgrps['SecurityGroups']:
        for sgip in sginsg['IpPermissions']:
            for sgid in sgip['UserIdGroupPairs']:
                sgsinsgs.append(sgid['GroupId'])
    lbs = boto3.client('elb',region_name=region['RegionName'])
    rds = boto3.client('rds',region_name=region['RegionName'])
    rdsdes = rds.describe_db_instances()
    for rdsins in rdsdes['DBInstances']:
        rdss= rdsins['VpcSecurityGroups']
        for rdsid in rdss:
#       for rdsg in rdss['VpcSecurityGroups']:
         dbsg.append(rdsid['VpcSecurityGroupId'])
    elbs = lbs.describe_load_balancers()
#    print secgrps
    for libs in elbs['LoadBalancerDescriptions']:
#        print lbs
        for elbnames in libs['SecurityGroups']:
            elbid.append(elbnames)
    for sgs in secgrps['SecurityGroups']:
            grpid = sgs['GroupId']
            allsgs.append(grpid)
#    print allsgs
    instances = ec2sgs.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running', 'stopped']
                }
            ])
    for ins in instances['Reservations']:
            for inst in ins['Instances']:
                 ins_sg = inst['SecurityGroups'][0]['GroupId']
                 inssg.append(ins_sg)
for alls in allsgs:
        if alls not in inssg:
            final.append(alls)
for elid in elbid:
        if elid in  final:
            final.remove(elid)
for dbs in dbsg:
        if dbs in final:
            final.remove(dbs)
#print "The Final list of unused SGs:"
for fn in final:
        try:
            sgdes = ec2sgs.describe_security_groups(GroupIds=[fn])
            if sgdes['SecurityGroups'][0]['GroupName']=='default':
                final.remove(fn)
        except Exception as e:
            pass
for fina in final:
    if fina in sgsinsgs:
        final.remove(fina)
for finalsgids in final:
    print finalsgids
    f.write(c5+finalsgids+'\n')

#Check if the NACLs are in place. This involves a partial manual process. One has to go through the list of NACLs and recommend changes if any.
print "\n****Report on the network ACLs in place: ****"
f.write('\n'+c3+'Report on the network ACLs in place:')
f.write(c4+'To ensure separation between environments and avoid common threats, it is recommended to DENY non-used or most commonly exploited ports.'+'\n')
for region in regions:
#    print region['RegionName']
    ec2nacl = boto3.client('ec2',region_name=region['RegionName'])
    nacls = ec2nacl.describe_network_acls()
    for nacl in nacls['NetworkAcls']:
        print "\nRegion: %s"%region['RegionName']+" - VpcId:"+nacl['VpcId']+" - NACL ID:"+nacl['NetworkAclId']+" - Entries",nacl['Entries']
        nentries=str(nacl['Entries'])
        f.write(c5+"Region%s"%region['RegionName']+" - VpcId:"+nacl['VpcId']+" - NACL ID:"+nacl['NetworkAclId']+" - For entries please check the o/p in the shell"+'\n')

#Check for Instances that do not have/have Cloud Watch alarms set. Ensure that you have given the region name here is set.
f.write('4')
f.write(c2+'CloudWatch'+'\n')
print "\n****Report on the CloudWatch alarms for EC2 instances: ****"
f.write('\n'+c3+'Report on the CloudWatch alarms for EC2 instances:')
f.write(c4+'If Detailed Monitroing is enabled, Amazon EC2 console displays monitoring graphs with a 1-minute period for the instance. It is recommended to enable this for Production and Staging instances for more granular monitoring data.'+'\n')
list1=[]
list2=[]
list3=[]
list4=[]
list5=[]
list6=[]
list7=[]
metric_names = ['CPUUtilization','StatusCheckFailed_System','StatusCheckFailed_Instance']
ec2conn = boto3.client('ec2')
regions = ec2conn.describe_regions()['Regions']
for region in regions:
    ec2 = boto3.client('ec2',region_name=region['RegionName'])
#ec2cw = boto3.client('ec2',region_name='us-east-1')
    cw = boto3.client('cloudwatch',region_name=region['RegionName'])
#cw = boto3.client('cloudwatch',region_name='us-east-1')
    instances = ec2.describe_instances()['Reservations']
for i in instances:
        list1.append(i['Instances'][0]['InstanceId'])
for i in list1:
#        count=0
            alarmcpu = cw.describe_alarms_for_metric(MetricName='CPUUtilization',Namespace='AWS/EC2',Dimensions=[{'Name':'InstanceId','Value':i}])['MetricAlarms']
            time.sleep(0.34)
            if alarmcpu != None:
                print("Instance: ",i, "Has CPUUtilization as a metric")
                list2.append(i)
            else:
                print("The instance doesn't have the CPUUtilization metric")
                list3.append(i)
#        for StatusCheckFailed_System in metric_names:
            alarmstf = cw.describe_alarms_for_metric(MetricName='StatusCheckFailed_System',Namespace='AWS/EC2',Dimensions=[{'Name':'InstanceId','Value':i}])['MetricAlarms']
            time.sleep(0.34)
            if alarmstf != None:
                print("Instance: ",i, "Has StatusCheckFailed_System as a metric")
                list4.append(i)
            else:
                print("The instance doesn't have the StatusCheckFailed_System metric")
                list5.append(i)
#        for StatusCheckFailed_Instance in metric_names:
            alarmst = cw.describe_alarms_for_metric(MetricName='StatusCheckFailed_Instance',Namespace='AWS/EC2',Dimensions=[{'Name':'InstanceId','Value':i}])['MetricAlarms']
            time.sleep(0.34)
            if alarmst != None:
                print("Instance: ",i, "Has StatusCheckFailed_Instance as a metric")
                list6.append(i)
            else:
                print("The instance doesn't have the StatusCheckFailed_Instance metric")
                list7.append(i)
print "\n List of instances with CPUUtilization:"
f.write(c5+'List of instances with CPUUtilization:'+'\n')
for ls2 in list2:
    print ls2
    f.write(c5+ls2+'\n')
print "\nList of instances without CPUUtilization:"
f.write(c5+'List of instances without CPUUtilization:'+'\n')
for ls3 in list3:
    print ls3
    f.write(c5+ls3+'\n')
print "\n List of instances with StatusCheckFailed_Instance:"
f.write(c5+'List of instances with StatusCheckFailed_Instance'+'\n')
for ls4 in list4:
    print ls4
    f.write(c5+ls4+'\n')
print "\nList of instances without StatusCheckFailed_Instance:"
f.write(c5+'List of instances without StatusCheckFailed_Instance:'+'\n')
for ls5 in list5:
    print ls5
    f.write(c5+ls5+'\n')
print "\n List of instances with StatusCheckFailed_System:"
f.write(c5+'List of instances with StatusCheckFailed_System:'+'\n')
for ls6 in list6:
    print ls6
    f.write(c5+ls6+'\n')
print "\nList of instances without StatusCheckFailed_System:"
f.write(c5+'List of instances without StatusCheckFailed_System:'+'\n')
for ls7 in list7:
    print ls7
    f.write(c5+ls7+'\n')    

#############AWS Config
#Check AWS Config
f.write('5')
f.write(c2+'AWSConfig'+'\n')
print "\n****Report on the AWS Config: ****"
f.write('\n'+c3+'Report on the AWS Config:')
f.write(c4+'AWS Config is a fully managed service that provides an AWS resource inventory/configuration historyand configuration change notifications to enable security and governance. It is recommended to enable this across all regions.'+'\n')
rgns=['eu-west-1','sa-east-1','us-east-1','ap-northeast-1','us-west-2','us-west-1','ap-southeast-1','ap-southeast-2']
for region in rgns:
        print "\nAWS config report for Region: %s"%region
        config = boto3.client('config',region_name=region)
        try:
            response = config.describe_config_rules()
            if(response['ConfigRules'][0]['ConfigRuleState']=='ACTIVE'):
                print 'Aws config service is ENABLED for region %s'%region
                f.write(c5+'Aws config service is ENABLED for region %s'%region+'\n')
            else:
                print 'Aws config service is DISABLED for region %s'%region
                f.write(c5+'Aws config service is DISABLED for region %s'%region+'\n')
        except Exception as e:
            print e

##############SES
#SES checking
f.write('6')
f.write(c2+'SES'+'\n')
print "\n****Report on the SES DKIM: ****"
f.write('\n'+c3+'Report on the SES DKIM:')
f.write(c4+'DomainKeys Identified Mail (DKIM) is a standard that allows senders to sign their email messages and ISPs to use those signatures to verify that those messages are legitimate and have not been modified by a third party in transit. It is good to verify DKIM keys for your domain.'+'\n')
ec2conn_ses = boto3.client('ec2',region_name='us-east-1')
emails=[]
ses_regions = ec2conn_ses.describe_regions()['Regions']
for region in ses_regions:
#    print region['RegionName']
        try:
                ses = boto3.client('ses',region_name=region['RegionName'])
                response = ses.list_identities(IdentityType='EmailAddress')
                pprint.pprint(response['Identities'])
                emails = (response['Identities'])
                print '\nReport for region : '+region['RegionName']
                if len(emails)>0:
                    for i in emails:
                        response1 = ses.get_identity_dkim_attributes(Identities=[i])
                        resstr =response1['DkimAttributes'][i]['DkimVerificationStatus']
                        print "For Email: %s, the DKIM verification status is: %s"%(i,resstr)
                        f.write(c5+"For Email: %s, the DKIM verification status is: %s"%(i,resstr)+'\n')        
        except Exception as b:
                print '\n'+str(b)
                f.write(c5+'Please check the command line for errors'+'\n')

############## ELB
#ELB Reports
f.write('7')
f.write(c2+'ELB'+'\n')
print "\n****Report on ELB port Mismatch: ****"
f.write('\n'+c3+'Report on ELB port Mismatch:')
f.write(c4+'Checks for load balancers configured with a missing security group or a security group that allows access to ports that are not configured for the load balancer.'+'\n')
def check_ports(ec2_conn,elb_listener_ports,elb_name,sg_id):
        sg = ec2_conn.describe_security_groups(GroupIds=sg_id)['SecurityGroups'][0]
        sg_ports=[]
        for ip_permission in sg['IpPermissions']:
                if ip_permission['IpProtocol']!='-1':
                        if ip_permission['FromPort']==ip_permission['ToPort']:
                                sg_ports.append(ip_permission['FromPort'])
                        else:
                                sg_ports.append(ip_permission['FromPort']+ip_permission['ToPort'])
        result = set(elb_listener_ports)^set(sg_ports)
        print "\nELB Name: %s"%elb_name
        f.write(c5+'ELB Name: %s'%elb_name+'\n')
        print "Security_Group_Id: %s"%sg_id
        f.write(c5+"Security_Group_Id: %s"%sg_id+'\n')
        if result:
                for i in result:
                        if i in elb_listener_ports:
                                if not i in sg_ports:
                                        print "Port mismatch found. Port number: %s"%i
                                        f.write(c5+"Port mismatch found. Port number: %s"%i+'\n')
                        elif i in sg_ports:
                                if not i in elb_listener_ports:
                                        print "Security Group port mismatch found. Port number: %s"%i
                                        f.write(c5+"Security Group port mismatch found. Port number: %s"%i+'\n')
        else:
                print "There is no port mismatch."
                f.write(c5+"There is no port mismatch."+'\n')

        #pass

for region in regions:
    elb_conn = boto3.client('elb',region_name=region['RegionName'])
    ec2_conn = boto3.client('ec2',region_name=region['RegionName'])
    elbs = elb_conn.describe_load_balancers()['LoadBalancerDescriptions']
    try:
        for elb in elbs:
            elb_listener_ports=[]
            for elb_listener_description in  elb['ListenerDescriptions']:
                elb_listener_ports.append(elb_listener_description['Listener']['LoadBalancerPort'])
            sg_id=elb['SecurityGroups']
            check_ports(ec2_conn,elb_listener_ports,elb['LoadBalancerName'],sg_id)
    except Exception as er:
        print er

#Report on the Backend Authentication and CrossZone Load Balancing
print "\n****Report on Backend Authenticaiton and CrossZone load balancing: ****"
f.write('\n'+c3+'Report on Backend Authenticaiton and CrossZone load balancing:')
f.write(c4+'To ensure secure communication between ELBs and EC2 instances, it is recommended to enabled ELB Backend Authentication ensuring public key of EC2 instances matches public key provided to ELB.Cross Zone Load Balancing ensures incoming traffic is distributed equally to backend instances regardless of the availability zone in which they are located.'+'\n')
backdis=[]
backena=[]
crossdis=[]
crossena=[]
for region in regions:
    elb=boto3.client('elb',region_name=region['RegionName'])
    elbs=elb.describe_load_balancers()
    for i in elbs['LoadBalancerDescriptions']:
#        print "\nVPC ID:" i['VPCId']
        k=len(i['BackendServerDescriptions'])
        if k==0:
            backdisabled= "LoadBalancer:%s - VPCID:%s - Region:%s"%(i['LoadBalancerName'],i['VPCId'],region['RegionName'])
            backdis.append(backdisabled)
            #print "Backend is disabled for: %s"%i['LoadBalancerName']
        else:
            backenabled= "LoadBalancer:%s - VPCID:%s - Region:%s"%(i['LoadBalancerName'],i['VPCId'],region['RegionName'])
            backena.append(backenabled)
            #print "Backend is enabled for: %s"%i['LoadBalancerName']
        response = elb.describe_load_balancer_attributes(LoadBalancerName=i['LoadBalancerName'])
        attr= response['LoadBalancerAttributes']
        if attr['CrossZoneLoadBalancing']['Enabled']==True:
            crossenabled= "LoadBalancer:%s - VPCID:%s - Region:%s"%(i['LoadBalancerName'],i['VPCId'],region['RegionName'])
            crossena.append(crossenabled)
            #print "CrossZone Loadbalancing is enabled for elb: %s"%i['LoadBalancerName']
        else:
            crossdisabled= "LoadBalancer:%s - VPCID:%s - Region:%s"%(i['LoadBalancerName'],i['VPCId'],region['RegionName'])
            crossdis.append(crossdisabled)
            #print "CrossZone loadbalancing is disabled for %s"%i['LoadBalancerName']
print "\nLoad Balancers with backend authentication disabled:"
f.write(c5+"Load Balancers with backend authentication disabled:"+'\n')
for bd in backdis:
    bcdi=str(bd)
    print bcdi.strip("()")
    f.write(c5+bcdi.strip("()")+'\n')
print "\nLoad Balancers with backend authentication enabled:"
f.write(c5+"Load Balancers with backend authentication enabled:"+'\n')
for be in backena:
    bcen= str(be)
    print bcen.strip("()")
    f.write(c5+bcen.strip("()")+'\n')
print "\nLoad Balancers with CrossZone load balancing disabled:"
f.write(c5+"Load Balancers with CrossZone load balancing disabled:"+'\n')
for cd in crossdis:
    crdi=str(cd)
    print crdi.strip("()")
    f.write(c5+crdi.strip("()")+'\n')
print "\nLoad Balancers with CrossZone load balancing enabled:"
f.write(c5+"Load Balancers with CrossZone load balancing enabled:"+'\n')
for ce in crossena:
    cren=str(ce)
    print cren.strip("()")
    f.write(c5+cren.strip("()")+'\n')

#Checking ELB Policies
print "\n****Report on the policies being used for the ELBs: ****"
f.write('\n'+c3+"Report on the policies being used for the ELBs:")
f.write(c4+'AWS regularly publishes latest ELB cipher policy. Make sure ELB Cipher policies are latest.'+'\n')
latpol=[]
nlatpol=[]
cuspol=[]
for reg in rgns:
    ec2=boto3.client('elb',region_name=reg)
    response = ec2.describe_load_balancers()
    try:
        for res in response['LoadBalancerDescriptions']:
            for res1 in res['ListenerDescriptions']:
                temp = res1['PolicyNames']
                if len(temp)>0:
                    #pdb.set_trace()
                    temp1 = temp[0]
                    #pdb.set_trace()
                    pol_name = temp1.strip()
                    del temp[:]
                    if pol_name.startswith('ELB'):
                        if pol_name == 'ELBSecurityPolicy-2015-05':
                            latpolicy = "PolicyName: %s-ELBName= %s"%(pol_name, res['LoadBalancerName'])
                            latpol.append(latpolicy)
#                            print 'The policy being used is the latest. Policy Name: %s. ELB Name: %s '%(pol_name, res['LoadBalancerName'])
                        else:
                            nlatpolicy = "PolicyName: %s-ELBName= %s"%(pol_name, res['LoadBalancerName'])
                            nlatpol.append(nlatpolicy)
#                            print 'The policy being used is not the latest. Policy Name: %s. ELB Name: %s '%(pol_name, res['LoadBalancerName'])
                    else:
                        cuspolicy = "PolicyName: %s-ELBName= %s"%(pol_name, res['LoadBalancerName'])
                        cuspol.append(cuspolicy)
#                        print 'A custom policy is used. Policy Nmae: %s. ELB Name: %s'%(pol_name, res['LoadBalancerName'])
    except Exception as elb:
        print elb
print "\nELBs using Latest Policy:"
f.write(c5+"ELBs using Latest Policy:"+'\n')
for lp in latpol:
    print lp
    f.write(c5+lp+'\n')
print "\nELBs not using Latest Policy:"
f.write(c5+"ELBs not using Latest Policy:"+'\n')
for nlp in nlatpol:
    print nlp
    f.write(c5+nlp+'\n')
print "\nELBs using Custom Policy:"
f.write(c5+"ELBs using Custom Policy:"+'\n')
for cp in cuspol:
    print cp
    f.write(c5+cp+'\n')

####### EBS Check
f.write('8')
f.write(c2+'EBS'+'\n')
print "\n****Report on the volumes encryption: ****"
f.write('\n'+c3+'Report on the volumes encryption:')
f.write(c4+'To ensure security of data at rest, it is advisable to store data on secondary volumes and make sure they are encrypted.'+'\n')
keys_list=[]
volms=[]
def_key='arn:aws:kms:us-west-2:080062124614:key/f97cc5d9-51be-43d9-93d2-09f5105096c8'
for region in regions:
    ec2ebs = boto3.client('ec2',region_name=region['RegionName'])
    response=ec2ebs.describe_volumes()
    for volume in response['Volumes']:
        if volume['Encrypted']==True:
            keys_list.append(volume['KmsKeyId'])
            if(def_key in keys_list):
                print 'This volume is encrypted with default kms-key with ID : '+volume['VolumeId']
            else:
                pass
        else:
            volms.append(volume['VolumeId'])
#            print volume['VolumeId']
print "Volumes that aren't encrypted:"
f.write(c5+"Volumes that aren't encrypted:"+'\n')
for v in volms:
    print v
    f.write(c5+v+'\n')

#Report on EBS Snapshots
print "\n****Report on existing snapshots: ****:"
f.write('\n'+c3+"Report on existing snapshots:")
f.write(c4+'It is recommended to delete snapshots older than 90 days unless there is an absolute need to retain them.'+'\n')
snap_ids=[]
x= allusers['Users'][0]['Arn']
ownerid = x.split(':')[4]
for region in regions:
    ec2snap=boto3.client('ec2',region_name=region['RegionName'])
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=90)
    DATEFORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    stime=ec2snap.describe_snapshots(OwnerIds=[ownerid],Filters=[{'Name':'status','Values': ['completed']}])
    count = 0
    print "\nRegion: %s"%region['RegionName']
    f.write('\n'+c3+"Region: %s"%region['RegionName']+'\n')
    for s in stime['Snapshots']:
        k= s['StartTime']
        if k.strftime(DATEFORMAT) < cutoff.strftime(DATEFORMAT):
            snap_ids.append(s['SnapshotId'])
#            print s['SnapshotId']
            count = count+1
            val=str(snap_ids).strip('[]')
    print "Total number of snapshots that are older than 90 days = " + str(count)
    f.write(c5+"Total number of snapshots that are older than 90 days = " + str(count)+'\n')
    print "Total number snapshots in the account = " + str(len(stime['Snapshots']))
    f.write(c5+"Total number snapshots in the account = " + str(len(stime['Snapshots']))+'\n')

#Report on the list of available volumes
print "\n****Report on the list of available volumes: ****"
f.write('\n'+c3+'Report on the list of available volumes:')
f.write(c4+'It is recommended to delete un-attached EBS volumes which are not in use and are lying in available state.'+'\n')
for region in regions:
    ec2 = boto3.client('ec2',region_name=region['RegionName'])
    response=ec2.describe_volumes()
    for volume in response['Volumes']:
#    print volume
        if volume['State']=='available':
            print volume['VolumeId'],region['RegionName']
            f.write(c5+volume['VolumeId']+''+region['RegionName']+'\n')

########## Cloud Trail
f.write('9')
f.write(c2+'CloudTrail'+'\n')
print "\n****Report on CloudTrail: ****"
f.write('\n'+c3+'Report on CloudTrail:')
f.write(c4+'It is highly recommended to enable CloudTrail in all regions to ensure all actions across your AWS account is recorded and can be used for audit purpose in future.It is recommended to store all CloudTrail logs in same master bucket.It is recommended to encrypt CloudTrail logs using server side encryption with AWS KMS managed keys.Logfile validation be used to track any changes made to logs after delivered by CloudTrail'+'\n')
for region in regions:
    print "\nRegion:  %s"%region['RegionName']
    f.write('\n'+c5+"Region:  %s"%region['RegionName']+'\n')
    cloud_trail = boto3.client('cloudtrail',region_name=region['RegionName'])
    trails = cloud_trail.describe_trails()['trailList']
    for trail in trails:
        s3buck = trail['S3BucketName']
        trailarn = trail['TrailARN']
        trailinteg = trail['LogFileValidationEnabled']
#        print trailinteg
        trstat = cloud_trail.get_trail_status(Name=trailarn)
        if trailinteg == True:
            print "Log File Validation has been enabled."
            f.write(c5+"Log File Validation has been enabled."+'\n')
        else:
            print "Log File Validation has been disabled. Please enable Log File Validation."
            f.write(c5+"Log File Validation has been disabled. Please enable Log File Validation."+'\n')
        if trstat['ResponseMetadata']['HTTPStatusCode']==200:
            print "CloudTrail has been enabled."
            f.write(c5+"CloudTrail has been enabled."+'\n')
        else:
            print "CloudTrail has been disabled. Please enable CloudtTrail."
            f.write(c5+"CloudTrail has been disabled. Please enable CloudtTrail."+'\n')
        if 'KmsKeyID' in trail:
            print "TrailName-%s :Encryption has been Enabled %s"%(trial['Name'],trail['KmsKeyId'])
            f.write(c5+"TrailName-%s :Encryption has been Enabled %s"%(trial['Name'],trail['KmsKeyId'])+'\n')
        else :
            print "TrailName-%s :Encryption has been Disabled "%(trail['Name'])
            f.write(c5+"TrailName-%s :Encryption has been Disabled "%(trail['Name'])+'\n')
#        print trail['S3BucketName']
        if trail['S3BucketName'] == s3buck:
                print "The S3 bucket is being compared with %s to ensure that a centralized bucket is being used. Centralized bucket test result: Pass"%s3buck
                f.write(c5+"The S3 bucket is being compared with %s to ensure that a centralized bucket is being used. Centralized bucket test result: Pass"%s3buck+'\n')
        else:
                print "Centralized buckets are not being used."
                f.write(c5+"Centralized buckets are not being used."+'\n')

############## VPC
f.write('10')
f.write(c2+'VPC'+'\n')
print "\n****Report on VPCs: ****"
f.write('\n'+c3+'Report on VPCs:')
f.write(c4+'It is recommended to enable VPC flow logs for capturing IP traffic going to and from network interfaces in VPC.If there is any protected health information stored on your EC2 instances, it is recommended to use VPC with dedicated tenancy.It is recommended to provide sufficient subnet IP range to meet your future growth requirements.'+'\n')
for region in regions:
    print "\n#REGION:%s"%region['RegionName']
    f.write('\n'+c5+"REGION:%s"%region['RegionName']+'\n')
    ec2clientvpc = boto3.client('ec2',region_name=region['RegionName'])
    ec2res = boto3.resource('ec2',region_name=region['RegionName'])
    subnets = ec2clientvpc.describe_subnets()
    vpcs = ec2clientvpc.describe_vpcs()
    try:
        flowlogs = ec2client.describe_flow_logs()
        for fl in flowlogs:
#            print "FlowLogs are Enabled."
            f.write(c5+"FlowLogs are Enabled."+'\n')
            fl['FlowLogs']
    except Exception as e:
        print "\nIn region %s, Permissions to pull information on the VPC Flowlogs are not sufficient. It is important to enable VPCFlowlogs to ensure that the traffic flowing into the VPC is logged."%region['RegionName']
        f.write(c5+"In region %s Permissions to pull information on the VPC Flowlogs are not sufficient. It is important to enable VPCFlowlogs to ensure that the traffic flowing into the VPC is logged."%region['RegionName']+'\n')
#    print flowlogs
#    print vpcs
    for vpc in vpcs['Vpcs']:
#        print vpc
        if vpc['IsDefault'] != True:
#            print vpc['VpcId'], vpc['Tags'][0]['Value']
            if vpc['InstanceTenancy'] == 'default':
                print "\nThe following VPC has %s tenancy. VPCID: %s"%(vpc['InstanceTenancy'],vpc['VpcId'])
                f.write(c5+"The following VPC has %s tenancy. VPCID: %s"%(vpc['InstanceTenancy'],vpc['VpcId'])+'\n')
            else:
                print "\nThe following VPC do not have Instance Tenancy as default: %s"%vpc['VpcId']
                f.write(c5+"The following VPC do not have Instance Tenancy as default: %s"%vpc['VpcId']+'\n')
    for subnet in subnets['Subnets']:
        print "\nVPCId: %s - SubnetId: %s - CIDRBlock: %s"%(subnet['VpcId'],subnet['SubnetId'],subnet['CidrBlock'])
        f.write(c5+"VPCId: %s - SubnetId: %s - CIDRBlock: %s"%(subnet['VpcId'],subnet['SubnetId'],subnet['CidrBlock'])+'\n')
        subrange = subnet['CidrBlock'].split("/")[-1]
        if subrange > '26' and subrange < '32':
            print "The subnet IP ranges for the subnet may not be sufficient. Please verify and choose a wider range."
            f.write(c5+"The subnet IP ranges for the subnet may not be sufficient. Please verify and choose a wider range."+'\n')
        if subrange > '21' and subrange < '25':
            print "The subnet is in a recommended CIDR ranges."
            f.write(c5+"The subnet is in a recommended CIDR ranges."+'\n')
        else:
            print "The subnet CIDR ranges need to be rechecked. Subnet ID: %s"%subnet['SubnetId']
            f.write(c5+"The subnet CIDR ranges need to be rechecked. Subnet ID: %s"%subnet['SubnetId']+'\n')

################ S3
f.write('11')
f.write(c2+'S3'+'\n')
print "\n****Report on S3 buckets with no Lifecycle policy enabled: ****"
f.write('\n'+c3+"Report on S3 buckets with no Lifecycle policy enabled:")
f.write(c4+'To save cost it is recommended to enable lifecycle rules for logs stored in Amazon S3. Depending upon the nature of these log files they can be deleted or moved to Glacier.'+'\n')
temp=[]
temp1=[]
s3variable=''
publicbuc=[]
privatebuc=[]
cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=90)
DATEFORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
s3 = boto3.client('s3')
response = s3.list_buckets()
for resp in response['Buckets']:
    s3variable = resp['Name']
    #pprint.pprint(resp)
    try:
        response2=s3.get_bucket_location(Bucket=s3variable)
        response1=s3.get_bucket_lifecycle(Bucket=s3variable)
    except Exception as b:
        #print 'S3 Buckets which are NOT enabled with any life policies : '+s3variable
        temp.append([s3variable,str(response2['LocationConstraint'])])
print '\nS3 buckets with no lifecycle policies:'
f.write(c5+'S3 buckets with no lifecycle policies:'+'\n')
for b in temp:
    print (b[0])
    f.write(c5+(b[0])+'\n')
#starting for the policies for older buckets
for resp in response['Buckets']:
    k=resp['CreationDate']
    if k.strftime(DATEFORMAT) < cutoff.strftime(DATEFORMAT):
        s3variable=resp['Name']
        try:
            response3=s3.get_bucket_location(Bucket=s3variable)
            response1 = s3.get_bucket_lifecycle(
            Bucket=s3variable)
            #print 'Life Cycle Configuration is enabled for the bucket : <<<<<<'+s3variable+'>>>>>>'
        except Exception as b:
            #print 'Life Cycle policy configuration doesnot exist for the buckets which are 3 months older: '+s3variable
            temp1.append([s3variable,str(response3['LocationConstraint'])])
#template = "{0:50} {1:10}"
print '\nS3 buckets with no lifecycle policies for over 3 months:'
f.write(c5+'S3 buckets with no lifecycle policies for over 3 months:'+'\n')
#print template.format("S3Bucket", "Location")
for b in temp1:
    print (b[0])
    f.write(c5+(b[0])+'\n')

##Check if S3 buckets are public
#print "\n****Report on if the buckets are private or public: ****" 
#f.write('\n'+c3+"Report on if the buckets are private or public:")
#f.write(c4+'It is essential that all the buckets in S3 have restricted access.'+'\n')
#s3buckslist=[]
#publicbuc=[]
#privatebuc=[]
#permredir=[]
#s3client = boto3.client('s3')
#respub = s3client.list_buckets()
#for s3bucks in respub['Buckets']:
#    s3buckslist.append(s3bucks['Name'])
#for region in regions:
#    s3pub= boto3.client('s3',region_name=region['RegionName'], config=boto3.session.Config(signature_version='s3v4'))
##s3 = boto3.client('s3')
#    response = s3pub.list_buckets()
#    for resp in response['Buckets']:
#        temp = resp['Name']
##        s3buckslist.append(temp)
#        try:
#            response1 = s3pub.get_bucket_policy(Bucket=temp)
#            # pprint.pprint(response1['Policy'])
#            temp1 = str(response1['Policy'])
#            temp2 = temp1.partition('[')[-1].rpartition(']')[0]
#            temp3 = temp2.split(":")[1]
#            temp4 = temp3.split(",")[0]
#            temp5 = temp4[1:-1]
#            if temp5 == 'AllowPublicRead':
##               print 'Bucket is Public : '+temp
#                publicbuc.append(temp)
#            else:
##               print 'Bucket is private : '+temp
#                privatebuc.append(temp)
#        except botocore.exceptions.ClientError as errb:
#            if errb.response['Error']['Code'] == 'NoSuchBucketPolicy':
#                privatebuc.append(temp)
#            elif errb.response['Error']['Code'] == 'PermanentRedirect':
#                permredir.append(temp)
##               print 'This is exception'+str(b)+'bucket name is : '+temp
#print "\nList of Buckets that are public:"
#f.write('\n'+c5+"List of Buckets that are public:"+'\n')
#for pub in s3buckslist:
##    print pub
#    if pub in publicbuc:
#        print pub
#        f.write(c5+pub+'\n')
#print "\nList of Buckets that are private:"
#f.write('\n'+c5+"List of Buckets that are private:"+'\n')
#for prv in s3buckslist:
#    if prv in privatebuc:
#        print prv
#        f.write(c5+prv+'\n')
##print "\nList of Buckets. Perm Redir:"
##for prm in s3buckslist:
##    if prv in permredir:
##        print prm
f.close()

