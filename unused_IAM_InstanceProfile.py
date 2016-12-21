from boto import ec2
import boto
from boto import iam
import os
from collections import OrderedDict
con = boto.connect_iam()

text_file1 = open("profile_names.txt", "w")
prof = con.list_instance_profiles()
for p in prof.instance_profiles:
    text_file1.write(p['instance_profile_name'])

text_file2 = open("region_names.txt", "w")
reg = boto.iam.regions()
for re in reg:
    text_file2.write(re.name)

text_file3 = open("all_instances.txt", "w")
text_file4 = open("all_instances_profiles.txt", "w")
for e in reg:
    ec2con = ec2.connection.EC2Connection(region =ec2.get_region(e.name))
    reservations = ec2con.get_all_instances()
    instances = [j for r in reservations for j in r.instances]
    for inst in instances:
        text_file3.write("%s \n" % inst.id)
        if inst.instance_profile != None:
	    text_file4.write("%s \n" % inst.instance_profile)
             

text_file1.close()
text_file2.close()
text_file3.close()
text_file4.close()
os.system("awk -F'/' '{print $NF}' all_instances_profiles.txt | rev | cut -c 4- | rev > outputfile1")
with open('outputfile') as fin:
    lines = (line.rstrip() for line in fin)
    unique_lines = OrderedDict.fromkeys( (line for line in lines if line) )

text_file5 = open("uniquefiles.txt", "w")
for u in unique_lines:
    text_file5.write("%s \n" % u)


text_file5.close()
with open('profile_names.txt', 'r') as file1:
    with open('uniquefiles.txt', 'r') as file2:
        diffe=set(file1).difference(file2)

diffe.discard('\n')
with open('unused_iam_instance_profiles.txt', 'w') as file_out:
    for line in diffe:
        file_out.write(line)



