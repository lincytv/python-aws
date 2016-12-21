#!/bin/bash
GREEN='\033[0;32m' #Green color
NC='\033[0m' #  No Color
BLUE='\033[0;34m' #Blue color
SOURCE_REGION=us-east-1 #The region where AMI is present
PROFILE_NAME=default #AWS profile name, default value is default
AMI_NAMES=IE08TestNowWnRmV04,IE10TestNowWnRmV03,IE11TestNowWnRmV04,IE9TestNowWnRmV03,SecurityTestNowV1,TestNowInfraImage,TestNowV15_with_awscli_simplehar #Provide the AMI names as comma separted values
aws_regions=($(aws ec2 describe-regions --filters "Name=region-name,Values=*" | jq '.Regions[] .RegionName' | sed 's/\"//g'))
existing_ami_name=($(aws ec2 describe-images --profile $PROFILE_NAME --filter "Name=name,Values=$AMI_NAMES" --region $SOURCE_REGION | jq '.Images[] .Name' | sed 's/\"//g'))
existing_ami_id=($(aws ec2 describe-images --profile $PROFILE_NAME --filter "Name=name,Values=$AMI_NAMES" --region $SOURCE_REGION | jq '.Images[] .ImageId' | sed 's/\"//g'))
for region in ${aws_regions[@]}
do
	echo -e "The region is ${BLUE}$region${NC}"
	i=0;
	for ami in ${existing_ami_name[@]}
	do
		if [ $ami == "$(aws ec2 describe-images --profile $PROFILE_NAME --filter "Name=name,Values=$ami" --region $region | jq '.Images[] .Name' | sed 's/\"//g')" ]; then
			copied_ami_id=$(aws ec2 describe-images --profile $PROFILE_NAME --filter "Name=name,Values=$ami" --region $region | jq '.Images[] .ImageId' | sed 's/\"//g')
			echo -e "AMI $ami, with id ${GREEN}${copied_ami_id}${NC} is already present in the region."
		else
			echo "AMI $ami not present in $region. Copying AMI $ami to $region"
			#new_ami_id=$(aws ec2 copy-image --source-image-id ${existing_ami_id[$i]} --source-region $SOURCE_REGION --region $region --profile $PROFILE_NAME --name $ami | jq '.ImageId' | sed 's/\"//g')
			#echo -e "New ami id is ${GREEN}$new_ami_id${NC}"
		fi
		((i=$i+1))
	done
done