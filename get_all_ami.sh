#!/bin/bash

all_ami = aws ec3 describe-images --filter Name=owner,Value='My AWM'