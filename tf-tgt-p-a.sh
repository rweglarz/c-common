#!/usr/bin/env bash

set -e

terraform plan $(egrep -h 'resource .*((panorama|panos)_(device_group|template_stack)|random_id)' *.tf | tr -d \" | awk '{ print "-target=" $2 "." $3}' ) -out p1 
terraform apply p1
