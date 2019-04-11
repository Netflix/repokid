# Environmental Variables
PACKAGES=aws

# check_host_system_installs:
# Runs `which` against program targets to ensure that the users development
# environment contains all the necessary packages.
#
# Environmental Variables:
# 	PACKAGES: A space separated list of packages required in the users
# 			  environment.
check_host_system_installs:
	for package in $(PACKAGES); do \
		which $$package ; \
	done

# check_aws_region:
# Retrieves the default AWS region present in your environment.
check_aws_region:
	aws configure get default.region
