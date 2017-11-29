#!/bin/sh

#First run:
#Create system user with no login shell for running executable. 
#useradd -r -s /bin/false liusystem

echo "Building and installing client-cert-auth to $GOPATH/bin/"
go install
echo "Setting capabilities for Go executable"
sudo setcap 'cap_net_bind_service=+ep' $GOPATH/bin/client-cert-auth
echo "Setting REDIS_URL envvar and running client-cert-auth"
sudo -u liusystem /bin/sh -c ". ./setEnvVar.sh && $GOPATH/bin/client-cert-auth"
