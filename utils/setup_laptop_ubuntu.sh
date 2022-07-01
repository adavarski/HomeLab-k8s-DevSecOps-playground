#!/bin/bash

set -eux

# install dependencies.
sudo apt-get update
sudo apt-get install -y ca-certificates curl apt-transport-https lsb-release gnupg

#Install docker
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
sudo apt update
sudo apt-cache policy docker-ce
sudo apt install -y docker-ce
sudo usermod -aG docker jenkins
sudo usermod -aG docker ubuntu
sudo systemctl enable docker
sudo systemctl start docker


### Install Terraform
TERRAFORM_VERSION="v1.0.5"

curl -Os https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip \
&& curl -Os https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS \
&& curl https://keybase.io/hashicorp/pgp_keys.asc | gpg --import \
&& curl -Os https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS.sig \
&& gpg --verify terraform_${TERRAFORM_VERSION}_SHA256SUMS.sig terraform_${TERRAFORM_VERSION}_SHA256SUMS \
&& shasum -a 256 -c terraform_${TERRAFORM_VERSION}_SHA256SUMS 2>&1 | grep "${TERRAFORM_VERSION}_linux_amd64.zip:\sOK" \
&& unzip -o terraform_${TERRAFORM_VERSION}_linux_amd64.zip -d /usr/local/bin

### Install Ansible
sudo apt-get update
sudo apt-get install software-properties-common
sudo apt-add-repository --yes --update ppa:ansible/ansible
sudo apt-get install ansible

### Install Packer
PACKER_VERSION="1.4.3" #Update with your desired version

curl -Os https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip \
&& curl -Os https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_SHA256SUMS \
&& curl https://keybase.io/hashicorp/pgp_keys.asc | gpg --import \
&& curl -Os https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_SHA256SUMS.sig \
&& gpg --verify packer_${PACKER_VERSION}_SHA256SUMS.sig packer_${PACKER_VERSION}_SHA256SUMS \
&& shasum -a 256 -c packer_${PACKER_VERSION}_SHA256SUMS 2>&1 | grep "${PACKER_VERSION}_linux_amd64.zip:\sOK" \
&& unzip -o packer_${PACKER_VERSION}_linux_amd64.zip -d /usr/local/bin

# install kubectl, the same version of on-prem k8s
KUBECTL_VERSION="v1.24.0" #Update with your desired version

wget https://dl.k8s.io/${KUBECTL_VERSION}/kubernetes-client-linux-amd64.tar.gz
tar -zxvf kubernetes-client-linux-amd64.tar.gz && sudo cp ./kubernetes/client/bin/kubectl /usr/local/bin && rm -rf ./kubernetes

### Install Vault 
VAULT_VERSION="1.2.1"
curl --silent --remote-name https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
unzip vault_${VAULT_VERSION}_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Install jenkins
sudo apt update
sudo apt install -y openjdk-11-jre-headless
wget -q -O - https://pkg.jenkins.io/debian/jenkins.io.key | sudo apt-key add -
sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
sudo apt update
sudo apt install -y jenkins
sudo systemctl enable jenkins
sudo systemctl start jenkins

#Install pkgs for (for J.docker pipeline plugin)
sudo apt install -y gnupg2 pass

# Install awscli

# install azure-cli.

# Install Cloud SDK (gcloud, gsutil, bq, etc.)

# Install Helm3


