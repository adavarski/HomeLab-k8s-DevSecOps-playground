FROM ubuntu:18.04


LABEL maintainer="Rory McCune <rorym@mccune.org.uk>"



RUN apt update && apt install -y openssh-server dnsutils nmap curl tcpdump jq git python3-pip build-essential && \
sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ /etc/ssh/sshd_config  

#Get kubectl modify the version for later ones, and damn but this is a big binary! this is 16 for older clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.6.12/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl16

#Kubernetes 1.8 for medium old clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.8.4/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl18

#Kubernetes 1.12 for more modern clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.12.8/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl

#Get docker we're not using the apk as it includes the server binaries that we don't need
RUN curl -OL https://download.docker.com/linux/static/stable/x86_64/docker-18.09.6.tgz && tar -xzvf docker-18.09.6.tgz && \
cp docker/docker /usr/local/bin && chmod +x /usr/local/bin/docker && rm -rf docker/ && rm -f docker-18.09.6.tgz

#Get etcdctl
RUN curl -OL https://github.com/etcd-io/etcd/releases/download/v3.3.13/etcd-v3.3.13-linux-amd64.tar.gz && \
tar -xzvf etcd-v3.3.13-linux-amd64.tar.gz && cp etcd-v3.3.13-linux-amd64/etcdctl /usr/local/bin && \
chmod +x /usr/local/bin/etcdctl && rm -rf etcd-v3.3.13-linux-amd64 && rm -f etcd-v3.3.13-linux-amd64.tar.gz

#Get Boltbrowser
RUN curl -OL https://bullercodeworks.com/downloads/boltbrowser/boltbrowser.linux64 && \
mv boltbrowser.linux64 /usr/local/bin/boltbrowser && chmod +x /usr/local/bin/boltbrowser

#Get AmIcontained
RUN curl -OL https://github.com/genuinetools/amicontained/releases/download/v0.4.7/amicontained-linux-amd64 && \
mv amicontained-linux-amd64 /usr/local/bin/amicontained && chmod +x /usr/local/bin/amicontained

#Get Rakkess
RUN curl -Lo rakkess.gz https://github.com/corneliusweig/rakkess/releases/download/v0.4.0/rakkess-linux-amd64.gz && \
  gunzip rakkess.gz && chmod +x rakkess && mv rakkess /usr/local/bin/

#Get Helm
RUN curl -OL https://storage.googleapis.com/kubernetes-helm/helm-v2.13.1-linux-amd64.tar.gz && \
tar -xzvf helm-v2.13.1-linux-amd64.tar.gz && mv linux-amd64/helm /usr/local/bin/helm && \
chmod +x /usr/local/bin/helm && rm -rf linux-amd64 && rm -f helm-v2.13.1-linux-amd64.tar.gz

#Initialize Helm
RUN helm init --client-only

#Put a Sample Privileged Pod Chart in the Image
RUN mkdir /charts
COPY privchart-0.1.0.tgz /charts/

#Get Kube-hunter
RUN git clone https://github.com/aquasecurity/kube-hunter.git
RUN cd /kube-hunter/ && pip3 install -r requirements.txt


COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

#We can run this but lets let it be overridden with a CMD 
CMD ["/entrypoint.sh"]
