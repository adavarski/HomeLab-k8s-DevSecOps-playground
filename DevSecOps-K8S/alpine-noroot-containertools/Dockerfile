FROM alpine:3.14

RUN apk --update add python3 py3-netifaces py3-prettytable py3-certifi \
py3-chardet py3-future py3-idna py3-netaddr py3-parsing py3-six\
 nmap nmap-scripts curl tcpdump bind-tools jq nmap-ncat bash && \
rm -rf /var/cache/apk/*

#Kubernetes 1.12 for old clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.12.8/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl112

#Kubernetes 1.16 for medium old clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.16.7/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl116

#Kubernetes 1.21 for new clusters
RUN curl -O https://storage.googleapis.com/kubernetes-release/release/v1.21.5/bin/linux/amd64/kubectl && \
chmod +x kubectl && mv kubectl /usr/local/bin/kubectl

#Get docker we're not using the apk as it includes the server binaries that we don't need
RUN curl -OL https://download.docker.com/linux/static/stable/x86_64/docker-20.10.9.tgz && tar -xzvf docker-20.10.9.tgz && \
cp docker/docker /usr/local/bin && chmod +x /usr/local/bin/docker && rm -rf docker/ && rm -f docker-20.10.9.tgz

#Get etcdctl
RUN curl -OL https://github.com/etcd-io/etcd/releases/download/v3.3.13/etcd-v3.3.13-linux-amd64.tar.gz && \
tar -xzvf etcd-v3.3.13-linux-amd64.tar.gz && cp etcd-v3.3.13-linux-amd64/etcdctl /usr/local/bin && \
chmod +x /usr/local/bin/etcdctl && rm -rf etcd-v3.3.13-linux-amd64 && rm -f etcd-v3.3.13-linux-amd64.tar.gz

#Get AmIcontained
RUN curl -OL https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64 && \
mv amicontained-linux-amd64 /usr/local/bin/amicontained && chmod +x /usr/local/bin/amicontained

#Get botb
RUN curl -OL https://github.com/brompwnie/botb/releases/download/1.8.0/botb-linux-amd64 && \
mv botb-linux-amd64 /usr/local/bin/botb && chmod +x /usr/local/bin/botb

#Get Reg
RUN curl -OL https://github.com/genuinetools/reg/releases/download/v0.16.1/reg-linux-amd64 && \
mv reg-linux-amd64 /usr/local/bin/reg && chmod +x /usr/local/bin/reg

#Get Rakkess
RUN curl -LO https://github.com/corneliusweig/rakkess/releases/download/v0.4.4/rakkess-amd64-linux.tar.gz && \
 tar -xzvf rakkess-amd64-linux.tar.gz && chmod +x rakkess-amd64-linux && mv rakkess-amd64-linux /usr/local/bin/rakkess

#Get kubectl-who-can
RUN curl -OL https://github.com/aquasecurity/kubectl-who-can/releases/download/v0.1.0/kubectl-who-can_linux_x86_64.tar.gz && \
tar -xzvf kubectl-who-can_linux_x86_64.tar.gz && cp kubectl-who-can /usr/local/bin && rm -f kubectl-who-can_linux_x86_64.tar.gz

#Get Helm3
RUN curl -OL https://get.helm.sh/helm-v3.7.0-linux-amd64.tar.gz && \
tar -xzvf helm-v3.7.0-linux-amd64.tar.gz && mv linux-amd64/helm /usr/local/bin/helm && \
chmod +x /usr/local/bin/helm && rm -rf linux-amd64 && rm -f helm-v3.7.0-linux-amd64.tar.gz

#Get Go-Pillage-Registries

RUN curl -OL https://github.com/nccgroup/go-pillage-registries/releases/download/v1.0/go-pillage-registries_1.0_Linux_x86_64.tar.gz && \
tar -xzvf go-pillage-registries_1.0_Linux_x86_64.tar.gz && mv go-pillage-registries /usr/local/bin && \
rm -f go-pillage-registries_1.0_Linux_x86_64.tar.gz

#Get oc
RUN curl -OL https://github.com/openshift/origin/releases/download/v3.10.0/openshift-origin-client-tools-v3.10.0-dd10d17-linux-64bit.tar.gz && \
tar -xzvf openshift-origin-client-tools-v3.10.0-dd10d17-linux-64bit.tar.gz && cp openshift-origin-client-tools-v3.10.0-dd10d17-linux-64bit/oc /usr/local/bin && \
chmod +x /usr/local/bin/oc && rm -rf openshift-origin-client-tools-v3.10.0-dd10d17-linux-64bit.tar.gz && rm -f openshift-origin-client-tools-v3.10.0-dd10d17-linux-64bit.tar.gz

#Get rbac-tool
RUN curl -OL https://github.com/alcideio/rbac-tool/releases/download/v1.4.0/rbac-tool_v1.4.0_linux_amd64.tar.gz && \
tar -xzvf rbac-tool_v1.4.0_linux_amd64.tar.gz && mv rbac-tool /usr/local/bin && chmod +x /usr/local/bin/rbac-tool && \
rm -f rbac-tool_v1.4.0_linux_amd64.tar.gz LICENSE README.md

#Get kdigger
RUN curl -OL https://github.com/quarkslab/kdigger/releases/download/v1.0.0/kdigger-linux-amd64 && \
mv kdigger-linux-amd64 /usr/local/bin/kdigger && chmod +x /usr/local/bin/kdigger

COPY /bin/conmachi /usr/local/bin/

#Having a setuid shell could be handy
RUN cp /bin/bash /bin/setuidbash && chmod 4755 /bin/setuidbash

#Create a group for our user
RUN addgroup -g 1001 -S tester

#create our new user
RUN adduser -S --ingroup tester --uid 1001 tester

#set the workdir, why not
WORKDIR /home/tester

USER tester

#Put a Sample Privileged Pod Chart in the Image
RUN mkdir charts
COPY --chown=tester /charts/* /home/tester/charts/


RUN mkdir manifests
COPY --chown=tester /manifests/* /home/tester/manifests/


# This is a Dumb Hack
CMD ["tail", "-f" , "/dev/null"]


