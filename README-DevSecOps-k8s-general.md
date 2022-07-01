 
## Summary: Cloud-Native & Kubernetes Security

- Cloud-Native Security: AWS/Azure/GCP/etc.: Security Policies; Security Frameworks&Standards compliance; Clouds Shared Responsibility Models (for IaaS/CaaS/
PaaS/FaaS/SaaS); Cloud Zero-Trust (PoLP) security model implementation: IAM/RBAC; Infrastructure/Network Protection and (micro)segmentation for fine-grined
access control (VPC/Subnets/Routing Tables/Firewall rules/NAT/Load Balancers/Application Gateways/WAF, VPC peering, VPC endpoints, Hub-Spoke network
topologies, VPN gateways); Data Protection(Data at Rest & Data in Transit: Data access control, KMS/Vault, Data Encryption, TLS/SSL, etc.); Security Observability:
Monitoring(Metrics)/Logs/Traces and Incident Response. DevSecOps pipelines: automated enforcement of RBAC/Security Policies for cloud infrastructure via IaC:
(terraform/etc + SCA for IaC) and CM(ansible/etc.). Deploy applications by creating complete end-to-end DevSecOps-like integration chains/pipelines(VCS secrets check/
SCA/SAST/DAST/System security audit/WAF&OWASP/etc.) & Cloud Security Automation (including cloud event-driven security and remediation).
 
- Kubernetes Security: k8s RBAC(API server), Managed-k8s(EKS/AKS/GKE) and Cloud IAM/RBAC
integration, k8s Clusters Security Audit (KubeBench, Kube-hunter, Kubestriker, Kubesec, etc.), Containers Security Scanners (Clair, Anchor, Trivy, etc.), Resource
Limits&Quotas, Network policies and CNI extensions, Workloads hardering (Containers Security Context/PSP/OPA/etc.), etc.
 
 
### DevSecOps & k8s/micsoservcies/docker images (on-prem/cloud) principles/tools : IaC/CI_CD pipelines/Continiuous Observe(Logs/Metrics(Monitoring)/Trace(services:mesh, etc.)  

```
Implement Sec tools into CI/CD pipelines for infrastructure (IaC: chechov ) and applications(SCA/SAST/DAST/WAF/Container Images Scaning) based on security model/policies/complience(PCI DSS). Every peace of code/commit (IaC) has to be threated as software and we have to use the same CI/CD metodology as application code. If we made a change in git repo for terraform module/ansible code we have to run some tools for IaC(infrastructure security:host/network/storage) implemented into CI/CD pipeline (CI: check for credetials leaks into VCS/linting/SAST(chechov)/kube bench/kubehunter/etc.). For application security every commit to git has to be CI/CD pipelined for SCA/SAST/DAST/Dependancy Checks/etc.

We have two vectors for CI/CD pipelines : 1.Infrastucture security:IaC + CM + k8s auditing and 2.Application Security (SAST/DAST/etc.) and we can have 1 pipeline for everything or 2 different pipelines.

- 1.OPS (Infrastructure provisioning)  - > IaC (terraform with secure infrastructure modules (VPC/subnets/firewall rules/NSG/ASG/WAF/LB) + CI/CD DevSecOps pipelines for Infrastructure( https://github.com/bridgecrewio/checkov for Terraform plans, k8s bench security) + Ansible playbooks (k8s nodes:RBAC check and VMs/hosts hardering/checks: sec policy and PCI DSS complience) + Secrets management (check leaked/harkoded credntials/passwords/API keys/Cloud IAM keys/certificates in IaC:source code(git) ... we have to use Vault for user credentials/API keys(JWT,etc.)/certificates (hashicorp/ansible/Azure/AWS Secret Manager/Google Secrets Manager for IaC repos:git) + Immutable AMIs (not changed, build with packer + ansible hardering playbooks:no ssh passowrd login, only keys; kernel sec tunnables)
- 2.DEV (Applications + DBs) ---> CI/CD DevSecOps pipelines for : SCM secret leaks check in apps git (password/token/keys/secrets/certificates) + Secrets management (Vault (hashicorp/ansible/Azure/AWS Secret Manager/Google Secrets Manager) for Apps + SCA + SAST + DAST + WAF(OWASP) + Container sec scanning/audit (Chair/etc.) 
- 3.Observe(Sec Dashboards(monitoring:metrics & infrastructure & app logs): Grafana/Kibana/etc. Trace: Istio mesh/Consul mesh/App Dynamics)

Example: https://github.com/adavarski/DevSecOps-full-integration-chain

Checkout project - check out python application project repository with XSS vulnerability (https://github.com/adavarski/Python-app-DevSecOps-XSS)
- git secret check - check there is no password/token/keys/secrets accidently commited to project github (trufflehog)
- SCA - check external dependencies/libraries used by the project have no known vulnerabilities (safety)
- SAST - static analysis of the application source code for exploits, bugs, vulnerabilites (Bandit)
- Container audit - audit the container that is used to deploy the python application (Lynis)
- DAST - deploy the application, register, login, attack & analyse it from the frontend as authenticated user (Nikto + Selenium + python custom script for DAST automation)
- System security audit - analyse at the security posture of the system hosting the application (Lynis)
- WAF - deploy application with WAF which will filter malicious requests according to OWASP core ruleset (owasp/modsecurity-crs)

```

### DevSecOps Metodology and tools (DevSecOps with Docker&K8s): 

```
These are the practices/metodologies of how DevSecOps is implemented:
- Review infrastructure-related security policies prior to deployment(IaC and IaC & CD/CD: Zero trust)
- Integrate security tools in the development integration process (App Sec CI/CD: Zero trust)
- Prioritize security requirements as part of the product’s backlog (DevOps & Security team)  
- Collaborate with the security and development teams on the threat model (DevOps & App leads & Architects)

Here are some of the benefits of implementing DevSecOps:
- Early identification of potential vulnerabilities in the code is encouraged.
- Greater speed and agility in applying security in all phases of development.
- Throughout the development process, tools and mechanisms are provided to quickly and efficiently respond to changes and new requirements.
- Better collaboration and communication between teams involved in development, as in DevOps.

In this way, tasks related to application security can be subject to
automation and monitoring mechanisms if security elements are
integrated from the early stages of development.

Security testing (via CI/CD pipelines) is often called intrusion testing or penetration. This
testing can be carried out in two modes: white box or black box.
It is aimed at breaking the security measures of a system.
- White box testing allows static checking the internal functioning of
the applications, and having all the necessary knowledge through
source code and architecture. (SAST)
- Black box testing focuses on examining the functionality of the
application without the knowledge of its internal structure using
dynamic The test cases of this approach focus on exploiting the
interaction with the application from the outside (APIs, databases,
files, protocols, input data, and so on) to break the application’s
security measures.(DAST)

Tip: Security testing with GitLab (need license and implemented by default)
- Static (SAST)
- Dynamic (DAST)
- Dependency (OWASP dependancy check)
- Container (Clair)

CI/CD tools (some are beter Sec integrated): Jenkins/Bamboo/TeamCity/CircleCI/TravisCI/CruisControl/Codeship

DevSecOps tools:

- Static Analysis Security Testing (SAST:OWASP top 10 compliance - SQL injection and Cross-site scripting,etc: Bandit(python), GitLab SAST, GitGuardian , SonarQube)
- Dynamic Analysis Security Testing (DAST:OWASP ZAP (Zed Proxy Attack - ZAP), Gauntlt, Nikto, Arachni Scanner)
- Dependency analysis (OWASP Dependency-Check, NPM check)
- Infrastructure as code security (IAST: Note: docker images, k8s manifests/Helm charts are IaC: Clair,  Anchore Engine, Open-Scap, Trivy, Dagda, etc)
- Secrets management (Gitleaks, trufflehog, GitRob ... Hashicorp Vault, AWS Secrets Manager, AWS System Manager, GCP Secret Manager, Azure Key Vault, etc.)
- Vulnerability management (ArcherySec, JackHammer, etc.)
- Vulnerability assessment (OpenVAS, Docker Bench)
- Alerts and monitoring (ModSecurity WAF - https://github.com/SpiderLabs/ModSecurity)

Notes: Trivy, Anchore, Clair 

$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
-v $HOME/Library/Caches:/root/.cache/ aquasec/trivy nginx:latest
$ curl https://engine.anchore.io/docs/quickstart/docker-compose.yaml \
> docker-compose.yaml
$ docker-compose exec api anchore-cli system status
$ docker-compose exec api anchore-cli image add \
docker.io/library/nginx:latest
$ docker-compose exec api anchore-cli image vuln \
docker.io/library/nginx:latest all
Clair & Docker Registry: Harbor ( goharbor.io ) integration
$ docker login -u admin -p Harbor12345 123.123.123.123
Login Succeeded.
$ docker pull nginx:latest
$ docker tag nginx:latest \
123.123.123.123/cloudnativesecurity/nginx:latest
$ docker push 123.123.123.123/cloudnativesecurity/nginx:latest
After a few minutes, depending on your bandwidth, the pushed image should
be available in our full-featured registry. Clearly, we need to avoid using the
admin user and change its default password as soon as possible. Still under
Projects on the left, if we enter the cloudnativesecurity repository and to
see Clair in action, click the nginx image and then Scan, we can see the result

Notes: OWASP ZAP 

$ docker run -t owasp/zap2docker-weekly zap-baseline.py \
-t https://chrisbinnie.tld
$ docker run --user $(id -u):$(id -g) -v $(pwd):/zap/wrk/:rw—rm \
-t owasp/zap2docker-stable zap-baseline.py \
-t https://chrisbinnie.tld -g gen.conf -r report.html

Notes: Gauntlt (xss attack;curl attack;etc.)
A key piece of terminology used by Gauntlt is that its tools are described as
attack adapters. The website lists adapters for the following attack tools (among
others, which we will look at a little later) as available for you to script rulesets
around:
- curl
- nmap
- sslyze ( github.com/iSECPartners/sslyze )
- sqlmap ( sqlmap.org )
- Garmr ( github.com/mozilla/Garmr )
$ git clone https://github.com/gauntlt/gauntlt-docker.git
$ docker run --rm -it --entrypoint /bin/bash gauntlt
root@d469b6590ba7:/opt# ls
arachni-1.5.1–0.5.12-linux-x86_64.tar.gz dirb222
dirb222.tar.gz nikto sqlmap
$ docker run --rm -it -v /root/attacks:/root/attacks —entrypoint gauntlt gauntlt /root/attacks/nmap-simple.attack

Note: GitLeaks & GitRob
$ docker run zricethezav/gitleaks \
--repourl=https://github.com/chrisbinnie/CloudNativeSecurity --redact
$ export GITROB_ACCESS_TOKEN=9e3b27d7c382XXXXXXXXXXXXX96b1a45ea351c24
$ ./gitrob chrisbinnie

Note: Nikto 
$ ./nikto.pl -h http://127.0.0.1
$ docker run --rm sullo/nikto -h http://localhost
$ docker run --rm sullo/nikto -h https://remotehost-2.tld

Points to remember:
- DevSecOps is a philosophy that integrates the DevOps security
process, generating a natural response to the bottlenecks that
originate in the traditional security patterns that exist in
continuous delivery developments. This philosophy focuses on the
cooperation between development, operations, and security. It
seeks to integrate the work of all teams in each part of the
process, creating a synchronized and automated progress in
activities.
- Security testing is usually the most widespread security measure
and involves carrying out specific security tests in addition to
software quality assurance tests (unit, integration, functional,
performance, and so on).

Note: IAST - Security It is a combination of static and dynamic analysis
techniques (SAST + DAST) generating a global analysis of theentire system


```

### k8s Security (DevSecOps with D&K8s & Cloud Native Security) 

```
Note: Local cluster development environment for DevSecOps

- K3s : It runs on any Linux distribution without any additional
external dependencies. K3s replace Docker with containerd as
container runtime and uses sqlite3 as default database. It is light,
with a consumption of 512MB of RAM and 200MB of disk space.

- Kind (Kubernetes-in-Docker) https://kind.sigs.k8s.io : It runs
Kubernetes clusters in Docker containers. It supports multi-node
clusters as well as HA Clusters (High-Availability). Kind can run
on Windows, Mac, and Linux operating systems because it runs
on top of Docker. It is a new project that aims to bring dockerized K3s. 
We can use this to build cluster on local dev environment. 
Also suport differnt CNI:Calico, etc., so we can test Network policies locally.

- Minikube - not recomended (not production-like)


1.Security features built into k8s

Kubernetes offers native security features to protect against some
of the threats described earlier or at least mitigate the potential
impact of a breach. The main safety features include:

- Role-Based Access Control (API Server securing)->  Kubernetes allows administrators to
define what are called Roles and ClusterRoles that specify which
users can access which resources within a namespace or an entire
cluster. This way, RBAC provides a way to regulate access to
resources.

- Pod security policies(PSP) and Network policies(we has to have some supported CNI:Calico, etc. for Network Policies to work)  -> Administrators 
can configure pod security policies and network policies, which place restrictions
on how containers and pods can behave. For example, pod
security policies can be used to prevent containers from running
as root users, and network policies can restrict communication
between pods.

- Network Kubernetes uses TLS encryption by default, which
provides additional protection for encryption of network traffic.

- Limits/Quotas (DoS protection, etc).

2.k8s infrastructure security. k8s security is dependent of (cloud) Infrastucture security.
Security in Kubernetes must extend beyond images and workloads and k8s itself
and protect the entire environment, including the cluster
infrastructure (VPC, VMs, networking, firewalls, etc). k8s out of the box sec (k8s is dependent of conteiners, conteiner-runtime, host and network security so we have to create infrastructure CI/CD pipelines for checking IaC: Containers Images, Containers Runtime, Host Security, Network security). Security in Kubernetes must extend beyond images and workloads
and protect the entire environment, including the cluster
infrastructure.

These built-in Kubernetes security features provide layers of
defense against certain types of attacks, but they do not cover all
threats. Kubernetes does !not offer native protections against the
following types of attacks!:

- Malicious code or incorrect settings inside containers or container
A third-party container scanning tool must be used to scan them (Container/Pod security-> Clair, Anchor)

- Security vulnerabilities in host operating (Host Security:Lynis, Lunar ...Note: Using Indepotent AMIs(not changable: there is no package manager: RPM/DEB, but only kernel i container runtime + kubelet, and we build AMIs via packer and ansible roles for security: no SSH login with passwords but only with keys, kernel tunables: line='net.ipv4.tcp_syncookies = 1' state=present, etc. )
Again, these need to be searched with other tools. Some Kubernetes distributions like
OpenShift integrate security solutions like SELinux at the kernel
level to provide more security at the host level, but this is not a
feature of Kubernetes itself.

- Container runtime 
In this case, Kubernetes has no way of alerting
if a vulnerability exists within its runtime or if an attacker is trying
to exploit a vulnerability at the time of execution.(Containerd, CRI-O, Docker)

- Kubernetes API Kubernetes does nothing to detect or respond to
API abuse beyond following any RBAC and security policy settings
that you define.(Private k8s clusters, Privite k8s API server access, Kubernetes External Attacks: API Server, ETCD, Kubelet)

- Management tools vulnerabilities or configuration Kubernetes
cannot guarantee that management tools like Kubectl are free
from security issues.

Here is a summary of the key parts of a Kubernetes environment (infrastructure security:IaC):
and the most common security risks that affect them:

- Containers: can contain malicious code that was included in your
container images. They can also be subject to misconfigurations
that allow attackers to gain unauthorized access under certain
conditions.

- Host: operating Vulnerabilities or malicious code within operating
systems installed on Kubernetes nodes can provide attackers with
a path to Kubernetes clusters.

- Container runtime: Kubernetes supports a variety of container runtimes. All
of them can contain vulnerabilities that allow attackers to take
control of individual containers, escalate attacks from container to
container, and even gain control of the Kubernetes environment.

- Network: Kubernetes relies on internal networks to facilitate
communication between nodes, pods, and containers. It also often
exposes applications to public networks so that they can be
accessed over the Internet. Both network layers can allow attackers
to gain access to the cluster or escalate attacks from one part of
the cluster to others.

- Kubectl Dashboard and other management They may be subject to
vulnerabilities that allow abuse in a Kubernetes cluster.


3.Kubernetes security best practices

- Use the minimum privilege principle for your service accounts (Zero-Trust model: principle of minimum privilege)
- Using secrets (for passwors, tokens, certificates -> Vault, not in VCS:git)
- Restrict the Docker pull command (Configure k8s to only needed docker registry with some authentification: token -> GitLab)
- Firewall ports (better have private clusters, and only privite access to k8s API server and use LB and AG for externel access with WAF/OWASP incorporated for LB/AG external access) and k8s Networ policies (iptables rules on VMs for kune-proxy or Calico/Culium network policy engine) 
- Create a cluster network policy
- Role Based Access Control (RBAC for API servers access): API authorization and anonymous authentication(disable)
- Management of resources and limits (DoS:CPU/Mem/Net/ and I/O) and Applying affinity rules between nodes and pods
- Disable Kubernetes dashboard


4.Analyzing Kubernetes components security (k8s auditing: only k8s, not infrastructure) / Auditing and Analyzing Vulnerabilities in Kubernetes

- CIS benchmarks for Kubernetes with KubeBench -> Kube Bench (based on CIS Kubernetes Benchmark guide), https://github.com/aquasecurity/kube-bench
that allow us to quickly check our infrastructure at the security
level. KubeBench is a Kubernetes security scanner that allows us to
eliminate about 95% of configuration defects, generating specific
guidelines to ensure the configuration of your computer network
through the application of Kubernetes benchmark. KubeBench is a tool that performs an in-depth analysis of your
Kubernetes environment. The tool integrates more than 100
security tests and parameters, so you get a clear picture of how
safe your environment is at the end of the process. KubeBench is an application developed in Golang that checks if
Kubernetes is implemented securely by executing controls
documented in CIS Kubernetes Benchmark.

$ docker run --rm -v `pwd`:/host aquasec/kube-bench:latest install
$ ./kube-bench master
$ ./kube-bench node

- Kube-hunter -> Kube-hunter is a Python script developed by Aqua Security that
allows you to analyze the potential vulnerabilities in a Kubernetes
Cluster.It allows remote, internal, or CIDR scanning over a Kubernetes
cluster and incorporates an active option through which it tries to
exploit the findings. It can be run locally or through the
deployment of a container that is already prepared.Kube-hunter offers a list of tests that are run both actively and
passively and allow us to identify most of the vulnerabilities that
we can find in a Kubernetes cluster.

$ git clone https://github.com/aquasecurity/kube-hunter.git$ cd ./kube-hunter && pip install -r requirements.txt
$ ./kube-hunter.py
$ docker run –rm aquasec/kube-hunter –cidr 192.168.0.0/24
$ docker run -it --rm --network host aquasec/kube-hunter
$ docker run -it --rm --network host aquasec/kube-hunter --list
$ docker run -it --rm --network host aquasec/kube-hunter—list—active
$ kubectl create -f job.yaml
job.batch/kube-hunter created
$ kubectl logs kube-hunter-r4z4k

- Kubestriker -> Kubestriker is a platform-agnostic tool designed to tackle
Kubernetes cluster security issues due to misconfigurations and
helps strengthen the overall IT infrastructure of any organization.
$ docker run -it --rm -v /Users//.kube/config:/root/.kube/config -v
“$(pwd)”:/kubestriker --name kubestriker
cloudsecguy/kubestriker:v1.0.0
$ python -m kubestriker (Kubestriker execution for Scanning for IAM
Misconfigurations section, etc.) 

- Auditing the state of the cluster with Polaris ->  You may have to perform a small internal audit of the state of
the cluster when you work with Kubernetes clusters.

- Kubesec -> This tool allows you to analyze the security risk for Kubernetes
resources. Kubesec is an open source security risk analysis tool for
Kubernetes resources. Validate the configuration and manifest files
used for Kubernetes cluster operations and deployment, and you
can install it on your system using its container image, its binary
package, or a kubectl plugin.

- Kubeaudit -> is a command line tool and a Go package to audit
Kubernetes clusters for various security concerns. It allows us to
find security misconfigurations in Kubernetes resources and gives
tips on how to resolve these issues.

- Audit2rbac takes a Kubernetes audit log and username as input
and generates RBAC roles and binding objects that cover all the
API requests made by that user. (usable if we don't know what app/microservcie is doing : reverse engineering for microservice RBAC, if developer not know what microservcie doing and how is related to k8s)

- Kubectl plugins for managing Kubernetes (kubectl auth can-i --as=system:serviceaccount:default:default --list; kubectl-trace, kubectl-debug, ksniff(tcpdump), kubectl-dig, Rakkes, kubectl-who-can; kubectl get sa,roles,rolebindings,clusterroles,clusterrolebindings
--all-namespaces -o json | rback | dot -Tpng> /tmp/rback.png && open /tmp/rback.png)

- Static analysis with kube-score (IaC: SAST) -> kube-score is a tool that performs static code analysis of your
Kubernetes object definitions. The output is a list of
recommendations of what you can improve to make your
application more secure and resilient.

- Checkov (IaC: SAST) -> is a tool that allows us to analyze security at the
infrastructure level as code. We can use it to avoid incorrect
configurations in the cloud if we are using solutions like Terraform
or Cloudformation. It is developed in Python and aims to increase
the adoption of security and compliance with best practices.

Note: Create the basic YAML manifest using the --dry-run command-line option:
$ kubectl run nginx --image=nginx --dry-run=client --
restart=Never \
-o yaml > nginx-pod.yaml
Now, edit the file nginx-pod.yaml and bind the PersistentVolumeClaim
to it and Security Context in Manifests



Here are some of the main advantages of using this type of tool:
- Identifies misconfigurations and vulnerabilities in clusters,
containers, and pods
- Provides solutions to correct misconfigurations and eliminate
vulnerabilities
- Provides a real-time view of the status of the cluster
- Gives more confidence to the DevOps team to develop and
deploy the applications in a Kubernetes cluster


```

### k8s Security Summary (Guidelines/Best practises: Core Kubernetes)
```
Container and Pod security: Summary

- If we do not have a focus on security, we allow people to waltz in and invade our
clusters. Security is a series of tradeoffs that are often fraught with hard deci-
sions, but by utilizing simple and basic practices, we can reduce the impact of a
security risk.
- You do not need to implement all of the security precautions yourself. There is
a growing set of tools that track containers and determine what possible security
holes exist.
- The most obvious place to start with Kubernetes security is at the container
level. Container provenance allows you to trace the source of a container to a
trusted point of origin.
- Don’t run your containers as root, especially if your environment uses contain-
ers that are not built by your organization.
- To find common problems with containers that can cause security vulnerabili-
ties, run a linter like hadolint.
- If your application does not need it, don’t install extra software. The more you
have installed, the greater your number of possible vulnerabilities.
- To secure individual Pods, you should disable the automounting of the default
service account token. Alternatively, you can turn off the default service
account automount for all Pods.

Nodes and Kubernetes security: Summary 

Note: Multi-tenancy
To categorize multi-tenancy, look at the level of trust that the tenants have with one
another, and then develop that model. There are three basic buckets or security mod-
els to categorize as multi-tenancy:
- High trust (same company)—Different departments in the same company are run-
ning workloads on the same cluster.
-  Medium to low trust (different companies)—External customers are running appli-
cations on your cluster in different namespaces.
-  Zero trust (data governed by law)—Different applications are running data that is
governed by laws, where allowing access between different data stores can cause
legal action against your company.

Note: Kubernetes tips
Here is a short list of various configurations and setup requirements:
- Have a private API server endpoint, and if you can, do not expose your API
server to the internet.
- Use RBAC (API Server) 
- Use network policies.
- Do not enable username and password authorization on the API server.
- Use specific users when creating Pods, and don’t use the default admin
accounts.
- Rarely allow Pods to run on the host network.
- Use serviceAccountName if the Pod needs to access the API server; otherwise,
set automountServiceAccountToken to false.
- Use resource quotas on namespaces and define limits in all Pods.

Nodes and Kubernetes security : Summary
-  Node security relies on TLS certificates to secure communication between
nodes and the control plane.
-  Using immutable OSs can further harden nodes.
-  Resource limits can prevent resource-level attacks.
-  Use the Pod network, unless you have to use the host network. The host net-
work allows a Pod to talk to the node OS.
-  RBAC is key to securing an API server. It is non-trivial, but necessary.
- The IAM service accounts allow for the proper isolation of Pod permissions.
-  Network policies are key to isolating network traffic. Otherwise, everything can
talk to everything else.280
-  An Open Policy Agent (OPA) allows a user to write security policies and
enforces those policies on a Kubernetes cluster.
-  Kubernetes was not built initially with zero trust multi-tenancy in mind. You’ll
find forms of mult-tenancy, but they come with tradeoffs.
```

### K8s AAA (k8s API Server) and Ingress (Microservcies routing, App gateway) (Kubernetes Bible)

```
- Authentifiacation(X.509/Tokens/OpenID) and Authorization(k8-native RBAC and Cloud RBAC integration (Azure AKS integration with Azure AAD: cloud IAM & RBAC), also webhook example for auth and autz (KeyCloack for example)

Summary
Authentication and authorization in Kubernetes. Provided
an overview of the available authentication methods in Kubernetes and explained how
you can use ServiceAccount tokens for external user authentication. Next, we focused
on RBAC in Kubernetes. You learned how to use Roles, ClusterRoles, RoleBindings,
and ClusterRoleBindings to manage authorization in your cluster. We demonstrated a
practical use case of RBAC for ServiceAccounts by creating a Pod that can list Pods in
the cluster using the Kubernetes API (respecting the principle of least privilege). Finally,
we provided an overview of how easily you can integrate your AKS with AAD for single
sign-on authentication and Azure RBAC for authorization.

- Advanced Traffic Routing with Ingress (Nginx Ingress Controler, Azure API GW ingres controler) - > Note: Beter use AGWs than LB!!!

Summary
Explained advanced traffic routing approaches in Kubernetes
using Ingress objects and Ingress Controllers. At the beginning, we need a brief recap
of Kubernetes Service types. We refreshed our knowledge regarding ClusterIP ,
NodePort , and LoadBalancer Service objects. Based on that, we introduced
Ingress objects and Ingress Controller and explained how they fit into the landscape
of traffic routing in Kubernetes. Now, you know that simple Services are commonly
used when L4 load balancing is required, but if you have HTTP or HTTPS endpoints
in your applications, it is better to use L7 load balancing offered by Ingress and Ingress
Controllers. You learned how to deploy the nginx web server as Ingress Controller and we
tested this on example Deployments. Lastly, we explained how you can approach Ingress
and Ingress Controllers in cloud environments where you have native support for L7 load
balancing outside of the Kubernetes cluster. As a demonstration, we deployed an AKS
cluster with Application Gateway Ingress Controller (AGIC) to handle Ingress objects.
Congratulations! This has been a long journey into the exciting territory of Kubernetes
and container orchestration.
```

### k8s Security Summary (Guidelines) (Cloud Native Security)

```
### Container Tools
etcdctl - useful for connecting to etcd instances
kubectl - useful for connecting to Kubernetes API servers
There's also kubectl112 and kubectl116 for older clusters
docker (client) - useful for connecting to Docker instances
helm3 - useful for deploying charts (see below)
amicontained - https://github.com/genuinetools/amicontained/ - Tool to assess the environment your process is running in, for things like capabilities and seccomp filters that have been applied.
reg - https://github.com/genuinetools/reg
conmachi - https://github.com/nccgroup/conmachi - Similar to amicontained, handy tool for understanding the privileges of a container that you're running in
boltbrowser - https://github.com/br0xen/boltbrowser - This is a tool for viewing BoltDB format databaes (which is used by etcd)
rakkess - https://github.com/corneliusweig/rakkess - Tool for analyzing RBAC permissions
kubectl-who-can - https://github.com/aquasecurity/kubectl-who-can - Tool for analyzing RBAC permissions
kube-hunter - https://github.com/aquasecurity/kube-hunter - Tool for pentesting Kubernetes clusters
rbac-tool - https://github.com/alcideio/rbac-tool - Lots of useful RBAC tools
kdigger - https://github.com/quarkslab/kdigger - Context discovery for containers, produces lots of useful info.

1.Kubernetes Authorization with RBAC

These are the main modes that can be used for user authorization:
- ABAC
Attribute-­based access control (ABAC) is generally a legacy mechanism that
uses JSON files held on the control plane nodes of the cluster to detail user
permissions.
- Webhook
With this authorization mechanism, the cluster defers the decision to an
external service.
- AlwaysAllow
This allows any authenticated user to make any request to the API server.
- AlwaysDeny
This rejects all requests.
- RBAC
This uses Kubernetes role-­based access control (RBAC) objects for authori-
zation decisions.

Of the available options, RBAC is the most commonly deployed and generally
provides the best compatibility with third-­party software used in the cluster.
For that reason, it is the focus of this chapter.

RBAC Overview
Kubernetes RBAC makes use of rights provided to !!!! principals (which can be
groups, users, or service accounts) !!! at either a cluster or namespace level. There
are four object types used as part of this process:
- Role
An object whose rights are defined to be provided in a single specified
namespace
- RoleBinding
An object that links a role or cluster role to a set of principals
- ClusterRole
A set of rights defined to be provided either cluster-­wide or to a specific
namespace
- ClusterRoleBinding
An object that links a cluster role to a set of principals
These objects can be combined in these three ways:
- Role ➪ RoleBinding
This method provides rights in a single namespace.
- ClusterRole ➪ ClusterRoleBinding
This method provides rights at a cluster level.
- ClusterRole ➪ RoleBinding
Perhaps unintuitively, this method provides rights in a single namespace.
Typically it is used to create a template set of rights that can be applied to
individual namespaces, without needing one role per namespace.


Create Pod Is Dangerous
In addition to challenges in providing read-­only access to cluster resources, it’s
important to note that, without additional controls, providing the ability for
a user to create pods presents risks of privilege escalation. This can present a
tricky problem, as allowing developers or application owners in a multitenant
cluster to create and manage their own resources is a fairly common Kubernetes
use case.
Although we’ll cover some of the options for mitigating this risk in Chapter 19,
“Network Hardening,” it’s worth looking at how various rights around pod
creation and management could lead to privilege escalation.
The simplest of these occurs where a user is able to create pods and also exe-
cute commands inside them (using kubectl exec ). In this case, getting root
access to the underlying node is a relatively trivial task. To see for yourself, first
create a pod manifest, as shown bellow.

NodeRoot Pod Manifest:
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
—name: noderootpod
image: busybox
securityContext:
privileged: true
volumeMounts:
—mountPath: /host
name: noderoot
command: [ "/bin/sh", "-­
c", "—" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
—name: noderoot
hostPath:
path: /


With this manifest saved as noderoot.yml , it takes only two commands to
get root on the underlying host, with the only rights needed being create on
pod resources and pod / exec subresources. First run this command:
kubectl create -f noderoot.yml

This will create the pod. Then run the following:

kubectl exec -it noderootpod chroot /host

You should get a root shell on the underlying node. This technique is based
on the article “The Most Pointless Docker Command Ever” from Ian Miell:
zwischenzugs.com/2015/06/24/the-most-pointless-docker-command-ever /
It is a useful demonstration that without additional hardening, it’s relatively
easy to remove the isolation provided by Linux containers and run commands
on the underlying host.

It’s also worth noting that, even without the pod/exec rights needed for this
attack, it’s possible to use techniques such as reverse shells to get access to a
host with just create pod rights.


Auditing RBAC

kubectl auth can-i get pods
yes

kubectl auth can-i get pods --as=system:serviceaccount:kube-system:certificate-controller
no

kubectl auth can-i --as=system:serviceaccount:default:default --list

Rakkess ( github.com/corneliusweig/rakkess ) is a useful tool for getting a
listing of rights available to either your current user or to another user/service
account that you specify when running it.

rakkess --sa kube-system:certificate-controller

kubectl-who-can
This tool, from Aqua Security (github.com/aquasecurity/kubectl-who-can ),
takes a different approach to showing information from a Kubernetes RBAC
system, one that can be useful when reviewing permissions in a cluster. You
can use it to find out which principals have specific rights. It works similarly to
rakkess in that it is available as a static Golang binary that can be downloaded
and executed, and it makes use of the running user’s kubeconfig file to deter-
mine which cluster to run against. When auditing the permissions of a cluster,
it’s a good idea to first check for likely dangerous permissions (for example,
get secrets):

kubectl-who-can get secrets

Rback
Rback ( github.com/team-soteria/rback ) is a useful visualization tool for RBAC
rights. What it does is parse the cluster’s RBAC objects and create a graphical
representation of them, which can be reviewed for unexpected entries. Rback
uses Graphviz to create the image file, so a standard run of the tool looks like this:

kubectl get sa,roles,rolebindings,clusterroles,clusterrolebindings --all-namespaces -o json | rback | dot -Tpng > /tmp/rback.png && open /tmp/rback.png

3.Network Hardening

Container Network Overview

Node IP Addresses
These are the addresses assigned to nodes in the cluster, typically virtual machines
or physical servers. They’ll be either handed out by DHCP servers on the LAN
that the cluster node sits on or statically assigned there. You can see the IP
addresses of your nodes by using the -­o wide option on kubectl get nodes or
by using a custom column to just get that information, as shown bellow.

Getting Node Addresses and Node Name:
kubectl get nodes -­
o custom-­
columns=Address:status.addresses[*].address
Address
192.168.41.100,k8smaster
192.168.41.101,k8sworker1
192.168.41.102,k8sworker2

Pod IP Addresses
These addresses are handed out to individual pods when they’re started. The
network they are part of will usually (but not always) be entirely different from
the network containing the node IP addresses. Assignment of the IP addresses
to pods is governed by the Container Network Interface (CNI) plugin that’s
used by the cluster (such as Calico or Cilium).
It’s worth noting that, usually when connecting to an application running
in a Kubernetes cluster, you would not connect directly to a pod IP address, as
those addresses are as ephemeral as the pods themselves. You would instead
connect to the service addresses, as discussed in the next section. However, pod
addresses can be useful when troubleshooting connectivity issues.
You can see a pod’s IP address by looking at the IP column in the output of
Getting Pod IP Addresses:
kubectl -n kube-system get po -o custom-columns=IP:.status.podIP
IP
10.1.8.31
10.1.16.131
192.168.41.100
192.168.41.100
192.168.41.102
192.168.41.100
192.168.41.101
192.168.41.100

This listing shows an example of a case where a pod’s IP address might
not be on a separate network. We’ve listed the IP addresses of the pods in the
kube-system namespace, and some of the IP addresses returned are the same
as the node IP addresses we saw in the previous section.
This occurs where a pod makes use of host networking, which means that
instead of being given a separate address, a pod is given the address of the
node to which it is assigned.

Service IP Addresses
The third set of IP addresses you’ll typically see in a cluster consists of service IP
addresses. Services provide a consistent IP address for an application running
in a Kubernetes cluster and are necessary because pods, by their very nature,
are ephemeral and may move from node to node, causing their IP addresses
to change. The SVC-IP column of output shows some service IP
addresses.

Getting Service IP Addresses:
kubectl get svc -o custom-columns=SVC-IP:.spec.clusterIP
SVC-IP
10.96.0.1
One important element of service IP addresses to know about is that, unlike
pod IP addresses and node IP addresses, there’s !!!no network interface associ-
ated with a service IP address!!!. In reality it’s associated with !!! a set of iptables
rules!!!. This is relevant when you’re testing connectivity (or the implementation
of network policies) in a cluster as you can’t expect to ping a service IP address.
Typically, they’ll respond only on the port number(s) that the service exposes.

Setting Up a Cluster with Network Policies
To demonstrate and test network policies, we’ll need to make sure that our cluster
supports them. Some of the common development cluster options (including
KinD and minikube) default to CNI providers that don’t handle the Network
Policy API.
There are instructions to enable cilium on minikube on the Kubernetes
documentation site ( kubernetes.io/docs/tasks/administer-c luster/
network-policy-provider/cilium-network-policy/ ). To set up a network
policy capable CNI with KinD, use the disableDefaultCNI option ( kind.sigs.
k8s.io/docs/user/configuration/#disable-­default-­cni ) and then just use
the installation instructions for a CNI, like Calico or Cilium (both discussed
later in the chapter).
Getting Started
With access to a (nonproduction) Kubernetes cluster, first we can create a couple
of namespaces to represent a two-­tier application (web application and database):

kubectl create namespace webapp
kubectl create namespace database

Next start an instance of the nginx web server in the webapp namespace and
expose port 80 using a service:

kubectl -n webapp run testwebapp --image=nginx --expose=true --port=80

We’ll also start an instance of postgres in the database namespace:

kubectl -n database run testdb --image=postgres --env="POSTGRES_PASSWORD=database" --expose=true --port=5432

In a real cluster, of course, you should never set your database pass-
word using an environment variable!
We can demonstrate that, at this point, the web application will be available
from another namespace in the cluster. First run a shell in a container in the
default namespace:

kubectl run -it client --image=davarski/alpine-containertools /bin/bash

and then we can access the webapp using curl :

curl http://testwebapp.webapp

Note that we can use the hostname shown here thanks to the way Kubernetes
uses DNS for service discovery. This is generally a useful feature for being able
to communicate between services in a predictable fashion.


If all is working well, you should get a response from the web application:
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>

We can also confirm that the database service is accessible using nmap :

nmap -Pn -v -n -sTV -p5432 testdb.database
This command should return output similar to 
nmap Scan of the Database Service:

nmap -Pn -sTV -p5432 testdb.database
Starting Nmap 7.70 ( https://nmap.org ) at 2020-10-10 12:57 UTC
Nmap scan report for testdb.database (10.111.98.83)
Host is up (0.000082s latency).
rDNS record for 10.111.98.83: testdb.database.svc.cluster.local
PORT
STATE SERVICE
VERSION
5432/tcp open postgresql PostgreSQL DB 9.6.0 or later
The way this initial environment is configured will be similar to most base

Kubernetes clusters, and traffic will be able to move freely.

Now that we have the basic environment set up, we can demonstrate the
operation of network policies. With network firewalling, it’s always best to
take a policy of denying by default, so let’s start by denying all ingress traffic
to the webapp namespace:

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
name: deny-ingress-webapp
namespace: webapp
spec:
podSelector: {}
policyTypes:
- Ingress

This basic policy has the usual required elements for a Kubernetes manifest,
namely, the apiVerison , kind , metadata , and spec . Within the spec , we have
a podSelector field that is empty, which means it will apply to all pods in the
namespace, and a policyTypes field stating that this applies to ingress traffic
to the namespace.
We will also apply a similar policy to the database namespace:

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
name: deny-ingress-database
namespace: database
spec:
podSelector: {}
policyTypes:
- Ingress

To demonstrate that these network policies have the desired effect, first apply
it to the cluster (we’ve called it default-deny-inbound.yaml ):

kubectl create -­f default-deny-inbound.yaml

Now, from back in our client container, if we try to execute the curl command
that previously worked, it will just time out, and using nmap to scan the database
pod will return a result of filtered , indicating that packets to that namespace
are being dropped.
shows the effect our policies have had. Traffic can still flow out of
the webapp and database namespaces to the client namespaces (and outside of
the cluster), but traffic from the client namespace to the webapp and database
namespace is blocked, and traffic between the webapp and database namespaces
is likewise not allowed.

Allowing Access
Of course, an application that doesn’t allow any access is somewhat useless, so
we need to provide the ability for necessary traffic to pass. A good example of
this is that the web application pod will likely need to communicate with the
database pod, so we can allow access into the database namespace from the
webapp namespace on the port we’re using (5432/TCP).
To do this we’re going to first need to apply a label to our namespace.
As of version 1.20 of Kubernetes, it’s not possible to address a namespace
directly by name (kubernetes.io/docs/concepts/services-networking/
network-policies/#what-you-can-t-do-with-network-policies-at-least-
not-yet), but we can apply a label to a namespace and use that:

kubectl label namespace/webapp tier=webapp

Labels are arbitrary name-­value pairs, so in this case we’re giving our namespace
a label tier with a value of webapp .
Once we’ve applied that label, we can create our policy, shown.

Network Policy to Allow the Database to Access the Web Application:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
name: allow-webapp-access
namespace: database
spec:
podSelector: {}
policyTypes:
- Ingress
ingress:
- from:
- namespaceSelector:
matchLabels:
tier: webapp
ports:
- protocol: TCP
port: 5432

In addition to the basic deny-all policies we started with, this one has two
additional sections. The first is a from section, which specifies where we are
allowing traffic from. Unlike traditional firewall rulebases, we’re not working
with CIDR ranges for this; instead, we’re using the label that we added to the
webapp namespace as a means of declaring where traffic should be allowed from.
The other new section is ports , which specifies the protocol (TCP or UDP)
and port numbers to be allowed. It’s important to be as specific as possible
when specifying firewall rules to avoid inadvertently allowing excess access.
Wherever possible, specifying individual ports here is helpful.
To apply this rule, we can just use kubectl as before:
kubectl create -f allow-webapp-access.yaml
shows the effect of this rule. The access is as before, except that
we can now go from the webapp namespace to the database port in the database
namespace.
Now that we’ve applied this rule, we can test first that access is still not
allowed from our client pod in the default namespace using nmap . Execute
another shell inside the pod:

kubectl exec -­
it client /bin/bash

and then run the same nmap command as before. This will return another filtered
result. Now to test that our access is now allowed from the webapp namespace
as expected, we’ll run a pod in that namespace:
kubectl run -n webapp -it webappclient -
-image=davarski/alpine-containertools /bin/bash

Now run the same nmap command we used before:

nmap -Pn -sTV -p5432 testdb.database

You’ll get back an open response, as shown bellow:

Open Port Scan of the Database Service:
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-27 10:53 UTC
Nmap scan report for testdb.database (10.111.98.83)
Host is up (0.00026s latency).
rDNS record for 10.111.98.83: testdb.database.svc.cluster.local
PORT
STATE SERVICE
VERSION
5432/tcp open postgresql PostgreSQL DB 9.6.0 or later

Egress Restrictions
In addition to restricting access inbound to a namespace, network policies can
be used to restrict outbound access. Egress restrictions can be useful in making
attackers lives harder and preventing inadvertent privilege escalation. If an
attacker is able to compromise a pod running in a Kubernetes cluster, one of the

first things they’re likely to do is to attempt to pull tooling into the compromised
environment to attempt to attack other services running in the cluster, or in the
general environment. Restricting access from the pods to those environments
will make that job harder.
One specific example, which can be usefully applied to clusters running in
the major cloud environments (such as AWS or Azure) is blocking access to the
metadata service. These services can provide credentials to the cloud environ-
ment or information about the service configuration that is useful to an attacker,
so access to them should be restricted, unless the workload running in a port
absolutely requires them.
Metadata services often run on predictable IP addresses, so they can be easily
blocked. In both Azure and AWS they run at 169.254.169.254.
The network policy to block egress access is similar to the ingress one. When
blocking access to a specific destination, it’s important to remember that net-
work policies are designed to add access, so the policy defined bellow
allows all access except the metadata address.

Network Policy Restricting Metadata Service Access:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
name: block-metadata
namespace: webapp
spec:
policyTypes:
- Egress
podSelector:
matchLabels: {}
egress:
- to:
- ipBlock:
cidr: 0.0.0.0/0
except:
- 169.254.169.254/32

This policy blocks access from the webapp namespace to the metadata service
address and can be applied to our cluster with the following command:

kubectl create -f block-metadata.yaml

Network Policy Restrictions
When using network policies as a security control, it’s important to note restric-
tions on how they’re applied. Specifically, standard Kubernetes network pol-
icies are implemented by the CNI plugin and apply only where a workload’s
networking is managed by that plugin. If a workload connects directly to the
underlying host network (using the directive hostNetwork: true in the pod
specification), then standard network policies will not apply to it.


CNI Network Policy Extensions
In addition to the base functionality provided by the Kubernetes Network Policy
API, there are also additional capabilities provided by some CNI providers.
These extensions often make scaling network policies and making consistent
network policies across larger clusters easier. The trade-­off with using them is
that the objects used to manage them will be tied to the CNI provider choice,
and if you want to have flexibility to use other CNI providers, you’ll need to
look at re-­implementing the restrictions on each CNI provider you implement.
Two of these providers are Cilium and Calico.

- Cilium
Cilium is a popular CNI provider that makes use of eBPF to provide
enhanced performance for Kubernetes networking. It also implements some
additional network policy capabilities, with the CiliumNetworkPolicy and
CiliumClusterWideNetworkPolicy objects.
Among its useful capabilities, CiliumNetworkPolicy can address nodes directly
in policy and apply policies to DNS names, which are not currently available
in base Kubernetes network policies.
For example, in the policy shown bellow, access will be allowed from
a namespace called webapp to Google domain sites on ports 80 and 443. Note
that to use DNS-­based policies, access from the affected workloads to DNS
services is necessary.

Cilium Network Policy DNS Example:
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
name: cilium-google-allow
namespace: webapp
spec:
endpointSelector: {}
egress:
- toEndpoints:
- matchLabels:
io.kubernetes.pod.namespace: kube-systemk8s-
app: kube-dns
toPorts:
- ports:
- port: "53"
protocol: UDP
rules:
dns:
- matchPattern: "*"
- toFQDNs:
- matchPattern: "*.google.com"
toPorts:
- ports:
- port: "443"
- ports:
- port: "80"

Applying the policy can be done with only kubectl :

kubectl create -f cilium-google-allow.yaml

CiliumClusterWideNetworkPolicy objects allow you to define policies that
are not namespaced and apply to the whole cluster. This is useful for establish-
ing baseline security policies where there are a large number of namespaces
in a cluster.
Looking at the example shown abowe, we can see that it is possible to
establish a default deny on traffic entering the cluster from any entity outside the
cluster. This policy makes use of a Cilium-­specific concept of the world entity,
which matches anything outside the managed cluster.

Cilium Cluster-Wide Lockdown Policy
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
name: cilium-external-lockdown
spec:
endpointSelector: {}
ingressDeny:
- fromEntities:
- "world"
ingress:
- fromEntities:
- "all"

You can find more information on the available entities that can be used in
Cilium policies in its documentation ( docs.cilium.io/en/stable/policy/
language/#entities-based ).

- Calico
Another popular CNI provider is Calico, which also provides extensions to the
base Kubernetes Network Policy API. Calico’s approach is to have an object type
called NetworkPolicy (the same as the Kubernetes object name) but to have that
in a separate API namespace ( projectcalico.org/v3 ), so care should be taken
when writing manifests to choose the correct value for the apiVersion field.
When using Calico-­specific policies, it’s currently necessary to use their
 calicoctl tool to apply the policies, although there is an intention to allow kubectl
to be used it the future ( github.com/projectcalico/calico/issues/2923 ). This
tool can be installed using the documentation on their site ( docs.projectcalico
.org/getting-started/clis/calicoctl/install ).
Calicoctl will use the same kubeconfig file as kubectl , by default, although
it is possible to configure it to connect to a specific cluster independently ( docs
.projectcalico.org/getting-started/clis/calicoctl/configure/ ).
Calico’s network policy provides useful features missing from base Kuber-
netes, including the ability to log where network policies block traffic in the
cluster. This kind of feature is handy, both for troubleshooting and also for
security monitoring.
As an example, the policy shown bellow could be used to allow
access to web applications running in the webapp namespace on port 80/TCP,
while logging the allowed access. Logs generated by Calico network policies
will be placed in the node’s iptables log location (typically the kernel logs).

Calico Policy to Allow and Log Access:
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
name: calico-allow-and-log-webapp
namespace: webapp
spec:
ingress:
- action: Log
protocol: TCP
destination:
ports:
- 80
- action: Allow
protocol: TCP
destination:
ports:
- 80

Applying this is done using calicoctl :

curl -O -Lhttps://github.com/projectcalico/calicoctl/releases/download/v3.18.1/calicoctl
chmod +x calicoctl
calicoctl create -f calico-allow-and-log-webapp.yaml

Calico also has a GlobalNetworkPolicy object that, similarly to the facility
provided by Cilium, allows network policies to be defined that work across
whole clusters.
The bellow example provides a default deny base policy that would
apply across the whole cluster apart from kube-­system , which should be pro-
tected from generalized policies because of its sensitive nature as it is the heart
of the cluster.

Calico Default Deny Global Policy
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
name: calico-default-deny
spec:
selector: projectcalico.org/namespace != "kube-­
system"
types:
- Ingress
- Egress
Again, this policy would be applied using calicoctl :
calicoctl create -f calico-default-deny.yaml

4.Workload Hardening

4.1.Using Security Context in Manifests

Kubernetes provides a number of features that can be used, when applications are
being deployed to the cluster, to improve their security. Some of these are likely
to be easily deployed with limited impacts, but others will require more prepara-
tion to effectively deploy. The mechanisms exposed as part of a security context
are largely mirrors of similar features available at the container runtime level.

Setting security contexts in manifests is an important hardening step, partic-
ularly when developing applications that will be deployed in arbitrary clusters
(for example, when developing open source applications). Having a good idea of
the rights required for your application and ensuring that the security context
matches those requirements as closely as possible will help users in improving
the security of their clusters.

General Approach
Security contexts can either be set at the level of a container or apply to all con-
tainers in a pod. If both are defined, the container-­level settings will override
pod settings. In most cases, it is advisable to set these items at one level only to
avoid potential unexpected results.
Within a container, the security context is defined at the same level as the
container name and image, as shown bellow.

Setting a Container Security Context:
containers:
—name: db
image: mongo
ports:
—name: mongo
containerPort: 27017
securityContext:
capabilities:
drop:
—all
add:
—CHOWN
—SETGID
—SETUID
readOnlyRootFilesystem: true

allowPrivilegeEscalation
This is one of the available hardening options that should almost always be set,
as it has limited risk of causing issues with running workloads. When set to
false , this flag instructs the container runtime (and thereby the Linux kernel) to
prevent any requests from the contained process to acquire additional privileges.
To illustrate this effect, imagine we have a container that is set to run as a
non-root user. If there was a setUID root instance of a Bash shell inside the con-
tainer image, it would be possible for an attacker who had gained access to the
container to escalate their privileges to root.

However, if allowPrivilegeEscalation is set to false, when the shell is run,
it won’t escalate privileges to root.
To demonstrate this, we can use Docker commands on a standard image
and an image on Docker Hub that has a setUID shell present. The Docker Hub
image raesene/setuidexample has a setUID shell located at /bin/setuidbash .
After launching a container based on this image:

docker run -it raesene/setuidexample /bin/bash

you can run whoami , which should show your user as newuser :

newuser@83ddb9714a5e:/$ whoami
newuser

Then, after running the setUID shell, we can confirm the user has changed:

newuser@83ddb9714a5e:/$ /bin/setuidbash -p
setuidbash-4.4# whoami
root

To demonstrate no-new-privileges in effect, we can pass that option to
docker run , which has the same effect as using a security context in a Kuber-
netes workload.

docker run -it --security-opt=no-new-privileges raesene/setuidexample /bin/bash

Now trying to use the setUID shell, we can see it has no effect:

/bin/setuidbash -p
newuser@15e5a64014a4:/$ whoami
newuser

Capabilities
By default, when a Linux container runs, it will be assigned a set of capabilities
(Linux capabilities were discussed in Chapter 1, “What Is A Container?”), which
are portions of the rights provided traditionally to the root user in a Linux
system. The default set of capabilities will depend on the container runtime in
use (for example, Docker may provide a different set than CRI-­O). As a result,
for applications, specifying the capabilities they require helps the application
to run smoothly on unknown clusters as they’re not depending on the default
set of capabilities assigned by the CRI being correct.
Dropping capabilities can be an effective method of hardening a container
and reducing the risk that an attacker can break out to attack other applications
running in a Kubernetes cluster.
It’s possible to see the capabilities assigned by default to a container by running
amicontained ( https://github.com/genuinetools/amicontained ) from inside
a container.
We can use the Docker Hub image davarski/alpine-containertools to dem-
onstrate this by running the following:

kubectl run -it amicontained --image=davarski/alpine-containertools /bin/bash

and then running amicontained . If your cluster is using Docker as a runtime,
you should see output similar to that shown in.

Capabilities Under a Docker Runtime:
Container Runtime: kube
Has Namespaces:
pid: true
user: false
AppArmor Profile: docker-­
default (enforce)
Capabilities:
BOUNDING -
> chown dac_override fowner fsetid kill setgid setUID
setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: disabled
Blocked Syscalls (22):
MSGRCV SYSLOG SETSID VHANGUP PIVOT_ROOT ACCT SETTIMEOFDAY
UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME
INIT_MODULE DELETE_MODULE LOOKUP_DCOOKIE KEXEC_LOAD
PERF_EVENT_OPEN FANOTIFY_INIT OPEN_BY_HANDLE_AT FINIT_MODULE
KEXEC_FILE_LOAD
Looking for Docker.sock

For our purposes, the important section is under Capabilities. This shows
the default set of capabilities assigned to the container.
There are two approaches that can be taken to hardening this container. The
first option is easier to implement: drop capabilities that you don’t require
from the default set. A prime example of a capability that should be dropped
from most container workloads is net_raw . From an attacker’s perspective, this
capability can be used to attempt ARP spoofing attacks, which can be a useful
mechanism for them to attempt to increase their access to a cluster. On the flip
side from the perspective of an application running in a container, this capa-
bility is required only if there is a requirement to send raw network packages
(for example, ICMP ping), which is often not required.
If you wanted to drop that capability from a manifest, it would be specified
in the security context this way:

securityContext:
capabilities:
drop:
—NET_RAW

The other approach to handling capabilities in a container is to drop all of them
and then add back those that are explicitly required. This requires some more
work as the application should be analyzed to see which, if any, capabilities are
required. Remember, though, that capabilities are facets of root’s privileges; so
if you are porting applications that previously ran as nonprivileged users, it’s
quite likely that they don’t need any capabilities at all.
In the example shown earlier in this chapter, we can see that after all capa-
bilities were dropped, three were added back, CHOWN , SETGID , and SETUID . In
this case, it would allow the process running in the container to modify the
ownership and permissions of files it can access.

privileged
This should always be set to false. Setting privileged to true will cause the
container to run with the security isolation provided by the container sandbox
effectively disabled. Given the flexibility and number of other, less drastic options
you can set to provide a container with additional rights, it should almost never
be necessary to set this flag to true.

readOnlyRootFilesystem
This setting prevents files from being written to the root filesystem of the container
and can often be applied to improve container security. Because ­containers are
meant to be ephemeral, they should generally avoid holding any state within
the container, so setting the root filesystem to be read only should not impact
their operation.
From an attacker’s perspective, this kind of control can make exploiting issues
in the application more difficult, as a common step in many attacks is placing
a tool onto the compromised system.
Where the contained application does need to write to disk (such as log or
temporary files) a good pattern to use is to mount something like an emptyDir
volume (for more information, see https://kubernetes.io/docs/concepts/
storage/volumes/#emptydir ), and if something like a database server will run
in the container, you can use persistent volumes to provide the storage and still
make the main root filesystem of the container read-­only.

seccompProfile
Another layer of isolation that comes with Linux container runtimes like Docker
is the ability to specify a seccomp profile ( https://docs.docker.com/engine/
security/seccomp/ ) for a container. Seccomp profiles provide the most granular
approach to Linux container isolation as they allow specific sets of Linux kernel


syscalls to be blocked or allowed. By default, Docker has a seccomp profile that
is enabled for every container and blocks a number of potentially dangerous
syscalls, but it is important to note that Kubernetes will disable this filter unless
explicitly told to enable it.
To illustrate this difference, we can use amicontained first on a container run
directly via Docker (that is, without using Kubernetes):

docker run -it davarski/alpine-containertools /bin/bash -c amicontained

The output includes a list of blocked syscalls:
Blocked Syscalls (63):
MSGRCV SYSLOG SETSID USELIB USTAT SYSFS VHANGUP
PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON
SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM
CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS
QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL
TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND
SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY
KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN
FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT
CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV
KCMP FINIT_MODULE KEXEC_FILE_LOAD BPF USERFAULTFD
MEMBARRIER PKEY_MPROTECT PKEY_ALLOC PKEY_FREE RSEQ

Running the same container image in a Kubernetes 1.18 cluster that uses Docker
as the CRI produces a smaller set of block syscalls, as the items from Docker’s
seccomp filter are not included:

Blocked Syscalls (22):
MSGRCV SYSLOG SETSID VHANGUP PIVOT_ROOT ACCT SETTIMEOFDAY
UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME
INIT_MODULE DELETE_MODULE LOOKUP_DCOOKIE KEXEC_LOAD
PERF_EVENT_OPEN FANOTIFY_INIT OPEN_BY_HANDLE_AT FINIT_MODULE
KEXEC_FILE_LOAD

In versions of Kubernetes up to version 1.18, enabling seccomp profiles for your
containers requires adding an annotation to the pod manifest in the metadata
section. For example, to set the runtime default profile for containers running
in a pod, you would add the following annotation to your definition:

annotations:
seccomp.security.alpha.kubernetes.io/pod: runtime/default

Since version 1.19, it is possible to set the seccomp profile using security con-
texts, although it is worth noting that this can be set only on new pods defined
in the cluster; you can’t edit the specification of an existing workload to add it.


2.Mandatory Workload Security
In addition to the voluntary controls that we can place into the security con-
text section of workload manifests, cluster operators will likely want to add
mandatory controls on what deployed workloads can do in their clusters.
Kubernetes handling for this mandatory workload security is currently
evolving (see https://kubernetes.io/blog/2021/04/06/podsecurity­policy-­
deprecation-past-present-and-future/ for more information and updates).
Traditionally, Pod Security Policies (PSPs) are the built-­in mechanism for
this; however, as a feature, they never hit full release and were stuck as a beta
feature for a large number of releases. As a result, the Kubernetes project decided
to deprecate them in version 1.21 and plan to remove them in version 1.25
(although this is subject to change). Fortunately, there are a number of options
we can consider when looking to achieve this goal.

Pod Security Standards
In preparation for the deprecation of PSPs, the Kubernetes project has defined
a set of generic recommendations for security settings to be applied to cluster
workloads, known as Pod Security Standards ( https://kubernetes.io/docs/
concepts/security/pod-security-standards/ ). The concept is that this could
form a reference point for practical implementations of workload restriction tools.
These standards define three levels of restriction that could be placed onto
cluster workloads: Privileged, Baseline, and Restricted.
The Privileged level is entirely unrestricted. Allowing a user to create work-
loads that can use this policy would allow them to gain access to the under-
lying node, should they want to do so. It’s mainly required for trusted cluster
components, which need to interoperate with the node operating system, like
the kube-proxy process.
The baseline level provides a minimal level of restrictions that should block
known privilege escalation points. It restricts specific things like the privileged
flag discussed earlier in this chapter, but still allows things like the NET_RAW
capability that can cause security issues. Using tools that implement this policy
should allow most common containers to run without modification.
The restricted level takes a far stricter approach, providing what the Kubernetes
project says is a best-practice level of restrictions. In addition to mandating the
removal of known privilege escalation paths, things like volume types allowed

and the user running the container are restricted. Implementing this policy is
likely to be a challenge in many clusters, as it will require workload manifests to
be modified in many cases; however, it serves as a good target operating model.

PodSecurityPolicy
Although Pod Security Policies are scheduled for deprecation, it is likely that
many existing clusters will have them deployed for some time, so it is worth
discussing how they operate and some of the challenges of using them.
Setting Up PSPs
Before enabling PSPs it’s important to understand a bit about how they operate.
Once PSPs are enabled, when a workload is launched on the cluster, the PSP
controller will be called to confirm that the user or service account launching the
workload has access to a PSP that matches the security contexts requests made
by the workload. If no matching PSP can be found, the workload will be rejected.
As such, if you enable the PSP admission controller in your cluster before
creating any policies, it won’t be possible to create any new workloads, until
you create some policies! So it’s important to have some basic policies worked
out before trying to enable PSPs in a production cluster.
One option is to create a default “allow all” policy before enabling PSPs and
then work to restrict access to that high-­privileged policy as you add new ones.
This is the approach taken by some managed Kubernetes distributions, such
as Amazon EKS ( https://docs.aws.amazon.com/eks/latest/userguide/
pod-security-policy.html ), and it enables you to enable PSPs without risking
the operation of the cluster.
Another approach is to set up a couple of basic policies before enabling PSPs;
one would be a “high-privileged” policy for system components that need that
level of access, and the other a “low-­privileged” policy for standard workloads.
This has the advantage that you aren’t allowing all access by default, so the PSP
enforcement will be having some effect from the point it’s enabled. If you’re
aligning your policies with the generic Pod Security Standards, these levels
would likely correlate to using their “privileged” and “baseline” policies.
Which approach you take for the initial PSP setup will likely depend on
whether you’re trying to retrofit PSPs to an existing cluster or developing the
cluster workloads as you create PSPs.
To illustrate the two-policy approach, let’s look at a couple of example PSPs.
shows the first one, which we’ll call highpriv as it allows most
security options that a workload might need.

High-Privileged PodSecurityPolicy:
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
name: highpriv
spec:
privileged: true
allowPrivilegeEscalation: true
allowedCapabilities:
- '*'
volumes:
- '*'
hostNetwork: true
hostPorts:
- min: 0
max: 65535
hostIPC: true
hostPID: true
runAsUser:
rule: 'RunAsAny'
seLinux:
rule: 'RunAsAny'
supplementalGroups:
rule: 'RunAsAny'
fsGroup:
rule: 'RunAsAny'

A key point is that this PSP allows for privileged containers. As mentioned
earlier, a user who can create privileged containers will be able to gain access
to the underlying node, likely as the root user, so care must be taken when
enabling this policy.
Next, we have a more restrictive policy we’ll call lowpriv .

Low-Privileged PodSecurityPolicy:
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
name: lowpriv
spec:
privileged: false
allowPrivilegeEscalation: false
requiredDropCapabilities:
- ALL
volumes:
- 'configMap'
- 'emptyDir'
- 'secret'
hostNetwork: false
hostPID: false
runAsUser:
rule: 'MustRunAsNonRoot'
seLinux:
rule: 'RunAsAny'
supplementalGroups:
rule: 'MustRunAs'
ranges:
- min: 1
max: 65535
fsGroup:
rule: 'MustRunAs'
ranges:
- min: 1
max: 65535
readOnlyRootFilesystem: false

This policy prevents users who use it from adding a number of potentially
dangerous options, like privileged containers, or using the underlying node’s
network interfaces. Note that it also restricts the volume types that workloads can
use as part of their specification; it does this because there are risks in allowing
pods to mount files from the underlying node. Specifically, they could mount
directories with sensitive information (for example, the TLS private key that
the kubelet uses to communicate with the Kubernetes API server).

Setting Up PSPs
Once you have the PSPs you want to use in the cluster, the next step is to create
them. This can be done by just applying the YAML files via kubectl :

kubectl create -f lowpriv.yaml
kubectl create -f highpriv.yaml

We can then view the created PSPs, as shown with the bellow command

kubectl get psp .

At this point, however, these PSPs will have no effect on cluster behavior,
because the PSP admission controller isn’t active yet.
To enable that, we need to edit the API server startup flags that specify the
admission controllers to enable. For a kubeadm -­based cluster, we do this by
editing the API server static pod manifest here:

sudo nano /etc/kubernetes/manifests/kube-apiserver.yaml

Add the string PodSecurityPolicy to the end of the --enable-admission-plugins parameter. In a standard cluster, it should now look like this:

--enable-admission-plugins=NodeRestriction,PodSecurityPolicy

Once the API sever manifest is modified and saved, it should, in a kubeadm
cluster, automatically be reloaded while the kubelet watches the directory it’s
in for any changes.


PSPs and RBAC
With policies created, the next step to consider when making use of PSPs is
ensuring that your RBAC settings are correctly configured to support them.
The way this works is that users and service accounts need the “USE” right
on a given PSP to be able to make use of it, and if a user has access to multiple
PSPs, then any of them can be used by a workload they’re creating.
When you have both a high-­privileged and low-­privileged policy, as in our
earlier example, a generally suitable approach is to give access to the low-­
privileged policy to the system:authenticated group. This is a special group
that is provided to any authenticated users and means that any cluster user
can create workloads that comply with the requirements of the lowpriv PSP.
To do this, create a cluster role, as shown bellow.

LowPriv Cluster Role:
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
name: psp-lowpriv
rules:
- apiGroups:
- extensions
resources:
- podsecuritypolicies
resourceNames:
- lowpriv
verbs:
- use
Then create a cluster role binding that ties this cluster role to the
system:authenticated group, as shown bellow.

LowPriv Cluster Role Binding:
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
name: psp-default
subjects:
- kind: Group
name: system:authenticated
roleRef:
kind: ClusterRole
name: psp-lowpriv
apiGroup: rbac.authorization.k8s.io

Applying these two objects to the cluster API will leave us in a position where
any user can create basic pods for the cluster.
The next step is to consider what rights to provide for the high-­privileged
role that was created earlier. This provides extensive rights for pods and should
be used with care. Users with cluster-­admin rights will already have access to
this policy, so there’s no need to explicitly create role bindings for them; how-
ever, if a cluster admin user tries to create a deployment, replicaset, or similar
object, it will be denied. Explaining this requires a bit of background into how
Kubernetes creates objects in the cluster.
When a user creates a pod, the permissions used are those of the user, but
when a user creates a higher-­level object like a deployment, it is actually one
of Kubernetes controllers that carries out the pod creation process; and there-
fore it is the controller service accounts that require access to PSPs as part of
the setup process.
For example, with a deployment, the user creates a deployment object, the
deployment controller uses its permissions to create a replicaset object, and then
the replicaset object creates the pods using its permissions.
This means that to allow privileged containers to be deployed, the controller
service accounts will need to have access to that PSP. Typically, the way this is
done, without giving access to every user who can create deployments, is to
restrict it by namespace.
For example, we would usually want privileged containers to be deployed
in the kube-system namespace, as some of the components there are likely to
need elevated rights.
To make that possible, you can create a role, as shown bellow.

HighPriv PSP Cluster Role:
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
name: psp-highpriv
rules:
- apiGroups:
- extensions
resources:
- podsecuritypolicies
resourceNames:
- highpriv
verbs:
- use

Then, in the kube-system namespace, define role binding, as shown  bellow.

HighPriv PSP Role Binding:
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
name: psp-permissive
namespace: kube-system
roleRef:
apiGroup: rbac.authorization.k8s.io
kind: ClusterRole
name: psp-highpriv
subjects:
- kind: ServiceAccount
name: daemon-set-controller
namespace: kube-system
- kind: ServiceAccount
name: replicaset-controller
namespace: kube-system
- kind: ServiceAccount
name: deployment-controller
namespace: kube-system

This will provide the rights the controller service accounts need, but only
where they are deploying workloads to the kube-­system namespace.
Using this approach, any user who is able to create daemonsets, replicasets,
or deployments in the kube-­system namespace will be able to make use of
this PSP. So, to prevent it being misused by users of the cluster, it’s impor-
tant to ensure that only trusted users have rights to create workloads in the
kube-system namespace.

PSP Alternatives
Now that PSPs are scheduled for deprecation, it is worth considering alter-
natives that can be used to implement similar controls. While there will be an
in-tree option for this, it is expected to be limited in scope, so for more complex
requirements an external admission controller is likely to be the best option.

There are a number of projects that can be configured to perform similar
checks to those carried out by PSPs on workloads being launched on the cluster.
As an added bonus, these solutions are generally more flexible and can be used
for other policy management duties.
Here we will examine two of the more popular options for this:

- Open Policy Agent ( https://www.openpolicyagent.org/ )
- Kyverno ( https://kyverno.io/ )

These two programs take quite different approaches to the problem of enforc-
ing policies on Kubernetes workloads, so it’s worth considering both when
working out which will be the most applicable to your environment.

- Open Policy Agent
Open Policy Agent (OPA) is a general policy control system for Cloud Native
environments and is part of the CNCF. It allows users to define policies to ensure
that a wide variety of systems meet specific requirements.
With the context of Kubernetes, there is a specific program that OPA provides
called Gatekeeper ( https://github.com/open-policy-agent/gatekeeper ),
which can be installed into a cluster to enforce policies. The gatekeeper compo-
nent runs as a controller inside the cluster and hooks into the API server using
a validating admission webhook ( https://kubernetes.io/docs/reference/
access-authn-authz/extensible-admission-controllers/ ). This mechanism
essentially allows Gatekeeper to define a range of events that will be sent to
it for review. Once the Gatekeeper component sees an event, it can apply the
policies that it has to decide whether to admit or reject it.

Installation
Installing Gatekeeper into a cluster is a relatively straightforward process, and
the documentation is clear and easy to follow ( https://open-policy-agent
.github.io/gatekeeper/website/docs/install/ ). In common with a lot of
Cloud Native software, it can be installed either by directly applying a manifest
or by using the helm package manager.
Once we’ve applied the Gatekeeper manifest, it’s possible to see some of the
changes that have been made to the cluster. As shown bellow, Gatekeeper
will install itself into its own namespace.

Gatekeeper Installed:
kubectl get ns
NAME
default
gatekeeper-system

we can see the webhook that Gatekeeper uses to gain access
to API server events.

Gatekeeper Webhook:
kubectl get validatingwebhookconfigurations
NAME
gatekeeper-validating-webhook-configuration
WEBHOOKS
2
AGE
12mOperation

Once Gatekeeper is installed, it will need policies to apply. OPA provides a
policy library covering common use cases and has a specific set of policies cov-
ering the same ground as Pod Security Policy, which can be found at https://
github.com/open-policy-agent/gatekeeper-library/tree/master/library/
pod-security-policy .
To apply a policy to a cluster, two objects need to be created. The first is a
constraint template. This object describes the constraint to be applied and provides
the rego code used to implement it. Rego ( https://www.openpolicyagent.org/
docs/latest/policy-language/ ) is a query language designed by OPA. Having
its own programming language does provide a lot of flexibility; ­however, it does
place a bit of a learning curve on designing your own constraints.
Looking at the sample constraint template provided for restricting privileged
containers ( https://github.com/open-policy-agent/gatekeeper-library/
blob/master/library/pod-security-policy/privileged-containers/
template.yaml ), we can see the main elements in .

OPA Constraint Template for Privileged Containers:
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
name: k8spspprivilegedcontainer
annotations:
description: Controls running of privileged containers.
spec:
crd:
spec:
names:
kind: K8sPSPPrivilegedContainer
targets:
- target: admission.k8s.gatekeeper.sh
rego: |
package k8spspprivileged
violation[{"msg": msg, "details": {}}] {
c:= input_containers[_]
c.securityContext.privileged
msg:= sprintf("Privileged container is not allowed: %v,
securityContext: %v", [c.name, c.securityContext])
}
input_containers[c] {
c:= input.review.object.spec.containers[_]
}
input_containers[c] {
c:= input.review.object.spec.initContainers[_]
}

The Constraint template essentially creates a custom resource definition that
will then be available in the cluster to be applied using constraint objects. Inside
the object spec, we can see the layout of the custom resource definition (CRD)
element. (See https://kubernetes.io/docs/concepts/extend-kubernetes/
api-extension/custom-resources/#customresourcedefinitions for more
information about CRDs.) The name to be used is set with kind: K8sPSP
PrivilegedContainer , which will then be available as an object type.
After that, the detail of the constraint template is the rego section, which lays
out the policy to be applied. Within that block we can see that there is code to
review the containers and initContainers sections of any manifest and to see if
the securityContext.privileged setting is present and deny admission if it is.
Because this object is just a template, on its own it won’t have any effect, so
an additional object is needed to apply the template to the cluster. This is done
using a constraint object. Let’s look at the sample for privileged containers, as
shown in.

Privileged Containers Constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
name: psp-privileged-container
spec:
match:
kinds:
- apiGroups: [""]
kinds: ["Pod"]
excludedNamespaces: ["kube-system"]

We can see how the constraint ties the template to the cluster. The constraint tem-
plate to be used is specified using the kind of this object. In this case, we see kind:
K8sPSPPrivilegedContainer , which is the same as we saw in our constraint template.
After that, the constraint lays out which type of objects should have the template
applied to them (in this case pod objects) and then any excluded namespaces. This
is an important element of the constraint to avoid disrupting the cluster.
As mentioned in the PSP section of this chapter, namespaces like kube-­system
will often need privileged pods to be deployed into them, so we need to exclude
that namespace from this kind of policy.

Enforcement Actions
Another useful feature that OPA has over PSP is that it is possible to set con-
straints to only log occasions where they would usually deny access ( https://
open-policy-agent.github.io/gatekeeper/website/docs/violations ).
This is done via the enforcementAction parameter in the constraint specifica-
tion. To see how it works, consider our previous example of denying privileged
containers. If you are deploying this constraint to a new cluster and want to see
whether any workloads would fail, without actually blocking things, you can
add the constraint as shown bellow.

Dry Run Privileged Containers Constraint:
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
name: psp-privileged-container
spec:
enforcementAction: dryrun
match:
kinds:
- apiGroups: [""]
kinds: ["Pod"]
excludedNamespaces: ["kube-system"]

Once this constraint has been set, you can see whether there are any viola-
tions for newly created resources, by looking at the totalViolations field in
the object specification. To get just that value the following jsonpath statement
can be used for this constraint:

kubectl get k8spspprivilegedcontainer -o jsonpath='{.items[*].status.totalViolations}'


- Kyverno
Kyverno ( https://kyverno.io/ ) is a policy engine designed for Kubernetes.
Like OPA, it is a CNCF project. Unlike OPA, Kyverno uses standard YAML files
to define policies, and the scope of the project is purely as a policy engine for
Kubernetes clusters.


Installation
Kyverno can be installed either by running a manifest directly from their GitHub
repository or by using the helm package manager ( https://kyverno.io/docs/
introduction/#quick-­start ). Once the manifest has been applied to the cluster,
we can see that, similarly to OPA, there’s a new namespace for Kyverno, as
shown in.

Namespaces with Kyverno Installed:
kubectl get ns
NAME
default
kube-node-lease
kube-public
kube-system
kyverno
local-path-storage

Kyverno also installs validating admission webhooks that will be used to check
workloads as they are deployed to the cluster, as we can see in.

Validating Admission Webhooks for Kyverno:
kubectl get validatingwebhookconfigurations
NAME
WEBHOOKS
kyverno-policy-validating-webhook-cfg
1
kyverno-resource-validating-webhook-cfg
1
AGE
118s
118s
Operation

With Kyverno installed, we need to define policies for it to apply. There is a
library of policies that replicate the requirements of PSP on Kyverno’s GitHub
account ( https://github.com/kyverno/policies/tree/main/pod-security ).
Kyverno allows for two types of policies: ClusterPolicy objects will apply
restrictions across the whole cluster, while Policy objects are used for individual
namespaces. Unlike OPA, Kyverno provides no separation between templates
and constraints.
A sample policy for blocking privileged containers, as shown bellow,
demonstrates the structure of a Kyverno policy.

Kyverno ClusterPolicy for Blocking Privileged Containers:
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
name: disallow-privileged-containers
annotations:
policies.kyverno.io/category: Pod Security Standards (Default)
policies.kyverno.io/description: >-Privileged mode disables most security mechanisms and must not be allowed.
spec:
validationFailureAction: enforce
background: true
rules:
- name: privileged-containers
match:
resources:
kinds:
- Pod
exclude:
resources:
namespaces:
- kube-system
validate:
message: >-Privileged mode is disallowed. The fields
spec.containers[*].securityContext.privileged
and spec.initContainers[*].securityContext.privileged must not be set
to true.
pattern:
spec:
=(initContainers):
- =(securityContext):
=(privileged): "false"
containers:
- =(securityContext):
=(privileged): "false"

In common with general Kubernetes object structures, the key fields are in
the spec: section. First the validationFailureAction is used to dictate what
happens when an object fails the policy. The two major options are enforce ,
which will block object creation, and audit , which will just log the failure and
allow creation, an option that is useful for testing new rules.
The match section shows which resources will have the rule applied to them.
For most PSP replacement policies, it will be pod resources that should be
addressed, although it’s worth noting that Kyverno policies can apply to any
object type.
The exclude section is also used to show which resources to choose. In this
case, the policy is configured to ignore the kube-­system namespace, as there
will likely be requirements for privileged containers there.
Lastly, the pattern section shows the test being applied, which is looking for
the privileged section of the pod’s securityContext and ensuring it’s set to false.
The Kyverno documentation has a lot of detail on how to create policies to
be enforced ( https://kyverno.io/docs/writing-policies/ ).

```

### Zero-Trust model implementation in cloud (VMs) (other models: The Security Wheel (cloud)/ The Attack Continuum Model(cloud/on-prem)/Perimeter Protection(old:before cloud) ---> Pritnl-Zero (centralize user management with ssh keys - add teams-> and keys on VMs only with needed privileges) 

```
- Using advanced authentication and authorization resources, before granting access, is
key for avoiding undesired use of your computing resources or, even worse, unautho-
rized access to data under your control. (IAM)

- Promoting granular segmentation of the network, up to the point where you are able to
define access control rules down to a single instance level (when necessary), is another
key measure associated with the new “shared land” reality. This fine-grained rule-
building practice is frequently called microsegmentation.(VPC, Firewall, WAF, SG, NSG/ASG, subnets, peerVPC, etc) 

- The use of encryption technologies everywhere is key to bring the confidentiality and
integrity attributes to the scene, thus helping you to ensure that data privacy has not
been compromised and that data remains unaltered.(Vault, KMS, Azure Vault, TLS/SSL and offloading, VPN (IPSec), Disks/blob encrytion)

Note(simple sec controls): principle of least privilege (IAM is part of zero-trust model Zero-rtust = 1.IAM + 2.VPC(FW,subnets,firewalls)+3.Encryption:Vault/KMS/encrypted disks&blobs/SSl_TLS(WAF/AG)/VPN(IPSec)):

Zero-Trust IAM (Clouds diff: IAM)

principle of least privilege (IAM is part of zero-trust model Zero-rtust = 1.IAM + 2.Infrastructure/Network security controls: VPC(hard partitioning), FW,subnets(soft partitioning),firewalls, routes)+3.Encryption(Vault/KMS/encrypted disks&blobs/SSl_TLS(WAF/AG)/VPN(IPSec)):

- !!!! AZURE: SCOPE+ Azure AD identity + Role = RBAC Assingments!!!!

- !!!! GCP: Member Identity (account, group, service account, cloud identity or workspace domain)   + Roles (Predefined Fine-Granted roles: compute.instance.admin, storage.object.admin, etc.) = Cloud IAM (RBAC Assinment) ( Identity <----- Policy(roles/storage.admin) ---> Resource )

- !!!! AWS: Principals (root user/IAM user/IAM group) +  IAM roles(don't have credentials (priv/pub keys & tokens) -> assined to IAM User/Group, Service(example: Ec2(application inside) and can be assumed (assumeRole) using AWS Security Token Service (STS) for temp keys/tockens) + Resource (Policy/Permisions) = Cloud IAM (RBAC) 
----> Identity (IAM user/group, Iam role) ---> policy ---> resource ----> cloud IAM (RBAC) 

NOTES !!!!: Cloud Security (microservcies/k8s): Zero-Trust model implementation

1.IAM(Microservcies in EKS/AKS/GKE):k8s pod is like VMs(EC2,Azure VMs) instance and cam Assume ROLES (apply cloud policies, not k8s Pod Security Policy is k8s not cloud related)+xample: k8s (EKS/AKS/GKE) : microservcies + k8s RBAC + cloud RBAC(IAM) ----(not only k8s nativ pod security policy and RBAC)

2.Infrasrtructure/Network controls (microsegmentation --- servcie/domain is in own VPC and inter-comunication via 1.VPC Peering(mesh topology-between servcies - only needed comunication:strict control)/2.hub-spoke(star) network topology(AWS Transit Gateway, Azure HUb-Spoke, Google -via transit GW routing table)/3.VPC endpoints(point-to-point topology)(strict comunictaion between consumer-publisher).More important to implement IAM/Data Security because it's understand security (application level). Microsegmentation more cost and traffic between VPCs(Domain servcies), more complecs for networking(routing/subnets) and security. Better use Prod/Stagin/DEV enviroments VPCs

3.Data security
-in-rest: example (IAM policies and roles + Encription: AWS KMS ---> S3, EBS (disks), Databases, FaaS:Lambda)
Preventing access to this data for unauthorized users through access control
Encrypting this data so unauthorized exposure of data will not be readable
-in-transit: Security in-Transit(inter-MS comunication:TLS/SSL) Example: Public-Facing Services notes (We carate only private k8s cluster and use API Gateway+ALB/NLB(k8s use ingress for creating servcie type:Load Balancer) or directly use NLB/ALB) -> Example: NLB(end-to-end encription using TLS passtrough)/ALB + TLS/SSL offloading(not end-to-end encryption in transit)+k8s Servcies(Ingress controler)/Application Gateways+ALB/NLB/Application Gateways+Serice Mesh+mTLS(Istio/Consul)

### Microservcices/k8s & Zero-Trust Security Model implementation for MS/k8s:

#### Microservices definition/characteristics
So what makes any architecture a microservice architecture? Unlike a monolithic
application, a microservice-based application is made up of a large number of light‐
weight services, which are:

- Independently deployed
You can upgrade, patch, or remove individual services without affecting the rest
of the application.

- Independently scalable
You can scale up or down individual services if there is additional load on indi‐
vidual parts of the application without affecting the rest of the application.

- Loosely coupled
Degradation or changes to individual services should not affect the rest of the
application.

- Domain-driven
Services are modularized and grouped into contexts according to the business
domains they belong to.

- Responsible for one single business task
Microservices are supposed to follow the single-responsibility principle (SRP).


#### Microservices security design patterns

In “Cloud Architecture and Security” on page 7, I promised you that cloud microser‐
vice architectures will help in realizing the secure design patterns I mentioned in the
section. With the help of the formal definition of microservices, I am sure you can see
why:

- Security through modularity
Since by definition microservice applications are made up of small modular serv‐
ices, it is possible to easily implement security controls.

- Security through simplicity
Since each modular microservice is small and follows the SRP, it is much easier to
achieve the goal of simplicity in a microservice architecture.

- Security through isolation
Since microservices follow DDD, it is easier to create an isolated environment to
run individual microservices.

- Security through zero trust architecture
By better using the AWS SRM(shared-responsibility model), and by using the granular controls that microser‐
vice architectures afford, it is possible to easily implement a zero trust
architecture.


Microservcies - Architecture/Security patterns (in-Rest (Vault, Encryption) & in-Transit (inter-communication: TLS/SSL)

#### Zero-Trust Security Model implementation for MS/k8s:

Security Controls: IAM/RBAC/PaC(policies)/Firewall Rules/subnets/Gateways/Routing Tables/Encription/KMS/Vault/AWS Certificate Manager/NLB(end-to-end encription using TLS passtrough)/ALB + TLS/SSL offloading(not end-to-end encryption in transit)+k8s Servcies(Ingress controler)/Application Gateways+ALB/NLB/Application Gateways+Serice Mesh+mTLS(Istio/Consul)

1.IAM(Microservcies in EKS/AKS/GKE): 

 k8s pod is like VMs(EC2,Azure VMs) instance and cam Assume ROLES (apply cloud policies, not k8s Pod Security Policy is k8s not cloud related)

EKS for example can attach policies for k8s-worker nodes EC2 instances  (to access ECRegistry for example) but this is not Cloud-RBAC (for pods to asume roles but k8s-nodes to asume roles and access other AWS services(ECR)/resourses), for cloud RBAC be use other implementation of RBAC for EKS where pod is like EC2 VM and we don't access metadatata servcie of EC2 to access credentials (temp tokens, pub/pivite keys)

For VMs example (EC2 roles/Service Roles/etc. or Google VM to use service account):
- AWS:STS (Simple Token Service). Use metadata service to get credentials(AWS key/AWS secret key)/tokens/public keys).
- GCP: Setup privite key in service1/resource1 we have to access ... Setup public key when provision servcie2(CM)/resource2 which have to use servcie2 via metadata service. A service account is an account that is used by services to consume other services,
unlike users who use a username and password. Roles are assigned to the service account
(this process is called binding), which has one or more permissions already defined in
order to facilitate the consumption of services.
If it is necessary to consume a service from a resource in a GCP project, simply access the
project's metadata and select the service account to use. This will allow the service to have
access to the service account private key path through the GOOGLE_APPLICATION_
CREDENTIALS environment variable and the client library will handle the authentication
using the private key and sign the access token.
On the other hand, if the application needs to consume a GCP service and the application
is not inside a GCP project, it is necessary to generate a private key of that particular
service account, download it, and save it safely in the resource. You can then expose it in
your application through the GOOGLE_APPLICATION_CREDENTIALS environment
variable:
In this way, it is possible to consume the different GCP services both for resources within
the platform itself and as resources in other clouds or in environments within their own
data centers.
- Azure: ??? Azure AD (kerberos Tokens?)



Ref: https://github.com/adavarski/k8s-UAP/blob/main/production-k8s/aws-k8s/EKS/main.tf

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_iam_role_policy_attachment.AmazonSSMManagedInstanceCore,
    aws_iam_role_policy.EKSClusterAutoscaler
  ]
}

esource "aws_iam_role" "cluster" {
  name = "${var.name}-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}
...
resource "aws_iam_role" "node" {
  name = "${var.name}-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}




Example: k8s (EKS/AKS/GKE) : microservcies + k8s RBAC + cloud RBAC(IAM) ----(not only k8s nativ pod security policy and RBAC)

In their words, AWS decided to make Kubernetes pods first-class citizens in AWS.
With Kubernetes service account annotations and OIDC identity providers, you can
assign IAM roles to individual pods and use roles the same way you did with AWS
Lambda. Shows how IAM roles for service accounts (IRSA) works when a
microservice running on a pod would like to access an AWS resource by assuming an
AWS role. !!! k8s pod is like EC2 instance and cam Assume ROLES (apply cloud policies, not k8s Pod Security Policy is k8s not cloud related)

k8s-RBAC (namespaces, servcie accounts, roles, cluster roles, cluster roles binding, Pod Security Policy) is different from Cloud-RBAC for k8s(EKS/AKS/GKE) --> Pods are like EC2(VMs) and can AsumeRoles for access resources (via policyes) 


-----EKS: RBAC cloud + k8s rbac integration ---> EKS: examples ---> https://aws.amazon.com/blogs/opensource/introducing-fine-grained-iam-roles-service-accounts/ && https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html && https://docs.aws.amazon.com/eks/latest/userguide/eks-ug.pdf#iam-roles-for-service-accounts && https://aws.amazon.com/blogs/containers/kubernetes-rbac-and-iam-integration-in-amazon-eks-using-a-java-based-kubernetes-operator/ && https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html

Let’s examine this more closely:
1. Each pod starts with an annotation about a service account along with a token
that it can use to exchange with AWS STS in return for a role within your organi‐
zation. This is done by mutating the pod with information that EKS injects into it
through the mutating webhook. It also injects the web identity token file that the
pod can use to identify itself to an OIDC IdP in Step 2.
2. To fetch the credentials, the pod makes a request to AWS STS to assume the iden‐
tity of the role along with the service account token that was injected in Step 1.
This token will be exchanged in order to get temporary authentication creden‐
tials with AWS.
3. AWS STS makes a request to the OIDC IdP to verify the validity of the request.
4. OIDC IdP responds with an affirmative response.
5. AWS STS responds with temporary credentials that the pod can use to access
AWS resources using the role that it wanted to use.
6. The pod accesses the AWS resource using the temporary credentials provided to
it by AWS STS.
By creating roles and assigning those roles to pods, IRSA also provides RBAC for
Kubernetes pods. Once assigned to pods, these roles can be used to design access con‐
trol using RBAC similar to how execution roles were used with AWS Lambda.



The IAM roles for service accounts feature provides the following benefits:

Least privilege — By using the IAM roles for service accounts feature, you no longer need to provide extended permissions to the node IAM role so that pods on that node can call AWS APIs. You can scope IAM permissions to a service account, and only pods that use that service account have access to those permissions. This feature also eliminates the need for third-party solutions such as kiam or kube2iam.

Credential isolation — A container can only retrieve credentials for the IAM role that is associated with the service account to which it belongs. A container never has access to credentials that are intended for another container that belongs to another pod.

Auditability — Access and event logging is available through CloudTrail to help ensure retrospective auditing.

Enable service accounts to access AWS resources in three steps

1.Create an IAM OIDC provider for your cluster – You only need to do this once for a cluster.
2.Create an IAM role and attach an IAM policy to it with the permissions that your service accounts need – We recommend creating separate roles for each unique collection of permissions that pods need.
3.Associate an IAM role with a service account – Complete this task for each Kubernetes service account that needs access to AWS resources.
4.Conigure the AWS Security Token Service endpoint type for a service account – You can optionally complete this task for a service account if you cluster is version 1.18 or later.

https://github.com/adavarski/aws-eks-production/blob/main/modules/iam/main.tf

#-------------------------------------------------------------------------------------------------
#--------- IAM Policy for Cluster autoscalar Deployment; Policy added to eks module
#--------------------------------------------------------------------------------------------------
resource "aws_iam_policy" "eks_autoscaler_policy" {
  count = var.cluster_autoscaler_enable ? 1 : 0

  name        = "eks-autoscaler-policy"
  path        = "/"
  description = "eks autoscaler policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeTags",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}


-----AKS: RBAC cloud + k8s rbac integration ---> AKS: examples ---> https://docs.microsoft.com/en-us/azure/aks/operator-best-practices-identity & https://docs.microsoft.com/en-us/azure/aks/manage-azure-rbac & https://docs.microsoft.com/en-us/azure/aks/azure-ad-rbac && https://docs.microsoft.com/en-us/azure/aks/concepts-identity#kubernetes-rbac


Example: terrafrom AKS 

  role_based_access_control {
    enabled = true
  }



----GKE: RBAC cloud + k8s RBAC integration ---> GKE: examples ---> https://cloud.google.com/kubernetes-engine/docs/how-to/iam && https://cloud.google.com/kubernetes-engine/docs/concepts/access-control

2.Infrasrtructure/Network controls (microsegmentation --- servcie/domain is in own VPC and inter-comunication via 1.VPC Peering(mesh topology-between servcies - only needed comunication:strict control)/2.hub-spoke(star) network topology(AWS Transit Gateway, Azure HUb-Spoke, Google -via transit GW routing table)/3.VPC endpoints(point-to-point topology)(strict comunictaion between consumer-publisher)

!More important to implement IAM/Data Security because it's understand security (application level). Microsegmentation more cost and traffic between VPCs(Domain servcies), more complecs for networking(routing/subnets) and security. Better use Prod/Stagin/DEV enviroments VPCs !!!

The network layer security infrastructure does !!!not read or understand application
layer semantics. Rather than seeing applications (that run business logic) interacting
with one another, the security infrastructure sees network interfaces that interact with
one another, making it difficult to apply controls that can incorporate business logic.
In general, network security is like an axe: solid, powerful, but occasionally blunt and
!!!inaccurate. In no way am I discrediting the importance of network security but
merely pointing out that it requires refinement to accommodate any nuance in apply‐
ing security rules.
If you list every service in your application, you can roughly divide these services
into two sets. The first are called "edge" services(via API Gateway or NLB/ALB), which allow end users to fetch or
change the state of their aggregates. These services are internet facing and hence are
exposed to threats from around the world that most internal services may never have
to face. The edge services are said to be residing in the public zone of your cloud
infrastructure. For the purposes of this chapter, I will not be focusing on the services
within the public zone. Rest assured, I will go into detail about these public-facing
services in Chapter 6.
The second set of services are the ones that communicate only with other services
or resources within your organization. I will label these as "backend" services. They
operate in nonpublic environments, giving them an extra shield of protection against
external (public) threats. This chapter focuses mainly on services that live within this
private zone.

2.1.Microsegmentation at the Network Layer
One option for segmentation involves isolating systems based on their environment(!!!! beter use this for simplicity and don't complicated inter-VPC comunications)
Production deployments get their own VPC, as do staging deployments, QA deploy‐
ments, and any others you may choose to have. This parallels the historic isolation of
servers of different environments from one another.
With microsegmentation, only domains and bounded contexts are
segmented into network partitions. Multiple services can be located
within the same domain and hence within the same network
partition

2.2.Containers and Network Security notes: 

- Block Instance Metadata Service
Kubernetes pods are abstractions that may be running on actual virtual machines
(VMs). The host machines may have roles and permissions that may be different
from those intended for your pods. It is important that your pods do not mistake who
they are with the roles and identities that are attached to the nodes that they run on.
If you have assigned roles to pods using some tool, such as kube2iAM or Kiam, you
have to make sure that calls from the pods do not reach the instance metadata service
(IMDS) that AWS makes available on each EC2 instance.
An important point worth remembering is, since the IMDS runs
locally, you cannot use security groups to block these calls. You can
use software tools such as !!! iptables or local firewalls to block this
access.
- Try to Run Pods in a Private Subnet
I might be a little opinionated here, but I can’t think of too many instances where a
Kubernetes pod needs to have direct internet accessibility. Almost all of your access
should be streamlined via AWS API Gateway or some sort of an application load bal‐
ancer. Hence, your Kubernetes data plane should almost always run in a private sub‐
net away from where any attacker can gain access and compromise your pods.
API server endpoints are public by default, and API server access is secured via
identity and access management (IAM) and Kubernetes role-based access control
(RBAC). You should enable private access to your production cluster endpoints so
that all communication between your nodes and the API server stays within
your VPC.
- Block Internet Access for Pods Unless Necessary
Generally speaking, it is not too common for pods to connect to the internet. Hence,
a default strategy should be to block internet access for pods unless it is absolutely
necessary. This can be achieved by running pods inside subnets that do not have NAT
routers.
- Use Encrypted Networking Between Pods
This is a new feature that AWS has added in some EC2 Nitro instances. Nearly all
container-based applications use only clear text HTTP for traffic and let the load bal‐
ancers handle transport layer security (TLS). This is an acceptable trade-off. After all,
if your pods run in a private subnet in your own VPC, it is generally acceptable to
assume your network connections between pods are secure. But with the rise of zero
trust networking and the downfall of perimeters, there has been a growing demand
for secure networking, especially in the defense and financial sectors.
There are two ways of implementing encryption at the pod networking level. One is
to use marketplace solutions such as !!!Cilium, which offers secure networking. How‐
ever, this comes at a network speed cost since this process is not fast. Another way is
to use certain EC2 Nitro instances, which allow AES-encrypted networking when
communicating between other instances within the same VPC.

2.3.FaaS(Labada) and Network Security notes: 

However, if you decide to use Lambdas for setting up your internal microservices,
chances are, for quite a few of your applications, you will need to have access to
resources that live on your VPC. In order to provide security, this access needs to
happen on the private AWS network so that the communication is not exposed to
external threats. To achieve this goal, AWS allows you to configure your Lambdas to
run with any of your VPCs. For each function, Lambda will create an ENI for any
combination of security groups and VPC subnets in your function’s VPC configura‐
tion. The network interface creation happens when your Lambda function is created
or its VPC settings are updated. Invoking a function in the execution environment
simply !!!creates a network tunnel!!! and uses the network interface that is created for the
execution of this Lambda.

2.4.Public-Facing Services notes (We carate only private k8s cluster and use API Gateway+ALB/NLB(k8s use ingress for creating servcie type:Load Balancer) or directly use NLB/ALB) 

Example: NLB(end-to-end encription using TLS passtrough)/ALB + TLS/SSL offloading(not end-to-end encryption in transit)+k8s Servcies(Ingress controler)/Application Gateways+ALB/NLB/Application Gateways+Serice Mesh+mTLS(Istio/Consul)

By definition, a cleanly isolated backend service should never be accessible from the
public internet directly. The only two ways to get to the production backend services
are by using the following:
- An API gateway (which hosts the edge services)
For end users who want to interact with the application in controlled, predefined
ways
- Jump boxes or bastion hosts
For developers or maintenance use


API Gateway Integration - 1.AWS Lambda integrations/2.HTTP integration/3.VPC links
Once the API is ready for use by the consumer, the architects have to think about
how the edge services can start consuming backend microservices. This process of
linking a backend service with the API Gateway is called an integration process. The
service that integrates with the API Gateway as part of the integration process is
called an integration endpoint. An integration endpoint can be an AWS Lambda func‐
tion, an HTTP webpage, another AWS service, or a mock response that is used for
testing. There are two elements in each API integration: an integration request and an
integration response. Integration requests are encapsulations of request data sent to
the backend service as requests. AWS allows you to map incoming data into a request
body that is expected by the backend microservice that services this request. It might
be different from the method request submitted by the client. Likewise, an integration
response receives output from a backend application and can then be repackaged and
sent to the client. Figure 6-7 highlights this setup

VPC links (use this --> k8s integration)
While HTTP integrations work well in calling public HTTP endpoints, from a secu‐
rity perspective, you may not want to expose your entire microservice backend infra‐
structure to the public internet just for it to be accessible via the API Gateway. This is
where VPC links come into the picture. VPC links connect resources in a VPC to
edge endpoints that can be accessed via HTTP API routes. If your setup uses Amazon
Elastic Kubernetes Service (EKS) or any other Kubernetes setup, you can add a net‐
work load balancer (NLB) that can then route incoming requests to the right destina‐
tion pod.
The NLB can be a private NLB that lives entirely within your private VPC. This way,
API Gateway can allow controlled access to your private backend environment. A
VPC link also uses security groups to restrict unauthorized access.
For application load balancers (ALBs), you can use a VPC link for HTTP APIs. A
VPC link is created within each specified subnet, allowing your customers to access
the HTTP endpoints inside their private VPCs. Figure 6-10 shows how you can add a
VPC link to your accoun

Kubernetes microservices and API Gateway
With VPC links, API Gateway can now be extended to call all of your REST backend
services that run on private Kubernetes environments. These services can be running
inside your private VPC.
To connect these services to your API Gateway, you can create an NLB and have your
Kubernetes cluster as a target group for this load balancer. This setup is really no dif‐
ferent than any other Kubernetes setup. For further information on setting up Kuber‐
netes on AWS, AWS provides great documentation.
This setup is highlighted in Figure 6-11.

There are three types of authorizers that AWS supports natively, and each of them has
a different use case:
- API-based identity and access management (IAM) authorizer
- Cognito-based authorizer
- Lambda-based authorizer!!!!(---> use this: KeyCloack)

Lambda-based authorizer: This information can be present in the form of the following:
- A JWT that can be present and passed along with the request
- A combination of headers/request parameters that are passed along with the
incoming request

Protecting Against Common Attacks on Edge Networks
Although AWS CloudFront and AWS API Gateway provide you with a great way of
protecting your static assets and your microservices from threats on the internet, you
may still want to add additional controls around the entry points to your application’s
infrastructure. In this section, I will discuss two of the most commonly used controls Chapter 6: Public-Facing Servicesat the edge of your infrastructure: AWS Web Application Firewall (AWS WAF:OWASP + known good host ) and
AWS Shield(DDoS protection).


3.Data Security 


3.1.Security in-Rest (AWS KMS ---> S3, EBS (disks), Databases, FaaS:Lambda)

-  Preventing access to this data for unauthorized users through access control
-  Encrypting this data so unauthorized exposure of data will not be readable

Note: !!! Storage and DBs: Dont use centralized DB for all microservcie. Use own DB for every microservice or domain (microservcies by domain). Some services may benefit from a NoSQL database, while some
others may prefer to use a relational database management system
(RDBMS). A distributed and localized storage mechanism ensures
that you can use the best tool for the job. “Storage” could mean anything from a database system, application
events, flat files, media objects, cached data, binary large objects
(blobs), as well as container images. In contrast to monoliths where data is created and stored from one
application, microservices are fragmented, resulting in data that needs to be logically
separated from one another, to conform to different data protection policies across the
organization. !! Every microservice --> own DB/Storage and segmentation via Roles/Policies and Network controls. Loosly coupled --> can update some of microservcise DB vithout affecting other MS (if using shared DB between servcies not so posible- > “single points of failure (SPOFs) , we can use different shemes for MSs, but again if we need to update the whole shared DB we have to stop all microservcies, if we want to update only on DB (used only for one MS) it's is possible, without downtime for other MS).. These different storage objects are loosely coupled with
one another, much like the microservices themselves. It is common for these distributed storages to follow the rules of the bounded contexts (DD-Domain-Driven design) in which they reside. One Storage (DB,S3) to one domain(bunch of MS whit the same busines role: Reporting, Credut Balance Check/Auth MS, etc.)/Microservcie..

Note: Data Clsification via cloud Tags:
For example, the US
National Classification Scheme based on Executive Order 12356 recognizes three data
classifications: Confidential, Secret, and Top Secret. The UK government also has
three classifications: Official, Secret, and Top Secret.
On AWS, data can be classified by using AWS tags that I briefly talked about in
Chapter 2. AWS tags allow you to assign metadata to your cloud resources so the
administrators will be aware of the type of data these resources store. Using these
tags, !!!!conditional logic(policies) can be applied to access control to enforce security clearance
checks while granting access. For compliance validation, AWS tags can also help iden‐
tify and track resources that contain sensitive data. From a security perspective, you
should tag each and every resource within your account, especially if it stores sensi‐
tive data.

3.2.Security in-transit


- Security in-Transit(inter-MS comunication:TLS/SSL)

You can achieve interservice communication between microservices in many ways.
Here are some common communication patterns. This list is not exhaustive and not
mutually exclusive:
1. Using asynchronous representational state transfer (REST) (inter-MS vs REAST API calls)
2. Using messaging queues such as AWS Simple Queue Service (SQS) or message
brokers such as Apache Kafka (TLS betverrn producers/consumers and MQ/MB)
3. Using wrappers on top of HTTP or HTTP/2 such as Google Remote Procedure
Call (gRPC).
4. Using a service mesh such as Istio/Consul Mesh (mTLS: client & server certs verification two-ways) or the AWS-managed AWS App Mesh


Note: gRPC and Application Load Balancer: gRPC still uses HTTP/2 as its transport, so encryption on gRPC can
still be achieved using TLS as for most of the other HTTP connections. The TLS cer‐
tificate is installed on the ALB when the load balancer is chosen. Doing so will ensure
encrypted gRPC communication between the pods and the ALB.
TLS for gRPC can also be implemented using a service mesh


Notes: TLS/Servcie Mesh + mTLS

Let’s assume Service A needs to send sensitive information to the CCPS. There are
two ways in which malicious actors may try to steal this sensitive information:
- Phishing
An imposter could pretend to be the CCPS. If Service A has no way of identifying
the real CCPS, it may end up sending sensitive information to the imposter.
- Man in the middle
Another service could start snooping and recording all the data that is being
exchanged legitimately between Service A and CCPS and thus come across sensi‐
tive information.

TLS reduces the risk of these potential threats by helping you implement authentica‐
tion and encryption controls on the communication channels.
In the following section, I will explain in detail how authentication and encryption
work to reduce this risk:
- Authentication
The purpose of authentication is to identify and validate the identity of a server
in a communication channel. Under TLS, both parties, the client and the server,
agree to entrust the authentication task to a trusted party called a trusted certifi‐
cate authority (trusted CA). Through the use of digital certificates and public key
encryption, a trusted CA can verify the identity of the server to a client that has
trusted the CA. Server validation can help to prevent impersonation and phish‐
ing attacks.
- Encryption
Encryption aims to ensure that any communication between the service provider
and the service consumer cannot be accessed by a third party. This is done using
end-to-end encryption that TLS provides after a secure line has been established.
Through encryption, TLS can help prevent man-in-the-middle or communica‐
tion channel hijacking attacks.

- Certificates, Certificate Authority, and Identity Verification
TLS achieves authentication using public-key cryptography in the form of digital cer‐
tificates. Digital certificates are electronic documents that prove ownership of private
keys based on digital signatures. The certificate includes the public key of the server
(called the subject), which is digitally signed by a trusted third party. If this signature
of the third party is valid, then the client can trust the authenticity of the server’s pub‐
lic key and encrypt data using this public key. X.509 TLS certificates that bind a service (URL) to the public
key that is contained in the certificate. Think of a certificate as a driver’s license for
the URL that identifies the server.(Private key is used during issue of cert).CA: Essentially, it is stating, Trust that anything that can be
decrypted by this public key belongs to the domain listed on the certificate.
Every certificate owner should be careful to make sure that the private key backing
the certificate is never exposed. If exposed, the certificate should be immediately
revoked and a new certificate should be issued in its place.

- Encryption Using TLS
The second important role that TLS plays in any given system is to provide end-to-
end encryption of data that is in transit.
Contrary to popular belief, TLS in itself is not an encryption algorithm. TLS instead
defines certain steps that both the client and the server need to take in order to mutu‐
ally decide which cipher works best for communication between them.
In fact, one of the first steps of any TLS connection is a negotiation process where the
client and the server mutually agree on which cipher works best for both of them.
This information exchange happens during the phase of communication known as
TLS Handshake. TLS Handshake is also used to exchange encryption keys for end-to-
end encryption. This makes TLS Handshake one of the most crucial, yet often over‐
looked, aspects of communication between any two processes.
TLS Handshake
As mentioned, encryption using TLS is done using a symmetric key algorithm.
This means that both the server and the client use the same encryption key as well as
an encryption algorithm that they agree upon to encrypt the communication
channel with.
Various AWS services support a vast variety of ciphers, and the strongest cipher is
chosen based on a waterfall process of selection. A waterfall process is where the
server creates a list of ciphers that it supports in the descending order of strength.
The client agrees to use the strongest cipher that it can support within that list. Thus,
the server and the client mutually decide on what they believe is the best common
algorithm that is supported by both parties.
When an algorithm is selected, the client and the server have to agree on an encryp‐
tion key. They use a key exchange mechanism (such as the Diffie–Hellman key
exchange), to exchange encryption keys that can then be used to encrypt all the data
that needs to be sent over the channel.


- Mutual TLS
Mutual TLS (mTLS) is a slightly newer standard that is rapidly gaining popularity
among secure systems everywhere. TLS is discussed in detail in Chapter 7, but as an
overview, TLS helps validate the server using a standardized handshake and digital
certificates signed by trusted certificate authorities for each domain.
With traditional TLS, security measures are performed only by the server; mTLS
takes things a step further by asking the client to authenticate every request for each
HTTP request that is sent, thus increasing the security of the protocol.
To set up mTLS, you first need to create the private certificate authority and the client
certificates. For API Gateway to authenticate certificates using mTLS, you need the
public keys of the root certificate authority and any intermediate certificate
authorities. These need to be uploaded to API Gateway. Figure 6-17 shows the steps
required to enable mTLS for any custom domain endpoint that is served using API
Gateway. Chapter 6 introduced Mutual TLS (mTLS). Let’s now revisit the concept of mTLS and
I’ll explain how it makes communication more secure. The TLS protocol uses X.509
certificates to prove the identity of the server, but the application layer is responsible
for verifying the identity of the client to the server. mTLS attempts to make TLS more
secure by adding client validation as part of the TLS process.
As discussed in “TLS Handshake” on page 239, a client trusts a CA while the server
presents a certificate that is signed by the CA. Upon successful establishment of the
connection, both parties can communicate in an encrypted format. mTLS requires
that both the client and server establish their identities as part of the TLS Handshake.
This additional step ensures that the identities of both parties involved in a commu‐
nication process are established and confirmed. Certificate verification is an integral
part of the TLS Handshake. With the requirement for client validation, mTLS essen‐
tially mandates that clients are required to maintain a signed certificate that trusted
CAs vouch for, thus making client verification possible.
This would mean installing a signed certificate on each of the microservice clients
that wants to make any outgoing request, unlike a load balancer that could be used to
terminate TLS on the servers. An operation of this magnitude requires significant
investment in infrastructure and security in order to implement such a setup.
As a result of this added complexity and the amount of work required to implement
mTLS, it is rarely seen in setups that use traditional servers or container systems.
However, mTLS is significantly easier to implement when two AWS-managed services
talk to each other. This is why API Gateway and AWS Lambda can easily communi‐
cate with each other using mTLS.
The downside of mTLS is that it is complicated. However, the next
sections introduce an AWS service called AWS App Mesh, which
can make implementing mTLS more straightforward and thus
practical.


- Servcie Mesh (Data Plain (MS + Proxy:Envoy) + Control Plain(Certs update for proxies + control routing and virtual endpoints+ingresses)

Service1 ---> Proxy(Envoy) <-----> Proxy(envoy) <---> Service2 

When a mesh of proxies communicates with one another, the plane of microservices (known as the
data plane) is transformed into a virtual service plane.A control plane is a
mechanism that controls all the proxies by sending them instructions from a central‐
ized location.Istio, Consul, and Linkerd are just some of the many
popular service mesh solutions available in the market today, and each has great fea‐
tures to offer. However, AWS App Mesh does simplify the implementation of a service
mesh by integrating easily with the rest of the AWS infrastructure.
AWS provides a fully managed service that manages the control plane for this mesh
of envoy proxies in the form of AWS App Mesh. AWS App Mesh lets you
communicate across multiple applications, infrastructures, and cloud services using
application-level networking. App Mesh gives end-to-end visibility and high availa‐
bility for your applications. Figure 7-21 illustrates how a managed proxy controller
can help keep proxies in sync.
```
##### Examples Microservcie Architectures (PaaS/SaaS)
```
Example1 architecture (PaaS/SaaS): ---> Cloud API Gateway(Azure/AWS: Call Lambada for Auth-->Keyclack) ---> NLB/ALB (VPC Link:privite communication) ----> k8s (Ingress) -> KONG API Gateway(Node Port or k8s Ingress ---> call KeyCloack for autentification+Authrization) ---> Keycloack(IAM) (IAM authontification+authorization: 1.authentification:IdP + Identity Brocker(OpenID Connect + OAuth 2.0 (google), and SAML 2.0(microsoft AD)) + 2.authorization(based on realm: --> https://github.com/adavarski/k8s-UAP/tree/main/k8s/Demo7-SaaS --> Keycloak instance, used later for JupyterHub to authenticate users before provisioning JupyterLab instances for them.

 ---> Service Mesh/mTLS (Consul Mesh) (client-server certs verification - two way - Envoy + microserocervices(data plain) + Consul/ConsulGW(control plain) ) 
    

Example PaaS/SaaS with Keycloak for IAM:

- name: KEYCLOAK_FRONTEND_URL
      value: "https://sso.prod.example.com/auth"

spec:
  rules:
  - host: "kong.example.cloud"
# Specify Kong proxy service configuration
proxy:
  # Enable creating a Kubernetes service for the proxy
  enabled: true
  type: LoadBalancer


Example2 architecture (SaaS): (KeyCloack _ JupiterHub --> JupyterHub is configured to provision JupyterLab environments(Spark driver with jupyter inside + spark workers/executors we can run via SparkSession), authenticating against Keycloak. So SaaS is based on JupyterHub/Lab. Provision Tenant environment (Jupiter Lab) on SaaS namespace per user/tenant (Or ve can have provisioned environment per tenant and only use Keycloack to authenticate the user (we can use external IdP - and use Keyckloack as IdP using OAuth2 or use as Identiry Broker for external IdP: AD/Google(oauth)

Notes:

JupyterHub (per user/tenant) snip:

singleuser:
  image:
    name: davarski/spark301-k8s-minio-jupyter
    tag: 2.0.0
  defaultUrl: "/lab"

https://github.com/adavarski/k8s-UAP/blob/main/k8s/003-data/10000-jupterhub/values.yml

proxy:
  secretToken: "1cdb29d3a3fcfa658283830209647b2bb6bfb08d9e0bae6258bbb3315476f038"
  service:
    type: ClusterIP

singleuser:
  image:
    name: davarski/spark301-k8s-minio-jupyter
    tag: 2.0.0
  defaultUrl: "/lab"

hub:
  image:
    name: jupyterhub/k8s-hub
    tag: 0.9-dcde99a
  db:
    pvc:
      storageClassName: local-storage
  extraConfig:
    jupyterlab: |-
      c.Spawner.cmd = ['jupyter-labhub']
      c.KubeSpawner.namespace = "saas"
      c.KubeSpawner.service_account = "saas"
    jupyterhub: |-
      c.Authenticator.auto_login = True
  extraEnv:
    OAUTH2_AUTHORIZE_URL: https://auth.data.davar.com/auth/realms/saas/protocol/openid-connect/auth
    OAUTH2_TOKEN_URL: https://auth.data.davar.com/auth/realms/saas/protocol/openid-connect/token
    OAUTH_CALLBACK_URL: https://saas.data.davar.com/hub/oauth_callback

scheduling:
  userScheduler:
    enabled: true
    replicas: 2
    logLevel: 4
    image:
      name: gcr.io/google_containers/kube-scheduler-amd64
      tag: v1.14.4

auth:
  type: custom
  custom:
    className: oauthenticator.generic.GenericOAuthenticator
    config:
      login_service: "Keycloak"
      client_id: "saas"
      client_secret: "4ad1a28d-76b0-4304-af10-3a728265e151"
      token_url: https://auth.data.davar.com/auth/realms/saas/protocol/openid-connect/token
      userdata_url: https://auth.data.davar.com/auth/realms/saas/protocol/openid-connect/userinfo
      userdata_method: GET
      userdata_params: {'state': 'state'}
      username_key: preferred_username

```

