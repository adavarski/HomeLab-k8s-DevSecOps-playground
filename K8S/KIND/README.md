## KIND local environment

References: 
- Calico : https://alexbrand.dev/post/creating-a-kind-cluster-with-calico-networking/ 
- Ingress: https://kind.sigs.k8s.io/docs/user/ingress/ 
- ServiceMesh: Linkerd/mTLS: https://linkerd.io/2.11/getting-started/
- LoadBalancer:  https://kind.sigs.k8s.io/docs/user/loadbalancer/
- Local Registry: https://kind.sigs.k8s.io/docs/user/local-registry/
- Private Registry: https://kind.sigs.k8s.io/docs/user/private-registries/
- Auditing: https://kind.sigs.k8s.io/docs/user/auditing/
- Kind in CI: https://github.com/kind-ci/examples


<img src="./KIND-diagram.png?raw=true" width="800">

KIND Source: https://github.com/kubernetes-sigs/kind (https://github.com/kubernetes-sigs/kind/tree/main/images/base)


### Install KIND
```
### Install docker, kubectl, etc.

### Instal KIND

$ curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.14.0/kind-linux-amd64 && chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind
```
### Create cluster (CNI=Calico, Enable ingress)

```
$ cat cluster-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
- role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16


$ kind create cluster --name devsecops --config cluster-config.yaml
```
Example Output:

```
$ kind create cluster --name devsecops --config cluster-config.yaml
Creating cluster "devsecops" ...
 ✓ Ensuring node image (kindest/node:v1.24.0) 🖼 
 ✓ Preparing nodes 📦 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing StorageClass 💾 
 ✓ Joining worker nodes 🚜 
Set kubectl context to "kind-devsecops"
You can now use your cluster with:

kubectl cluster-info --context kind-devsecops

Have a nice day! 👋

$ docker ps -a
CONTAINER ID        IMAGE                   COMMAND                  CREATED             STATUS              PORTS                                                                 NAMES
b1f0d34833c0        kindest/node:v1.24.0    "/usr/local/bin/entr…"   24 minutes ago      Up 24 minutes       0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 127.0.0.1:36409->6443/tcp   devsecops-control-plane
b2dfe90a04cb        kindest/node:v1.24.0    "/usr/local/bin/entr…"   24 minutes ago      Up 24 minutes                                                                             devsecops-worker
baea6d91feb6        kindest/node:v1.24.0    "/usr/local/bin/entr…"   27 minutes ago      Created                                                                                   kind-control-plane
ff1679781bbc        kindest/node:v1.24.0    "/usr/local/bin/entr…"   27 minutes ago      Created                                                                                   kind-worker


$ kind get kubeconfig --name="devsecops" > admin.conf
$ export KUBECONFIG=./admin.conf 
$ kubectl get node
NAME                      STATUS     ROLES           AGE     VERSION
devsecops-control-plane   NotReady   control-plane   10m     v1.24.0
devsecops-worker          NotReady   <none>          9m51s   v1.24.0

$ kubectl get pods -n kube-system
NAME                                              READY   STATUS    RESTARTS   AGE
coredns-6d4b75cb6d-8ltl7                          0/1     Pending   0          5m4s
coredns-6d4b75cb6d-crfxv                          0/1     Pending   0          5m4s
etcd-devsecops-control-plane                      1/1     Running   0          5m18s
kube-apiserver-devsecops-control-plane            1/1     Running   0          5m19s
kube-controller-manager-devsecops-control-plane   1/1     Running   0          5m19s
kube-proxy-4kcgw                                  1/1     Running   0          5m5s
kube-proxy-phc5j                                  1/1     Running   0          5m2s
kube-scheduler-devsecops-control-plane            1/1     Running   0          5m19s

$ kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
configmap/calico-config created
customresourcedefinition.apiextensions.k8s.io/bgpconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/bgppeers.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/blockaffinities.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/caliconodestatuses.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/clusterinformations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/felixconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworksets.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/hostendpoints.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamblocks.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamconfigs.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamhandles.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ippools.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipreservations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/kubecontrollersconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networksets.crd.projectcalico.org created
clusterrole.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrolebinding.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrole.rbac.authorization.k8s.io/calico-node created
clusterrolebinding.rbac.authorization.k8s.io/calico-node created
daemonset.apps/calico-node created
serviceaccount/calico-node created
deployment.apps/calico-kube-controllers created
serviceaccount/calico-kube-controllers created
poddisruptionbudget.policy/calico-kube-controllers created

$ kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
daemonset.apps/calico-node env updated

$ kubectl get pods -n kube-system
NAME                                              READY   STATUS    RESTARTS   AGE
calico-kube-controllers-6766647d54-5jpkc          1/1     Running   0          2m48s
calico-node-7457x                                 1/1     Running   0          41s
calico-node-ggrfn                                 1/1     Running   0          21s
coredns-6d4b75cb6d-8ltl7                          1/1     Running   0          14m
coredns-6d4b75cb6d-crfxv                          1/1     Running   0          14m
etcd-devsecops-control-plane                      1/1     Running   0          14m
kube-apiserver-devsecops-control-plane            1/1     Running   0          14m
kube-controller-manager-devsecops-control-plane   1/1     Running   0          14m
kube-proxy-4kcgw                                  1/1     Running   0          14m
kube-proxy-phc5j                                  1/1     Running   0          14m
kube-scheduler-devsecops-control-plane            1/1     Running   0          14m

$ kubectl -n kube-system get pods | grep calico-node
calico-node-7457x                                 1/1     Running   0          63s
calico-node-ggrfn                                 1/1     Running   0          43s

$ kubectl api-resources
$ kubectl api-resources|head

$ kubectl get node -o wide
NAME                      STATUS   ROLES           AGE     VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION     CONTAINER-RUNTIME
devsecops-control-plane   Ready    control-plane   4h56m   v1.24.0   172.17.0.3    <none>        Ubuntu 21.10   5.0.0-32-generic   containerd://1.6.4
devsecops-worker          Ready    <none>          4h56m   v1.24.0   172.17.0.2    <none>        Ubuntu 21.10   5.0.0-32-generic   containerd://1.6.4

```

### Ingress NGINX (other options: Ingress Kong/Contour/Ambassador)

```
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
namespace/ingress-nginx created
serviceaccount/ingress-nginx created
serviceaccount/ingress-nginx-admission created
role.rbac.authorization.k8s.io/ingress-nginx created
role.rbac.authorization.k8s.io/ingress-nginx-admission created
clusterrole.rbac.authorization.k8s.io/ingress-nginx created
clusterrole.rbac.authorization.k8s.io/ingress-nginx-admission created
rolebinding.rbac.authorization.k8s.io/ingress-nginx created
rolebinding.rbac.authorization.k8s.io/ingress-nginx-admission created
clusterrolebinding.rbac.authorization.k8s.io/ingress-nginx created
clusterrolebinding.rbac.authorization.k8s.io/ingress-nginx-admission created
configmap/ingress-nginx-controller created
service/ingress-nginx-controller created
service/ingress-nginx-controller-admission created
deployment.apps/ingress-nginx-controller created
job.batch/ingress-nginx-admission-create created
job.batch/ingress-nginx-admission-patch created
ingressclass.networking.k8s.io/nginx created
validatingwebhookconfiguration.admissionregistration.k8s.io/ingress-nginx-admission created

$ kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=90s
pod/ingress-nginx-controller-5458c46d7d-7mblv condition met
$ kubectl get ns
NAME                 STATUS   AGE
default              Active   48m
ingress-nginx        Active   65s
kube-node-lease      Active   49m
kube-public          Active   49m
kube-system          Active   49m
local-path-storage   Active   48m

$ kubectl get po -n ingress-nginx
NAME                                        READY   STATUS      RESTARTS   AGE
ingress-nginx-admission-create-5slj4        0/1     Completed   0          97s
ingress-nginx-admission-patch-fc2rz         0/1     Completed   1          97s
ingress-nginx-controller-5458c46d7d-7mblv   1/1     Running     0          97s

$ wget https://kind.sigs.k8s.io/examples/ingress/usage.yaml && mv usage.yaml ingress-usage.yaml
$ kubectl apply -f ./ingress-usage.yaml
pod/foo-app created
service/foo-service created
pod/bar-app created
service/bar-service created
ingress.networking.k8s.io/example-ingress created

$ kubectl get all 
NAME          READY   STATUS    RESTARTS   AGE
pod/bar-app   1/1     Running   0          83s
pod/foo-app   1/1     Running   0          83s

NAME                  TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/bar-service   ClusterIP   10.96.156.74    <none>        5678/TCP   83s
service/foo-service   ClusterIP   10.96.164.200   <none>        5678/TCP   83s
service/kubernetes    ClusterIP   10.96.0.1       <none>        443/TCP    52m
$ kubectl get ing
NAME              CLASS    HOSTS   ADDRESS     PORTS   AGE
example-ingress   <none>   *       localhost   80      93s

$ curl -s 127.0.0.1/foo | wc -l
1
$ curl -s 127.0.0.1/bar | wc -l
1
$ curl -s 127.0.0.1/bar 
bar
$ curl -s 127.0.0.1/foo
foo

```

### Network Policy (Example: Ingress)

```

$ cat np-deny-all.yaml 
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  
$ kubectl apply -f np-deny-all.yaml 
networkpolicy.networking.k8s.io/deny-all created

$ kubectl -n default describe netpol deny-all
Name:         deny-all
Namespace:    default
Created on:   2022-06-28 15:57:57 +0300 EEST
Labels:       <none>
Annotations:  <none>
Spec:
  PodSelector:     <none> (Allowing the specific traffic to all pods in this namespace)
  Allowing ingress traffic:
    <none> (Selected pods are isolated for ingress connectivity)
  Not affecting egress traffic
  Policy Types: Ingress

$ docker exec -it devsecops-control-plane bash
root@devsecops-control-plane:/# iptables -n -L -v
root@devsecops-control-plane:/# ps -ef
$ docker exec -it devsecops-worker bash
root@devsecops-worker:/# iptables -n -L -v 
root@devsecops-worker:/# ps -ef

$ curl --max-time 3 127.0.0.1/bar
curl: (28) Operation timed out after 3001 milliseconds with 0 bytes received


```

### Service Mesh: Linkerd/mTLS (Case Study: mTLS with Linkerd : https://linkerd.io/2.11/getting-started/)

```
$ curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
Downloading linkerd2-cli-stable-2.11.2-linux-amd64...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 44.7M  100 44.7M    0     0  8306k      0  0:00:05  0:00:05 --:--:--  9.9M
Download complete!

Validating checksum...
Checksum valid.

Linkerd stable-2.11.2 was successfully installed 🎉


Add the linkerd CLI to your path with:

  export PATH=$PATH:/home/davar/.linkerd2/bin

Now run:

  linkerd check --pre                     # validate that Linkerd can be installed
  linkerd install | kubectl apply -f -    # install the control plane into the 'linkerd' namespace
  linkerd check                           # validate everything worked!
  linkerd dashboard                       # launch the dashboard

Looking for more? Visit https://linkerd.io/2/tasks

$ export PATH=$PATH:/home/davar/.linkerd2/bin
$ linkerd check --pre
Linkerd core checks
===================

kubernetes-api
--------------
√ can initialize the client
√ can query the Kubernetes API

kubernetes-version
------------------
√ is running the minimum Kubernetes API version
√ is running the minimum kubectl version

pre-kubernetes-setup
--------------------
√ control plane namespace does not already exist
√ can create non-namespaced resources
√ can create ServiceAccounts
√ can create Services
√ can create Deployments
√ can create CronJobs
√ can create ConfigMaps
√ can create Secrets
√ can read Secrets
√ can read extension-apiserver-authentication configmap
√ no clock skew detected

linkerd-version
---------------
√ can determine the latest version
√ cli is up-to-date

Status check results are √

$ linkerd install | kubectl apply -f - 
namespace/linkerd created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-identity created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-identity created
serviceaccount/linkerd-identity created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-destination created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-destination created
serviceaccount/linkerd-destination created
secret/linkerd-sp-validator-k8s-tls created
validatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-sp-validator-webhook-config created
secret/linkerd-policy-validator-k8s-tls created
validatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-policy-validator-webhook-config created
clusterrole.rbac.authorization.k8s.io/linkerd-policy created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-destination-policy created
role.rbac.authorization.k8s.io/linkerd-heartbeat created
rolebinding.rbac.authorization.k8s.io/linkerd-heartbeat created
clusterrole.rbac.authorization.k8s.io/linkerd-heartbeat created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-heartbeat created
serviceaccount/linkerd-heartbeat created
customresourcedefinition.apiextensions.k8s.io/servers.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/serverauthorizations.policy.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/serviceprofiles.linkerd.io created
customresourcedefinition.apiextensions.k8s.io/trafficsplits.split.smi-spec.io created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-proxy-injector created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-proxy-injector created
serviceaccount/linkerd-proxy-injector created
secret/linkerd-proxy-injector-k8s-tls created
mutatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-proxy-injector-webhook-config created
configmap/linkerd-config created
secret/linkerd-identity-issuer created
configmap/linkerd-identity-trust-roots created
service/linkerd-identity created
service/linkerd-identity-headless created
deployment.apps/linkerd-identity created
service/linkerd-dst created
service/linkerd-dst-headless created
service/linkerd-sp-validator created
service/linkerd-policy created
service/linkerd-policy-validator created
deployment.apps/linkerd-destination created
Warning: batch/v1beta1 CronJob is deprecated in v1.21+, unavailable in v1.25+; use batch/v1 CronJob
cronjob.batch/linkerd-heartbeat created
deployment.apps/linkerd-proxy-injector created
service/linkerd-proxy-injector created
secret/linkerd-config-overrides created

$ kubectl get all -n linkerd
NAME                                          READY   STATUS    RESTARTS   AGE
pod/linkerd-destination-854665ffdd-2pq8d      3/4     Running   0          97s
pod/linkerd-identity-685dc4fd66-mrhtg         2/2     Running   0          97s
pod/linkerd-proxy-injector-848f4b78f9-v748g   1/2     Running   0          97s

NAME                                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/linkerd-dst                 ClusterIP   10.96.87.16     <none>        8086/TCP   97s
service/linkerd-dst-headless        ClusterIP   None            <none>        8086/TCP   97s
service/linkerd-identity            ClusterIP   10.96.163.49    <none>        8080/TCP   97s
service/linkerd-identity-headless   ClusterIP   None            <none>        8080/TCP   97s
service/linkerd-policy              ClusterIP   None            <none>        8090/TCP   97s
service/linkerd-policy-validator    ClusterIP   10.96.147.63    <none>        443/TCP    97s
service/linkerd-proxy-injector      ClusterIP   10.96.58.174    <none>        443/TCP    97s
service/linkerd-sp-validator        ClusterIP   10.96.180.177   <none>        443/TCP    97s

NAME                                     READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/linkerd-destination      0/1     1            0           97s
deployment.apps/linkerd-identity         1/1     1            1           97s
deployment.apps/linkerd-proxy-injector   0/1     1            0           97s

NAME                                                DESIRED   CURRENT   READY   AGE
replicaset.apps/linkerd-destination-854665ffdd      1         1         0       97s
replicaset.apps/linkerd-identity-685dc4fd66         1         1         1       97s
replicaset.apps/linkerd-proxy-injector-848f4b78f9   1         1         0       97s

NAME                              SCHEDULE      SUSPEND   ACTIVE   LAST SCHEDULE   AGE
cronjob.batch/linkerd-heartbeat   23 13 * * *   False     0        <none>          97s

$ linkerd check
Linkerd core checks
===================

kubernetes-api
--------------
√ can initialize the client
√ can query the Kubernetes API

kubernetes-version
------------------
√ is running the minimum Kubernetes API version
√ is running the minimum kubectl version

linkerd-existence
-----------------
√ 'linkerd-config' config map exists
√ heartbeat ServiceAccount exist
√ control plane replica sets are ready
√ no unschedulable pods
√ control plane pods are ready
√ cluster networks can be verified
√ cluster networks contains all node podCIDRs

linkerd-config
--------------
√ control plane Namespace exists
√ control plane ClusterRoles exist
√ control plane ClusterRoleBindings exist
√ control plane ServiceAccounts exist
√ control plane CustomResourceDefinitions exist
√ control plane MutatingWebhookConfigurations exist
√ control plane ValidatingWebhookConfigurations exist
√ proxy-init container runs as root user if docker container runtime is used

linkerd-identity
----------------
√ certificate config is valid
√ trust anchors are using supported crypto algorithm
√ trust anchors are within their validity period
√ trust anchors are valid for at least 60 days
√ issuer cert is using supported crypto algorithm
√ issuer cert is within its validity period
√ issuer cert is valid for at least 60 days
√ issuer cert is issued by the trust anchor

linkerd-webhooks-and-apisvc-tls
-------------------------------
√ proxy-injector webhook has valid cert
√ proxy-injector cert is valid for at least 60 days
√ sp-validator webhook has valid cert
√ sp-validator cert is valid for at least 60 days
√ policy-validator webhook has valid cert
√ policy-validator cert is valid for at least 60 days

linkerd-version
---------------
√ can determine the latest version
√ cli is up-to-date

control-plane-version
---------------------
√ can retrieve the control plane version
√ control plane is up-to-date
√ control plane and cli versions match

linkerd-control-plane-proxy
---------------------------
√ control plane proxies are healthy
√ control plane proxies are up-to-date
√ control plane proxies and cli versions match

Status check results are √

$ wget https://run.linkerd.io/emojivoto.yml && cat emojivoto.yml
$ curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/emojivoto.yml \
>   | kubectl apply -f -
namespace/emojivoto created
serviceaccount/emoji created
serviceaccount/voting created
serviceaccount/web created
service/emoji-svc created
service/voting-svc created
service/web-svc created
deployment.apps/emoji created
deployment.apps/vote-bot created
deployment.apps/voting created
deployment.apps/web created

$ kubectl get ns
NAME                 STATUS   AGE
default              Active   87m
emojivoto            Active   63s
ingress-nginx        Active   40m
kube-node-lease      Active   87m
kube-public          Active   87m
kube-system          Active   87m
linkerd              Active   10m
local-path-storage   Active   87m

$ kubectl get all -n emojivoto
NAME                            READY   STATUS    RESTARTS   AGE
pod/emoji-78594cb998-bxt5d      1/1     Running   0          75s
pod/vote-bot-786d75cf45-4s2rw   1/1     Running   0          75s
pod/voting-5f5b555dff-thwjj     1/1     Running   0          75s
pod/web-68cc8bc689-b4vj4        1/1     Running   0          74s

NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)             AGE
service/emoji-svc    ClusterIP   10.96.58.218    <none>        8080/TCP,8801/TCP   75s
service/voting-svc   ClusterIP   10.96.85.163    <none>        8080/TCP,8801/TCP   75s
service/web-svc      ClusterIP   10.96.208.127   <none>        80/TCP              75s

NAME                       READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/emoji      1/1     1            1           75s
deployment.apps/vote-bot   1/1     1            1           75s
deployment.apps/voting     1/1     1            1           75s
deployment.apps/web        1/1     1            1           75s

NAME                                  DESIRED   CURRENT   READY   AGE
replicaset.apps/emoji-78594cb998      1         1         1       75s
replicaset.apps/vote-bot-786d75cf45   1         1         1       75s
replicaset.apps/voting-5f5b555dff     1         1         1       75s
replicaset.apps/web-68cc8bc689        1         1         1       75s


$ kubectl get -n emojivoto deploy -o yaml | linkerd inject - | kubectl apply -f -

deployment "emoji" injected
deployment "vote-bot" injected
deployment "voting" injected
deployment "web" injected

deployment.apps/emoji configured
deployment.apps/vote-bot configured
deployment.apps/voting configured
deployment.apps/web configured

$ linkerd -n emojivoto check --proxy
Linkerd core checks
===================

kubernetes-api
--------------
√ can initialize the client
√ can query the Kubernetes API

kubernetes-version
------------------
√ is running the minimum Kubernetes API version
√ is running the minimum kubectl version

linkerd-existence
-----------------
√ 'linkerd-config' config map exists
√ heartbeat ServiceAccount exist
√ control plane replica sets are ready
√ no unschedulable pods
√ control plane pods are ready
√ cluster networks can be verified
√ cluster networks contains all node podCIDRs

linkerd-config
--------------
√ control plane Namespace exists
√ control plane ClusterRoles exist
√ control plane ClusterRoleBindings exist
√ control plane ServiceAccounts exist
√ control plane CustomResourceDefinitions exist
√ control plane MutatingWebhookConfigurations exist
√ control plane ValidatingWebhookConfigurations exist
√ proxy-init container runs as root user if docker container runtime is used

linkerd-identity
----------------
√ certificate config is valid
√ trust anchors are using supported crypto algorithm
√ trust anchors are within their validity period
√ trust anchors are valid for at least 60 days
√ issuer cert is using supported crypto algorithm
√ issuer cert is within its validity period
√ issuer cert is valid for at least 60 days
√ issuer cert is issued by the trust anchor

linkerd-webhooks-and-apisvc-tls
-------------------------------
√ proxy-injector webhook has valid cert
√ proxy-injector cert is valid for at least 60 days
√ sp-validator webhook has valid cert
√ sp-validator cert is valid for at least 60 days
√ policy-validator webhook has valid cert
√ policy-validator cert is valid for at least 60 days

linkerd-identity-data-plane
---------------------------
√ data plane proxies certificate match CA

linkerd-version
---------------
√ can determine the latest version
√ cli is up-to-date

linkerd-control-plane-proxy
---------------------------
√ control plane proxies are healthy
√ control plane proxies are up-to-date
√ control plane proxies and cli versions match

linkerd-data-plane
------------------
√ data plane namespace exists
√ data plane proxies are ready
√ data plane is up-to-date
√ data plane and cli versions match
√ data plane pod labels are configured correctly
√ data plane service labels are configured correctly
√ data plane service annotations are configured correctly
√ opaque ports are properly annotated

Status check results are √

$ kubectl -n emojivoto exec -it $(kubectl -n emojivoto get po -o name | grep voting)  -c voting-svc -- /bin/bash
root@voting-55d76f4bcb-qfs8n:/usr/local/bin# apt update
root@voting-55d76f4bcb-qfs8n:/usr/local/bin# apt install tshark
root@voting-55d76f4bcb-qfs8n:/usr/local/bin# dpkg-reconfigure wireshark-common
root@voting-55d76f4bcb-qfs8n:/usr/local/bin# chmod +x /usr/bin/dumpcap
root@voting-55d76f4bcb-qfs8n:/usr/local/bin# tshark -i any -d tcp.port==8080,ssl |grep -v 127.0.0.1

$ linkerd viz install | kubectl apply -f - # install the on-cluster metrics stack
namespace/linkerd-viz created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-metrics-api created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-metrics-api created
serviceaccount/metrics-api created
serviceaccount/grafana created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-prometheus created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-prometheus created
serviceaccount/prometheus created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-tap created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-tap-admin created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-tap created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-tap-auth-delegator created
serviceaccount/tap created
rolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-tap-auth-reader created
secret/tap-k8s-tls created
apiservice.apiregistration.k8s.io/v1alpha1.tap.linkerd.io created
role.rbac.authorization.k8s.io/web created
rolebinding.rbac.authorization.k8s.io/web created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-web-check created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-web-check created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-web-admin created
clusterrole.rbac.authorization.k8s.io/linkerd-linkerd-viz-web-api created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-linkerd-viz-web-api created
serviceaccount/web created
server.policy.linkerd.io/admin created
serverauthorization.policy.linkerd.io/admin created
server.policy.linkerd.io/proxy-admin created
serverauthorization.policy.linkerd.io/proxy-admin created
service/metrics-api created
deployment.apps/metrics-api created
server.policy.linkerd.io/metrics-api created
serverauthorization.policy.linkerd.io/metrics-api created
configmap/grafana-config created
service/grafana created
deployment.apps/grafana created
server.policy.linkerd.io/grafana created
serverauthorization.policy.linkerd.io/grafana created
configmap/prometheus-config created
service/prometheus created
deployment.apps/prometheus created
service/tap created
deployment.apps/tap created
server.policy.linkerd.io/tap-api created
serverauthorization.policy.linkerd.io/tap created
clusterrole.rbac.authorization.k8s.io/linkerd-tap-injector created
clusterrolebinding.rbac.authorization.k8s.io/linkerd-tap-injector created
serviceaccount/tap-injector created
secret/tap-injector-k8s-tls created
mutatingwebhookconfiguration.admissionregistration.k8s.io/linkerd-tap-injector-webhook-config created
service/tap-injector created
deployment.apps/tap-injector created
server.policy.linkerd.io/tap-injector-webhook created
serverauthorization.policy.linkerd.io/tap-injector created
service/web created
deployment.apps/web created
serviceprofile.linkerd.io/metrics-api.linkerd-viz.svc.cluster.local created
serviceprofile.linkerd.io/prometheus.linkerd-viz.svc.cluster.local created
serviceprofile.linkerd.io/grafana.linkerd-viz.svc.cluster.local created

$ linkerd check
Linkerd core checks
===================

kubernetes-api
--------------
√ can initialize the client
√ can query the Kubernetes API

kubernetes-version
------------------
√ is running the minimum Kubernetes API version
√ is running the minimum kubectl version

linkerd-existence
-----------------
√ 'linkerd-config' config map exists
√ heartbeat ServiceAccount exist
√ control plane replica sets are ready
√ no unschedulable pods
√ control plane pods are ready
√ cluster networks can be verified
√ cluster networks contains all node podCIDRs

linkerd-config
--------------
√ control plane Namespace exists
√ control plane ClusterRoles exist
√ control plane ClusterRoleBindings exist
√ control plane ServiceAccounts exist
√ control plane CustomResourceDefinitions exist
√ control plane MutatingWebhookConfigurations exist
√ control plane ValidatingWebhookConfigurations exist
√ proxy-init container runs as root user if docker container runtime is used

linkerd-identity
----------------
√ certificate config is valid
√ trust anchors are using supported crypto algorithm
√ trust anchors are within their validity period
√ trust anchors are valid for at least 60 days
√ issuer cert is using supported crypto algorithm
√ issuer cert is within its validity period
√ issuer cert is valid for at least 60 days
√ issuer cert is issued by the trust anchor

linkerd-webhooks-and-apisvc-tls
-------------------------------
√ proxy-injector webhook has valid cert
√ proxy-injector cert is valid for at least 60 days
√ sp-validator webhook has valid cert
√ sp-validator cert is valid for at least 60 days
√ policy-validator webhook has valid cert
√ policy-validator cert is valid for at least 60 days

linkerd-version
---------------
√ can determine the latest version
√ cli is up-to-date

control-plane-version
---------------------
√ can retrieve the control plane version
√ control plane is up-to-date
√ control plane and cli versions match

linkerd-control-plane-proxy
---------------------------
√ control plane proxies are healthy
√ control plane proxies are up-to-date
√ control plane proxies and cli versions match

Linkerd extensions checks
=========================

linkerd-viz
-----------
√ linkerd-viz Namespace exists
√ linkerd-viz ClusterRoles exist
√ linkerd-viz ClusterRoleBindings exist
√ tap API server has valid cert
√ tap API server cert is valid for at least 60 days
√ tap API service is running
√ linkerd-viz pods are injected
√ viz extension pods are running
√ viz extension proxies are healthy
√ viz extension proxies are up-to-date
√ viz extension proxies and cli versions match
√ prometheus is installed and configured correctly
√ can initialize the client
√ viz extension self-check

Status check results are √

$ linkerd viz dashboard &

Linkerd dashboard available at:
http://localhost:50750
Grafana dashboard available at:
http://localhost:50750/grafana
Opening Linkerd dashboard in the default browser
Using PPAPI flash.
Opening in existing browser session.


```

### LoadBalancer (MetalLB)

```
### Clean ingress

$ kubectl delete -f ingress-usage.yaml 
pod "foo-app" deleted
service "foo-service" deleted
pod "bar-app" deleted
service "bar-service" deleted
ingress.networking.k8s.io "example-ingress" deleted

$ kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.12.1/manifests/namespace.yaml
namespace/metallb-system created
$ kubectl get ns
NAME                 STATUS   AGE
default              Active   135m
emojivoto            Active   48m
ingress-nginx        Active   87m
kube-node-lease      Active   135m
kube-public          Active   135m
kube-system          Active   135m
linkerd              Active   57m
linkerd-viz          Active   21m
local-path-storage   Active   135m
metallb-system       Active   6s

$ kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.12.1/manifests/metallb.yaml
Warning: policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+
podsecuritypolicy.policy/controller created
podsecuritypolicy.policy/speaker created
serviceaccount/controller created
serviceaccount/speaker created
clusterrole.rbac.authorization.k8s.io/metallb-system:controller created
clusterrole.rbac.authorization.k8s.io/metallb-system:speaker created
role.rbac.authorization.k8s.io/config-watcher created
role.rbac.authorization.k8s.io/pod-lister created
role.rbac.authorization.k8s.io/controller created
clusterrolebinding.rbac.authorization.k8s.io/metallb-system:controller created
clusterrolebinding.rbac.authorization.k8s.io/metallb-system:speaker created
rolebinding.rbac.authorization.k8s.io/config-watcher created
rolebinding.rbac.authorization.k8s.io/pod-lister created
rolebinding.rbac.authorization.k8s.io/controller created
daemonset.apps/speaker created
deployment.apps/controller created

$ kubectl get pods -n metallb-system --watch
NAME                          READY   STATUS                       RESTARTS   AGE
controller-7476b58756-sfdm7   0/1     ContainerCreating            0          14s
speaker-rnrhs                 0/1     CreateContainerConfigError   0          14s
controller-7476b58756-sfdm7   0/1     Running                      0          17s
speaker-rnrhs                 0/1     Running                      0          24s
controller-7476b58756-sfdm7   1/1     Running                      0          30s
speaker-rnrhs                 1/1     Running                      0          40s
$ kubectl get pods -n metallb-system 
NAME                          READY   STATUS    RESTARTS   AGE
controller-7476b58756-sfdm7   1/1     Running   0          72s
speaker-rnrhs                 1/1     Running   0          72s

$ wget https://kind.sigs.k8s.io/examples/loadbalancer/metallb-configmap.yaml && mv metallb-configmap-carbon.yaml

### Edit metallb-configmap-davar.yaml

$ docker network inspect -f '{{.IPAM.Config}}' kind
[{172.17.0.0/16  172.17.0.1 map[]} {fc00:f853:ccd:e793::/64   map[]}]

$ cat metallb-configmap-carbon.yaml 
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 172.17.0.200-172.17.0.250

$ kubectl apply -f metallb-configmap-carbon.yaml 
configmap/config created

$ wget https://kind.sigs.k8s.io/examples/loadbalancer/usage.yaml && mv usage.yaml loadbalancer-usage.yaml
$ kubectl apply -f https://kind.sigs.k8s.io/examples/loadbalancer/usage.yaml
pod/foo-app created
pod/bar-app created
service/foo-service created

$ LB_IP=$(kubectl get svc/foo-service -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')

$ echo $LB_IP
172.17.0.200
$ curl ${LB_IP}:5678
foo
      
$ for _ in {1..10}; do
>   curl ${LB_IP}:5678
> done
foo
foo
bar
foo
bar
foo
foo
bar
bar
foo

$ kubectl get po --all-namespaces
NAMESPACE            NAME                                              READY   STATUS      RESTARTS       AGE
default              bar-app                                           1/1     Running     0              84m
default              foo-app                                           1/1     Running     0              84m
emojivoto            emoji-699d77c79-k4p2w                             2/2     Running     0              142m
emojivoto            vote-bot-b57689ffb-j475j                          2/2     Running     0              142m
emojivoto            voting-55d76f4bcb-qfs8n                           2/2     Running     0              142m
emojivoto            web-6c54d9554d-x4rvq                              2/2     Running     0              142m
ingress-nginx        ingress-nginx-admission-create-5slj4              0/1     Completed   0              3h5m
ingress-nginx        ingress-nginx-admission-patch-fc2rz               0/1     Completed   1              3h5m
ingress-nginx        ingress-nginx-controller-5458c46d7d-7mblv         1/1     Running     0              3h5m
kube-system          calico-kube-controllers-6766647d54-5jpkc          1/1     Running     0              3h41m
kube-system          calico-node-7457x                                 1/1     Running     0              3h39m
kube-system          calico-node-ggrfn                                 1/1     Running     0              3h39m
kube-system          coredns-6d4b75cb6d-8ltl7                          1/1     Running     0              3h52m
kube-system          coredns-6d4b75cb6d-crfxv                          1/1     Running     0              3h52m
kube-system          etcd-devsecops-control-plane                      1/1     Running     0              3h53m
kube-system          kube-apiserver-devsecops-control-plane            1/1     Running     0              3h53m
kube-system          kube-controller-manager-devsecops-control-plane   1/1     Running     0              3h53m
kube-system          kube-proxy-4kcgw                                  1/1     Running     0              3h52m
kube-system          kube-proxy-phc5j                                  1/1     Running     0              3h52m
kube-system          kube-scheduler-devsecops-control-plane            1/1     Running     0              3h53m
linkerd-viz          grafana-5595bcc798-ggpcs                          2/2     Running     0              119m
linkerd-viz          metrics-api-69d57b76db-rnj4l                      2/2     Running     0              119m
linkerd-viz          prometheus-5db449486f-579p8                       2/2     Running     0              119m
linkerd-viz          tap-57d4d8658d-6zkjk                              2/2     Running     0              119m
linkerd-viz          tap-injector-67986c5574-r9q7g                     2/2     Running     0              119m
linkerd-viz          web-685d6f9457-2q5g9                              2/2     Running     0              119m
linkerd              linkerd-destination-854665ffdd-2pq8d              4/4     Running     0              155m
linkerd              linkerd-identity-685dc4fd66-mrhtg                 2/2     Running     0              155m
linkerd              linkerd-proxy-injector-848f4b78f9-v748g           2/2     Running     1 (153m ago)   155m
local-path-storage   local-path-provisioner-9cd9bd544-wwlk6            1/1     Running     0              3h52m
metallb-system       controller-7476b58756-sfdm7                       1/1     Running     0              97m
metallb-system       speaker-rnrhs                                     1/1     Running     0              97m

```

### Clean environment

```
$ kind delete cluster --name=devsecops

$ kind delete cluster --name=devsecops
Deleting cluster "devsecops" ...
[1]+  Killed                  linkerd viz dashboard
```

