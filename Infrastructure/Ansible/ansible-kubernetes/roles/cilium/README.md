Ansible Role: cilium
=========

This role installs and configures an opinionated version of cilium on a kubernetes cluster using kubectl.
It also installs the Cilium CLI on master nodes for debugging purposes.


Requirements
------------

As the role will use kubectl directly, it is necessary that kubectl is properly configured on the first node in the inventory to successfully install cilium.
The role expects to find the master nodes to be in group `master`.


Role Variables
--------------

The role expects two variables, that must point to the k8s API endpoint (most likely the load balancer). This is needed for cilium to correctly interact with k8s.
| Variable | Description | Default Value |
| ----------- | ----------- | ----------- |
| k8s_api_host | Host to connect to for the k8s API | localhost |
| k8s_api_port | Port to connect to for the k8s API | 6443/443 |


Re-Create the configuration
--------------
The configuration files where created using the following command and replacing `REPLACE_WITH_API_SERVER_IP` with `{{ k8s_api_host }}` and `REPLACE_WITH_API_SERVER_PORT` with `{{ k8s_api_port }}` afterwards:
```
helm template cilium cilium/cilium --version 1.10.4 \
    --namespace kube-system \
    --set kubeProxyReplacement=strict \
    --set k8sServiceHost=REPLACE_WITH_API_SERVER_IP \
    --set k8sServicePort=REPLACE_WITH_API_SERVER_PORT
```


Example Playbook
----------------

A minimal playbook to run the role will look like so:
```
- name: install cilium on nodes
  hosts: all
  tasks:
    - include_role:
        name: cilium
```
