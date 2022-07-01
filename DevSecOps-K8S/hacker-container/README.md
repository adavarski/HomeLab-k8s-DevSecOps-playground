# Hacker Container

The Swiss Army Container for Cloud Native Security. Container with all the list of useful tools/commands while hacking and securing Containers, Kubernetes Clusters, and Cloud Native workloads.

Container with all the list of useful tools/commands while hacking Kubernetes Clusters. 


* List of the tools/commands/utilities available in container are **[list.todo](list.todo)**

TODO: Fix GOLang -> Dockerfile.ORIG for kube-bench, gobuster, kubeletctl installation.

  
```
go: go.mod file not found in current directory or any parent directory.
	'go get' is no longer supported outside a module.
	To build and install a command, use 'go install' with a version,
	like 'go install example.com/cmd@latest'
	For more information, see https://golang.org/doc/go-get-install-deprecation
	or run 'go help get' or 'go help install'.
The command '/bin/sh -c apk add --no-cache git     && go get github.com/aquasecurity/kube-bench     && go get github.com/OJ/gobuster     && git clone https://github.com/cyberark/kubeletctl     && cd kubeletctl && go get github.com/mitchellh/gox     && go mod vendor && go fmt ./... && mkdir -p build     && GOFLAGS=-mod=vendor gox -ldflags "-s -w" --osarch="linux/amd64" -output "build/kubeletctl_{{.OS}}_{{.Arch}}"' returned a non-zero code: 1

```

## How to use Hacker Container


* Just run the following command to explore in the docker container environments

```bash
docker run --rm -it davarski/hacker-container
```

* To deploy as a Pod in Kubernetes cluster run the following command

```bash
kubectl run -it hacker-container --image=davarski/hacker-container
```

> This container can be used in different ways in different environments, it aids your penetration testing or security assessments of container and Kubernetes cluster environments.


