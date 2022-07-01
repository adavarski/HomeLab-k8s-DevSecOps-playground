Alpine Container Tools Docker Image
--

I had a need for an image with some container tools in it which doesn't run as root. So this is it :)

Based on alpine to keep the image nice and small.



Tools installed
--
- nmap
- curl
- etcd
- kubectl
- docker client
- boltbrowser
- oc
- amicontained


Running Instructions
--
`docker run -it davarski/alpine-noroot-containertools /bin/sh`
