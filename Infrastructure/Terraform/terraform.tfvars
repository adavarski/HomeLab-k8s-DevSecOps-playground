PROXMOX_API_ENDPOINT = "https://192.168.1.99:8006/api2/json"
PROXMOX_USERNAME = "root@pam"
PROXMOX_PASSWORD = "XXXXXXXXX"
PROXMOX_NODE = "pve"
DEFAULT_BRIDGE = "vmbr1"
DEFAULT_BRIDGE_TAG = "200"
CLONE_TEMPLATE = "k8s-node"
TEMPLATE_USERNAME = "root"
NAMESERVER = "8.8.8.8"
# If your boot disk is not of type virtio Block, update the boot order to use your boot device
BOOT_ORDER = "order=virtio0;net0;ide2"