#Variables
variable "kmaster_config" {
  description = "kmaster config"
  type = object({
    onboot  = bool
    memory  = number
    sockets = number
    cores   = number
    count   = number
  })
  default = {
    onboot  = false
    memory  = 4096
    sockets = 1
    cores   = 4
    count   = 1
  }
}

variable "kworker_config" {
  description = "kworker config"
  type = object({
    onboot  = bool
    memory  = number
    sockets = number
    cores   = number
    count   = number
  })
  default = {
    onboot  = false
    memory  = 2048
    sockets = 1
    cores   = 2
    count   = 2
  }
}

variable "common_configs" {
  description = "Common configs between all nodes"
  type = object({
    agent         = number
    network_model = string
    disk_type     = string
  })
  default = {
    agent         = 1
    network_model = "virtio"
    disk_type     = "sata"
  }
}

variable "PROXMOX_NODE" {
  description = "Node to use for VM creation in proxmox"
  type        = string
}

variable "PROXMOX_API_ENDPOINT" {
  description = "API endpoint for proxmox"
  type        = string
}

variable "PROXMOX_USERNAME" {
  description = "User name used to login proxmox"
  type        = string
}

variable "PROXMOX_PASSWORD" {
  description = "Password used to login proxmox"
  type        = string
}

variable "DEFAULT_BRIDGE" {
  description = "Bridge to use when creating VMs in proxmox"
  type        = string
}

variable "DEFAULT_BRIDGE_TAG" {
  description = "Bridge VLAN to use when creating VMs in proxmox"
  type        = string
}

variable "CLONE_TEMPLATE" {
  description = "Name of your template"
  type        = string
}

variable "TEMPLATE_USERNAME" {
  description = "Username that's configured in your cloud-init template VM in proxmox"
  type        = string
}

variable "NAMESERVER" {
  description = "Default nameserver that you might want to configure for all your VMs"
  type        = string
}

variable "BOOT_ORDER" {
  description = "Boot Order to use when booting all cloned VMs"
  type        = string
}

