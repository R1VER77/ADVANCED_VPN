# One chain server on Azure (docs/INSTALL_AND_SETUP_PLAN.md phase 3, the provider contract):
# a Trusted Launch VM (secure boot and a virtual TPM, so its keys are TPM-sealed and it
# restarts unattended), first-boot user data, the tunnel port open only to the previous
# hop, a static public address, everything in one tagged resource group (teardown removes
# the group), and SSH only from the admin sources: the relay's address, so administration
# goes through the chain's own relay, never from your address.

terraform {
  required_version = ">= 1.13.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 5.13.0"
    }
  }
}

variable "name" {
  type = string
  validation {
    condition     = can(regex("^cpvpn-[a-z0-9-]{1,35}$", var.name))
    error_message = "name must start with cpvpn- and use a-z, 0-9 and -."
  }
}
variable "location" { type = string }
variable "size" {
  type    = string
  default = "Standard_B1s"
}
variable "port" { type = number }
variable "tunnel_sources" {
  type = list(string)
  validation {
    condition     = length(var.tunnel_sources) > 0
    error_message = "the previous hop's address is required."
  }
}
variable "tcp_fallback" {
  type    = bool
  default = false
}
variable "admin_sources" { type = list(string) }
variable "ssh_public_key" { type = string }
variable "user_data" {
  type        = string
  description = "first-boot user data, base64"
}
variable "address_space" {
  type    = string
  default = "10.77.110.0/24"
}

locals {
  tags = { "cpvpn-managed" = "true", "cpvpn-name" = var.name }
}

resource "azurerm_resource_group" "this" {
  name     = var.name
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.address_space]
  tags                = local.tags
}

resource "azurerm_subnet" "this" {
  name                 = var.name
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.address_space]
}

resource "azurerm_network_security_group" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  security_rule {
    name                       = "tunnel"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.port)
    source_address_prefixes    = var.tunnel_sources
    destination_address_prefix = "*"
    description                = "cypherpunk_vpn previous hop"
  }
  dynamic "security_rule" {
    for_each = var.tcp_fallback ? [1] : []
    content {
      name                       = "tunnel-tcp"
      priority                   = 110
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = tostring(var.port)
      source_address_prefixes    = var.tunnel_sources
      destination_address_prefix = "*"
      description                = "cypherpunk_vpn camouflage TLS fallback"
    }
  }
  security_rule {
    name                       = "admin-ssh"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.admin_sources
    destination_address_prefix = "*"
    description                = "admin SSH (from the relay only)"
  }
  # Azure's defaults admit traffic from the virtual network and its load balancer; an
  # explicit deny keeps the exit closed to everything not listed above.
  security_rule {
    name                       = "deny-other-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

resource "azurerm_public_ip" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = var.name
  location                        = var.location
  resource_group_name             = azurerm_resource_group.this.name
  size                            = var.size
  admin_username                  = "ubuntu"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.this.id]
  custom_data                     = var.user_data
  # Trusted Launch: secure boot and a virtual TPM. The host setup probes the TPM and seals
  # the VPN keys to it (systemd-creds host+tpm2), so the exit restarts on its own.
  secure_boot_enabled = true
  vtpm_enabled        = true
  tags                = local.tags

  admin_ssh_key {
    username   = "ubuntu"
    public_key = var.ssh_public_key
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 30
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

output "public_ip" { value = azurerm_public_ip.this.ip_address }
output "private_ip" { value = azurerm_network_interface.this.private_ip_address }
output "vm_id" { value = azurerm_linux_virtual_machine.this.id }
output "resource_group" { value = azurerm_resource_group.this.name }
