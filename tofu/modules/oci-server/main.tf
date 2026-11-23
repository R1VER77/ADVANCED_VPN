# One chain server on Oracle Cloud (docs/INSTALL_AND_SETUP_PLAN.md phase 3, the provider
# contract): a server from an image with first-boot user data, the tunnel port open only to
# the previous hop, a public address, everything tagged for teardown, and SSH only from
# the given admin sources (an OCI bastion's private endpoint, never your own address).
#
# Discovery (home region, availability domain, image, a free /24, the bastion endpoint)
# stays in tools/cloud.py's planner; this module owns the resources it creates. It mirrors
# `cypherpunk cloud oci server` (cloud.py oci_server_apply) resource for resource.

terraform {
  required_version = ">= 1.13.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "= 9.12.1"
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
variable "compartment_id" { type = string }
variable "vcn_id" {
  type        = string
  description = "an existing VCN (a free tenancy has two); empty creates one"
  default     = ""
}
variable "internet_gateway_id" {
  type    = string
  default = ""
}
variable "subnet_cidr" { type = string }
variable "vcn_cidr" {
  type    = string
  default = "10.77.100.0/24"
}
variable "availability_domain" { type = string }
variable "shape" { type = string }
variable "ocpus" {
  type    = number
  default = 1
}
variable "memory_gb" {
  type    = number
  default = 6
}
variable "image_id" { type = string }
variable "port" { type = number }
variable "tunnel_sources" {
  type = list(string)
  validation {
    condition     = length(var.tunnel_sources) > 0
    error_message = "the previous hop's address is required."
  }
}
variable "tcp_fallback" {
  type        = bool
  description = "a first hop also takes its port on TCP (the camouflage's TLS fallback)"
  default     = false
}
variable "admin_sources" { type = list(string) }
variable "bastion_plugin" {
  type    = bool
  default = false
}
variable "ssh_public_key" { type = string }
variable "user_data" {
  type        = string
  description = "first-boot user data, base64"
}

locals {
  tags     = { "cpvpn-managed" = "true", "cpvpn-name" = var.name }
  own_vcn  = var.vcn_id == ""
  vcn_id   = local.own_vcn ? oci_core_vcn.own[0].id : var.vcn_id
  gateway  = local.own_vcn ? oci_core_internet_gateway.own[0].id : var.internet_gateway_id
  flexible = endswith(var.shape, ".Flex")
}

resource "oci_core_vcn" "own" {
  count          = local.own_vcn ? 1 : 0
  compartment_id = var.compartment_id
  cidr_blocks    = [var.vcn_cidr]
  display_name   = var.name
  freeform_tags  = local.tags
}

resource "oci_core_internet_gateway" "own" {
  count          = local.own_vcn ? 1 : 0
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.own[0].id
  enabled        = true
  display_name   = var.name
  freeform_tags  = local.tags
}

resource "oci_core_route_table" "this" {
  compartment_id = var.compartment_id
  vcn_id         = local.vcn_id
  display_name   = var.name
  freeform_tags  = local.tags
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = local.gateway
  }
}

resource "oci_core_security_list" "this" {
  compartment_id = var.compartment_id
  vcn_id         = local.vcn_id
  display_name   = var.name
  freeform_tags  = local.tags
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }
  dynamic "ingress_security_rules" {
    for_each = var.tunnel_sources
    content {
      protocol    = "17"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      stateless   = false
      description = "cypherpunk_vpn previous hop"
      udp_options {
        min = var.port
        max = var.port
      }
    }
  }
  dynamic "ingress_security_rules" {
    for_each = var.tcp_fallback ? var.tunnel_sources : []
    content {
      protocol    = "6"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      stateless   = false
      description = "cypherpunk_vpn camouflage TLS fallback"
      tcp_options {
        min = var.port
        max = var.port
      }
    }
  }
  dynamic "ingress_security_rules" {
    for_each = var.admin_sources
    content {
      protocol    = "6"
      source      = ingress_security_rules.value
      source_type = "CIDR_BLOCK"
      stateless   = false
      description = "admin SSH"
      tcp_options {
        min = 22
        max = 22
      }
    }
  }
}

resource "oci_core_subnet" "this" {
  compartment_id             = var.compartment_id
  vcn_id                     = local.vcn_id
  cidr_block                 = var.subnet_cidr
  route_table_id             = oci_core_route_table.this.id
  security_list_ids          = [oci_core_security_list.this.id]
  prohibit_public_ip_on_vnic = false
  display_name               = var.name
  freeform_tags              = local.tags
}

resource "oci_core_instance" "this" {
  availability_domain = var.availability_domain
  compartment_id      = var.compartment_id
  shape               = var.shape
  display_name        = var.name
  freeform_tags       = local.tags

  dynamic "shape_config" {
    for_each = local.flexible ? [1] : []
    content {
      ocpus         = var.ocpus
      memory_in_gbs = var.memory_gb
    }
  }
  source_details {
    source_type = "image"
    source_id   = var.image_id
  }
  create_vnic_details {
    subnet_id        = oci_core_subnet.this.id
    assign_public_ip = true
  }
  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = var.user_data
  }
  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }
  agent_config {
    # Managed SSH sessions through an OCI bastion need this plugin on the instance.
    plugins_config {
      name          = "Bastion"
      desired_state = var.bastion_plugin ? "ENABLED" : "DISABLED"
    }
  }
}

output "instance_id" { value = oci_core_instance.this.id }
output "public_ip" { value = oci_core_instance.this.public_ip }
output "private_ip" { value = oci_core_instance.this.private_ip }
output "subnet_id" { value = oci_core_subnet.this.id }
output "security_list_id" { value = oci_core_security_list.this.id }
output "route_table_id" { value = oci_core_route_table.this.id }
