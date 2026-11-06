output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "location" {
  value = azurerm_resource_group.rg.location
}

output "subnet_id" {
  value = azurerm_subnet.my_terraform_subnet.id
}

output "nic_id" {
  value = azurerm_network_interface.my_terraform_nic.id
}

output "nsg_id" {
  value = azurerm_network_security_group.my_terraform_nsg.id
}

output "storage_account_name" {
  value = azurerm_storage_account.temen_os_sa.name
}

output "storage_container_name" {
  value = azurerm_storage_container.temen_os_container.name
}

output "storage_account_id" {
  value = azurerm_storage_account.temen_os_sa.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.temen_os_vm.name
}

output "public_ip_address" {
  value = azurerm_linux_virtual_machine.temen_os_vm.public_ip_address
}

output "tls_keyvault_name" {
  value = var.tls_keyvault_name
}

output "vm_principal_id" {
  value = azurerm_linux_virtual_machine.temen_os_vm.identity[0].principal_id
}
