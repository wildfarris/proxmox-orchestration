Import-Module $PSScriptRoot\proxmox.psm1 -force

$ProxmoxConfiguration = Get-PVEConfiguration -File "config.json"

Optimize-PVEResourceBalance -ProxmoxConfiguration $ProxmoxConfiguration
if ($ProxmoxConfiguration.CreateBind) { 
    $Domain = $ProxmoxConfiguration.Domain
    Convertto-PVEBindZone -PrimaryDNS "ns.$Domain" -AdminEmail "webmaster@$Domain" -ProxmoxConfiguration $ProxmoxConfiguration -OutFile
}
