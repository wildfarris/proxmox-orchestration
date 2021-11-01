$File = "config.json"

$Config = Get-Content $File | Out-String | ConvertFrom-Json
$Domain = $Config.Domain
$GenerateBind = $Config.CreateBind
$Loops = $Config.Iterations
$ZoneFile = $Config.ZoneFile
$NSRecord = $Config.NSRecord

Import-Module $PSScriptRoot\proxmox.psm1 -force

$ProxmoxConfiguration = Get-PVEConfiguration -File $File

Optimize-PVEResourceBalance -ProxmoxConfiguration $ProxmoxConfiguration -Loops $Loops

if ($GenerateBind) { Convertto-PVEBindZone -Domain $Domain -PrimaryDNS ("ns." + $Domain) -AdminEmail ("webmaster@" + $Domain)  -ProxmoxConfiguration $ProxmoxConfiguration -NSRecord $NSRecord | Out-File $ZoneFile }

#Convertto-PVEBindZone @($Config | select domain,NSRecord) -PrimaryDNS ("ns." + $Domain) -AdminEmail ("webmaster@" + $Domain) -ProxmoxConfiguration $ProxmoxConfiguration 