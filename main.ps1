param($Target, $Auth, $Domain, $Pool, [switch]$GenerateBind, $File, $Iterations, $Group)

$File = "config.json"

if ($File) {
    if (Test-Path -Path $File) {
        $Config = Get-Content $File | Out-String | ConvertFrom-Json
        $Target = $Config.Target      
        $Auth = $Config.Auth        
        $Domain = $Config.Domain      
        $Pool = $Config.Pool        
        $Group = $Config.Group       
        $GenerateBind = $Config.CreateBind
        $Loops = $Config.Iterations     
        $ZoneFile = $Config.ZoneFile       
        $NSRecord = $Config.NSRecord
    }
    else {
        Write-Error "$File does not exist"
    }
}

Import-Module $PSScriptRoot\proxmox.psm1 -force

$ProxmoxConfiguration = Get-PVEConnectionConfig -Target $Target -Authorization $Auth -Group $Group -Pool $Pool

for ($x = 0; $x -lt $Loops; $x++) {
    Write-Verbose ("Starting loop " + $x)

    $Remediations = Update-PVEHAConfig -ProxmoxConfiguration $ProxmoxConfiguration

    if ($Remediations) {
        $Remediations | ForEach-Object { 
            Write-Debug ("Running " + ($_.Remediation | ConvertTo-Json -Compress) + " to correct " + $_.Rule)
            Move-PVEVM -ProxmoxConfiguration $ProxmoxConfiguration -MoveData $_.Remediation
        }
        Start-Sleep -Seconds 30
    }
    else {
        Write-Verbose "No remediations found"
        $x = $Loops
    }
}

if ($GenerateBind) { Convertto-PVEBindZone -Domain $Domain -PrimaryDNS ("ns." + $Domain) -AdminEmail ("webmaster@" + $Domain)  -ProxmoxConfiguration $ProxmoxConfiguration -NSRecord $NSRecord | Out-File $ZoneFile }
