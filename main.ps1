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

Import-Module $PSScriptRoot\proxmox.psm1 

function New-bindconfig {
    param($Domain, $PrimaryDNS, $AdminEmail, $TTL = 600, $ServiceData, $VMData, $NSRecord)
    $file = '$TTL 86400' + [System.Environment]::NewLine
    $file += "@`tIN`tSOA`t$PrimaryDNS`.`t$AdminEmail`. (" + [System.Environment]::NewLine
    $file += "`t`t`t`t`t`t" + (Get-Date -Format yyyyMMdd) + "01" + [System.Environment]::NewLine
    $file += "`t`t`t`t`t`t" + [math]::Round(($TTL * .5), 0) + [System.Environment]::NewLine
    $file += "`t`t`t`t`t`t" + [math]::Round(($TTL * .25), 0) + [System.Environment]::NewLine
    $file += "`t`t`t`t`t`t" + $TTL + [System.Environment]::NewLine
    $file += "`t`t`t`t`t`t" + [math]::Round(($TTL * .9), 0) + [System.Environment]::NewLine
    $file += "`t`t)" + [System.Environment]::NewLine
    $file += "`t`t" + "NS`t$PrimaryDNS`." + [System.Environment]::NewLine
    $file += "`$ORIGIN" + "`t$Domain`." + [System.Environment]::NewLine
    $file += [System.Environment]::NewLine
    if ($ServiceData.Service -notcontains "ns") {
        if ($NSRecord) {
            $NSRecord | ForEach-Object { $file += ("ns`tIN`tA`t" + $NSRecord + [System.Environment]::NewLine) }
        }
        else {
            $PrimaryInterface = Get-NetIPInterface | Sort-Object interfacemetric | Where-Object { $_.connectionstate -eq "connected" } | Select-Object -first 1 -ExpandProperty InterfaceIndex
            $PrimaryIP = (Get-NetIPAddress -ifIndex $PrimaryInterface | Where-Object { $_.AddressFamily -eq "IPv4" }).ipaddress
            $file += ("ns`tIN`tA`t" + $PrimaryIP + [System.Environment]::NewLine)
        }
    }
    $VMData | ForEach-Object { $file += ($_.name + "`tIN`tA`t" + $_.ip_addresses + [System.Environment]::NewLine) }
    $ServiceData | ForEach-Object {
        $ServiceName = $_.Service
        $_.Components | ForEach-Object { $file += ($ServiceName + "`tIN`tA`t" + $_.ip_addresses + [System.Environment]::NewLine) }
    }
    $file
}

$ProxmoxConfiguration = Get-ProxmoxConnectionConfig -Target $Target -Authorization $Auth -Pool $Pool

for ($x = 0; $x -lt $Loops; $x++) {
    Write-Verbose ("Starting loop " + $x)
    $NodeData = Get-NodeData -ProxmoxConfiguration $ProxmoxConfiguration -Group $Group
    Write-Verbose ("Found: " + @($NodeData.nodes).Count + " nodes")
    $VMData = Get-ManagedVMs -ProxmoxConfiguration $ProxmoxConfiguration -Pool $Pool
    Write-Verbose ("Found: " + @($VMData).Count + " VMs")
    $ServiceData = Get-ServiceData -ManagedVMs $VMData
    Write-Verbose ("Found: " + @($ServiceData).Count + " services") 

    $Remediations = Update-HAConfig -NodeData $NodeData -ServiceData $ServiceData -VMData $VMData
    if ($Remediations) {
        $Remediations | ForEach-Object { 
            Write-Debug ("Running " + $_.Remediation + " to correct " + $_.Rule)
            Move-VM -ProxmoxConfiguration $ProxmoxConfiguration -MoveData ($_.Remediation | ConvertFrom-Json) 
        }
        Start-Sleep -Seconds 30
    }
    else {
        Write-Verbose "No remediations found"
        $x = $Loops
    }
}

if ($GenerateBind) { New-bindconfig -Domain $Domain -PrimaryDNS ("ns." + $Domain) -AdminEmail ("webmaster@" + $Domain) -ServiceData $ServiceData -VMData $VMData | Out-File $ZoneFile }
