function New-ProxmoxConfiguration {
    $Target = Read-Host -Prompt "Proxmox Server? "
    if(!$Target){Write-Error "Must provide a value" -ErrorAction Stop}
    $ProxmoxToken = Read-Host -Prompt "Proxmox API Token (Format: PVEAPIToken=<USERNAME>@<REALM>!<API-TOKEN-NAME>=<SECRET>)? "
    if(!$ProxmoxToken){Write-Error "Must provide a value" -ErrorAction Stop}
    $PoolName = Read-Host -Prompt "Proxmox resource pool name? "
    if(!$PoolName){Write-Error "Must provide a value" -ErrorAction Stop}
    $HostGroup = Read-Host -Prompt "Proxmox host group name? "
    if(!$HostGroup){Write-Error "Must provide a value" -ErrorAction Stop}
    $Iterations = Read-Host -Prompt "How many times should Agmen iterate? (Default: 20)"
    if(!$Iterations){$Iterations = 20}
    $CreateBind = Read-Host -Prompt "Create bind zone file? (y/N) " 
    if($CreateBind -eq "y"){
        $DNSDomain = Read-Host -Prompt "DNS Domain for bind zone file? "
        if(!$DNSDomain){Write-Error "Must provide a value" -ErrorAction Stop}
        $ZoneFile = Read-Host -Prompt "File path to create zone file? "
        if(!$DNSDomain){Write-Error "Must provide a value" -ErrorAction Stop}
        $CreateBind = $true
    } else {
        $CreateBind = $false
        $DNSDomain = $false
    }
    
    $ProxmoxConfiguration = New-Object -TypeName psobject -Property @{
        Target     = $Target
        Auth       = $ProxmoxToken
        Pool       = $PoolName
        Group      = $HostGroup
        CreateBind = $CreateBind
        Domain     = $DNSDomain
        ZoneFile   = $ZoneFile
    }

    Write-Verbose ("Configuration read: " + ($ProxmoxConfiguration | ConvertTo-Json -Compress))
    
    ConvertTo-Json $ProxmoxConfiguration
}

function Get-ProxmoxConnectionConfig {
    param($File, $Target, $Authorization, $Format = "json")
    if($File){
        if(Test-Path -Path $File){
            $Config = Get-Content $File | Out-String | ConvertFrom-Json
            $Target = $Config.Target
            $Authorization = $Config.Auth
        } else{
            Write-Error "$File does not exist"
        }
    }
    if ($Target -and $Authorization) {
        $Config = New-Object -TypeName psobject -Property @{
            Auth   = $Authorization
            Target = $Target
            Format = $Format
        }
    } else {
        Write-Error "Missing required parameters. Must have -File or both -Target and -Authorization"
    }
    
    Write-Verbose ("Configuration read: " + ($Config | ConvertTo-Json -Compress))
    $Config

}

function Invoke-ProxmoxCall {
    param($ProxmoxConfiguration, $Endpoint, $Method = "GET", $Body)

    $Uri = $ProxmoxConfiguration.Target + "/api2/" + $ProxmoxConfiguration.Format + "/" + $Endpoint

    Write-Verbose ("Making call to: " + $Uri)
    if($Body) { Write-Verbose ("Call body: " + $Body) }

    try {
        if($PSVersionTable.PSVersion.Major -lt 7){
            $response = Invoke-RestMethod -Method $Method -Headers @{Authorization = $ProxmoxConfiguration.Auth} -Body $Body -Uri $Uri
        } else{
            $response = Invoke-RestMethod -Method $Method -Headers @{Authorization = $ProxmoxConfiguration.Auth} -Body $Body -Uri $Uri -SkipHeaderValidation
        }
    }
    catch {
        $_.Exception.Response.StatusCode.Value__ 
    }

    Write-Verbose ("Call response: " + ($response | ConvertTo-Json -Compress))
    $response | Select-Object -expand data
}

function Get-ManagedVMs {
    param($ProxmoxConfiguration, $Pool)

    $ManagedVMs = Invoke-ProxmoxCall -ProxmoxConfiguration $ProxmoxConfiguration -Endpoint "pools/$Pool" | Select-Object -ExpandProperty members

    $return = $ManagedVMs | ForEach-Object {
        $node = $_.node
        $id = $_.id

        $Ignored_IPs = @("127.0.0.1", "172.17.0.1")
        $results = Invoke-ProxmoxCall -ProxmoxConfiguration $ProxmoxConfiguration -Endpoint "nodes/$node/$id/agent/network-get-interfaces"
        $ipaddresses = $results.result."ip-addresses" | Where-Object { $_."ip-address-type" -eq "ipv4" -and $_."ip-address" -notin $Ignored_IPs } | Select-Object -ExpandProperty ip-address
        if (!$ipaddresses) { $ipaddresses = "0.0.0.0" }

        Add-Member -InputObject $_ -Name "ip_addresses" -Value $ipaddresses -MemberType NoteProperty -PassThru -Force
    } 

    Write-Verbose ("Managed VM data: " + ($return | ConvertTo-Json -Compress))
    $return
}

function Get-ServiceData {
    param($ManagedVMs)

    $Services = $ManagedVMs | Where-Object { $_.name -like "*-*" } | Select-Object -ExpandProperty name | ForEach-Object { $_ -split "-" | Select-Object -First 1 } | Sort-Object -Unique

    $return = $Services | ForEach-Object {
        $ServiceName = $_
        $Components = $ManagedVMs | Where-Object { $_.name -like "$ServiceName-*" }
        
        New-Object -TypeName psobject -Property @{
            Service    = $ServiceName
            Components = $Components | Select-Object vmid, node, name, ip_addresses, mem, cpu
        }
    }

    Write-Verbose ("Service data: " + ($return | ConvertTo-Json -Compress))
    $return
}

function Get-NodeData {
    param ($ProxmoxConfiguration)
    $data = Invoke-ProxmoxCall -ProxmoxConfiguration $ProxmoxConfiguration -Endpoint "nodes" 
    $ManagedNodes = (Invoke-ProxmoxCall -ProxmoxConfiguration $ProxmoxConfiguration -Endpoint "cluster/ha/groups/Agmen").nodes -split ","

    $nodes = $data | Where-Object { $_.node -in $ManagedNodes } | ForEach-Object {
        New-Object -TypeName psobject -Property @{
            name    = $_.node
            uptime  = $_.uptime
            status  = $_.status
            maxmem  = $_.maxmem
            usedmem = $_.mem
        }
    }

    $return = New-Object -TypeName psobject -Property @{
        nodes   = $nodes
        maxmem  = $nodes | Measure-Object -Sum -Property maxmem | Select-Object -ExpandProperty Sum
        usedmem = $nodes | Measure-Object -Sum -Property usedmem | Select-Object -ExpandProperty Sum
    }
    
    Write-Verbose ("Node data: " + ($return | ConvertTo-Json -Compress))
    $return
}

function New-Remediation {
    param($Remediation)
    New-Object -TypeName psobject -Property $Remediation | Select-Object FromNode, ToNode, VM | ConvertTo-Json -Compress
}

function Update-HAConfig {
    param($NodeData, $ServiceData, $VMData)
    $MaxHA = $NodeData.nodes.Count

    $HAFacts = New-Object -TypeName System.Collections.ArrayList 

    $ServiceData | ForEach-Object {
        $UniqueNodes = $_.Components.node | Sort-Object -Unique
        if (!(@($UniqueNodes).Count -eq $MaxHA -or @($UniqueNodes).Count -eq @($_.Components).Count)) {
            
            $PossibleNodes = ($NodeData.nodes.name | Where-Object { $_ -notin $UniqueNodes })

            $MoveCandidate = $_.Components | Sort-Object -Property mem, cpu | Select-Object -First 1
            $DestinationCandidate = $NodeData.nodes | Where-Object { $_.Name -in $possiblenodes } | Sort-Object -Property usedmem | Select-Object -First 1

            $fact = New-Object -TypeName psobject -Property @{
                Rule        = "Service_not_dispersed"
                Target      = $_.Service
                Remediation = New-Remediation -Remediation @{VM = $MoveCandidate.vmid; FromNode = $MoveCandidate.Node; ToNode = $DestinationCandidate.Name }
            }
            if ($Fact.Remediation -notin $HAFacts.Remediation) { [void]$HAFacts.Add($fact) }
        }
        if (@($UniqueNodes).Count -eq $MaxHA) {
            $ServiceName = $_.Service
            $_.Components | ForEach-Object {
                $CurrentNode = $_.Node
                $VM = $_.vmid
                $NodeData.Nodes.Name | Where-Object { $_ -ne $CurrentNode } | ForEach-Object {
                    $fact = New-Object -TypeName psobject -Property @{
                        Rule        = "Service_dispersed_one_per_node_BLOCKMOVES"
                        Target      = $ServiceName
                        Remediation = New-Remediation -Remediation @{VM = $VM; FromNode = $CurrentNode; ToNode = $_ }
                    }
                    if ($Fact.Remediation -notin $HAFacts.Remediation) { [void]$HAFacts.Add($fact) }
                }
            }
        }
        elseif (@($UniqueNodes).Count -eq @($_.Components).Count) {
            $ServiceName = $_.Service
            $UsedNodes = $_.Components.Node
            $_.Components | ForEach-Object {
                $Thisnode = $_.Node
                $VM = $_.vmid
                $UsedNodes | Where-Object { $_ -ne $Thisnode } | ForEach-Object {
                    $fact = New-Object -TypeName psobject -Property @{
                        Rule        = "Service_dispersed_BLOCKMOVES"
                        Target      = $ServiceName
                        Remediation = New-Remediation -Remediation @{VM = $VM; FromNode = $Thisnode; ToNode = $_ }
                    }
                    if ($Fact.Remediation -notin $HAFacts.Remediation) { [void]$HAFacts.Add($fact) }
                }
            }
        }
    }

    $NodeData.nodes | Sort-Object -Property usedmem -Descending | Select-Object -First 1 | ForEach-Object {
        $Node = $_.name
        $LowMemNode = $NodeData.nodes | Sort-Object -Property usedmem | Select-Object -First 1 
        $Difference = $_.usedmem - ($LowMemNode.usedmem + ($LowMemNode.maxmem * .05))
        $HighMemVM = $VMData | Where-Object { $_.Node -eq $Node } | Sort-Object -Property mem -Descending | Select-Object -First 1
        $LowMemVM = $VMData | Where-Object { $_.Node -eq $Node } | Sort-Object -Property mem | Select-Object -First 1

        if ($Difference -gt $HighMemVM.mem) {
            $LowMemNode = $NodeData.nodes | Sort-Object -Property usedmem | Select-Object -First 1 
            $fact = New-Object -TypeName psobject -Property @{
                Rule        = "Unbalanced_Memory_HIGHMEMMOVE"
                Target      = $_.Name
                Remediation = New-Remediation -Remediation @{VM = $HighMemVM.vmid; FromNode = $_.Name; ToNode = $LowMemNode.Name }
            }
            if ($Fact.Remediation -notin $HAFacts.Remediation) { [void]$HAFacts.Add($fact) }
        }
        elseif ($Difference -gt $LowMemVM.mem) {
            $LowMemNode = $NodeData.nodes | Sort-Object -Property usedmem | Select-Object -First 1
            $fact = New-Object -TypeName psobject -Property @{
                Rule        = "Unbalanced_Memory_LOWMEMMOVE"
                Target      = $_.Name
                Remediation = New-Remediation -Remediation @{VM = $LowMemVM.vmid; FromNode = $_.Name; ToNode = $LowMemNode.Name }
            }
            if ($Fact.Remediation -notin $HAFacts.Remediation) { [void]$HAFacts.Add($fact) }
        }
    }
    $HAFacts | Where-Object { $_.Rule -cnotlike "*_BLOCKMOVES" }
}

function Move-VM {
    param($ProxmoxConfiguration, $MoveData)
    Invoke-ProxmoxCall -ProxmoxConfiguration $ProxmoxConfiguration -Endpoint "nodes/$($MoveData.FromNode)/qemu/$($MoveData.VM)/migrate" -Body ('target=' + $MoveData.ToNode + ';online=1') -Method "POST" | Out-Null
}

Export-ModuleMember -Function New-ProxmoxConfiguration
Export-ModuleMember -Function Get-ProxmoxConnectionConfig
Export-ModuleMember -Function Invoke-ProxmoxCall
Export-ModuleMember -Function Get-ManagedVMs
Export-ModuleMember -Function Get-ServiceData
Export-ModuleMember -Function Get-NodeData
Export-ModuleMember -Function Update-HAConfig
Export-ModuleMember -Function Move-VM