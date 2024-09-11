Function Invoke-ProxyBuilder {

    <#
    .SYNOPSIS
    Creates a proxy.pac that obtains updated information for Microsoft 365 and other various cloud services
    with the intention of bypassing proxy for the cloud services and redirecting all other traffic to the proxy defined in the parameter
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ProxyServerAddress,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$ProxyServerPort,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$LocalDNSDomains
    )

    begin {
    
        
        function Convert-CIDRToNetmask {
            param (
                [string]$cidr
            )
        
            if ($cidr -match "^(\d+\.\d+\.\d+\.\d+)$") {
                # Single IP address, treat as /32
                return "255.255.255.255"
            } elseif ($cidr -match "^(\d+\.\d+\.\d+\.\d+)/(\d+)$") {
                # CIDR format
                $prefix = [int]$matches[2]
                $mask = [math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix)
                $mask = [string]::Format("{0}.{1}.{2}.{3}", ($mask -band 0xFF000000) -shr 24, ($mask -band 0x00FF0000) -shr 16, ($mask -band 0x0000FF00) -shr 8, $mask -band 0x000000FF)
                return $mask
            }
        }

        
        # Declare Folder Variables
        $Script:Directories = [PSCustomObject]([ordered]@{
            StaticInputDir      = "$($pwd.Path)\Inputs"
            OutputRoot          = "$($pwd.Path)\Output"
            EDLipv4OutputDir    = "$($pwd.Path)\Output\EDL\ipv4"
            EDLdomainOutputDir  = "$($pwd.Path)\Output\EDL\domain"
            WPADOutputDir       = "$($pwd.Path)\Output\WPAD"
            ArchivePath         = "$($pwd.Path)\Archive"
        })

        # declare proxy.pac/wpad.dat output file path

        $script:wpadfile = "$($Script:Directories.WPADOutputDir)\wpad.dat"


        # I have no idea why, but microsoft has these domains in their url filters.  
        # *microsoft.com is potentially something that could be used maliciously if a firewall allowed it (maliciousmicrosoft.com would pass the filter in this example)
        # i've yet to see a next gen firewall or a proxy honor a * that wasnt immediately followed by a subdomain
        $script:DomainFilters = @(
            "*displaycatalog.mp.microsoft.com",
            "*microsoft.com",
            "*gallerycdn.vsassets.io",
            "*vstmrblob.vsassets.io",
            "*cdn.onenote.net"
        )





        $Script:IPs = [PSCustomObject]([ordered]@{
            Feed_M365Common_Mirosoft_IPs                    =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Common" } | ForEach-Object { $_.ips } | ForEach-Object { $_ -split ',' } | Where-Object { $_ -notmatch ':' -and $_ -ne '' })           # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Exchange_Mirosoft_IPs                      =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Exchange" } | ForEach-Object { $_.ips } | ForEach-Object { $_ -split ',' } | Where-Object { $_ -notmatch ':' -and $_ -ne '' })         # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Exchange_PaloAlto_IPs                      =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/exchange/all/ipv4").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                      # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Sharepoint_Mirosoft_IPs                    =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "SharePoint" } | ForEach-Object { $_.ips } | ForEach-Object { $_ -split ',' } | Where-Object { $_ -notmatch ':' -and $_ -ne '' })       # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Sharepoint_PaloAlto_IPs                    =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/sharepoint/all/ipv4").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                    # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Teams_Mirosoft_IPs                         =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Skype" } | ForEach-Object { $_.ips } | ForEach-Object { $_ -split ',' } | Where-Object { $_ -notmatch ':' -and $_ -ne '' })            # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Teams_PaloAlto_IPs                         =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/skype/all/ipv4").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                         # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Intune_Microsoft_IPs                       =       ((invoke-restmethod -Uri ("https://endpoints.office.com/endpoints/WorldWide?ServiceAreas=MEM`&`clientrequestid=" + ([GUID]::NewGuid()).Guid)) | Where-Object {$_.ServiceArea -eq "MEM" -and $_.ips} | Select-Object -Unique -ExpandProperty ips)                                            # https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america
            Feed_Intune_PaloAlto_IPs                        =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/msintune/all/ipv4").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                                     # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Static_Azure_Devops                             =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\ipv4\Microsoft_Azure_Devops.txt")                                                                                                                                                                                                 # https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url?view=azure-devops&tabs=IP-V4 
            Static_Microsoft_Azure_Information_Protection   =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\ipv4\Microsoft_Azure_Information_Protection.txt")                                                                                                                                                                                 # https://learn.microsoft.com/en-us/azure/information-protection/requirements 
            Static_Microsoft_Defender_Cloud_Apps            =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\ipv4\Microsoft_Defender_Cloud_Apps.txt")                                                                                                                                                                                          # https://learn.microsoft.com/en-us/defender-cloud-apps/network-requirements

        })

        $Script:Domains = [PSCustomObject]([ordered]@{
            Feed_M365Common_Mirosoft_Domains                =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { ($_.serviceArea -eq "Common") }).urls                                                                                                                      # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Exchange_Mirosoft_Domains                  =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Exchange" }).urls                                                                                                                      # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide        
            Feed_Exchange_PaloAlto_Domains                  =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/exchange/all/url").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                       # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Sharepoint_Mirosoft_Domains                =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Sharepoint" }).urls                                                                                                                    # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Sharepoint_PaloAlto_Domains                =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/sharepoint/all/url").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                     # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Teams_Mirosoft_Domains                     =       ((Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$((New-Guid).Guid)") | Where-Object { $_.serviceArea -eq "Skype" }).urls                                                                                                                         # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
            Feed_Teams_PaloAlto_Domains                     =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/skype/all/url").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                          # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_Intune_Microsoft_Domains                   =       ((invoke-restmethod -Uri ("https://endpoints.office.com/endpoints/WorldWide?ServiceAreas=MEM`&`clientrequestid=" + ([GUID]::NewGuid()).Guid)) | Where-Object {$_.ServiceArea -eq "MEM" -and $_.urls} | Select-Object -Unique -ExpandProperty urls)                                          # https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america
            Feed_Intune_PaloAlto_Domains                    =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/msintune/all/url").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                                      # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Feed_MSDefender_PaloAlto_Domains                =       (Invoke-WebRequest -Uri "https://saasedl.paloaltonetworks.com/feeds/msdefender/all/any/url").Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }                                                                                                                # https://docs.paloaltonetworks.com/resources/edl-hosting-service
            Static_Intune_Endpoint_Analytics                =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Intune_Endpoint-analytics.txt")                                                                                                                                                                                 # https://learn.microsoft.com/en-us/mem/analytics/troubleshoot#endpoints-required-for-configuration-manager-managed-devices
            Statice_Device_Health_Attestation               =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Intune_Device_Health_Attestation.txt")                                                                                                                                                                          # https://techcommunity.microsoft.com/t5/intune-customer-success/support-tip-update-endpoints-to-support-microsoft-azure/ba-p/3888995
            Static_Windows_Microsoft_Domains                =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Windows_11_Endpoints.txt")                                                                                                                                                                                      # https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints
            Static_EntraHybridJoin_Microsoft_Domains        =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Entra_Hybrid_Join.txt")                                                                                                                                                                                         # https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join
            Static_M365_Support_Recovery_Assistant_Domains  =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Support_And_Recovery_Assistant_M365.txt")                                                                                                                                                                       # https://learn.microsoft.com/en-us/microsoft-365/enterprise/additional-office365-ip-addresses-and-urls?view=o365-worldwide
            Static_Exchange_Hybrid_Entra_Auth               =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Exchange_Hybrid_Entra_Auth.txt")                                                                                                                                                                                # https://learn.microsoft.com/en-us/microsoft-365/enterprise/additional-office365-ip-addresses-and-urls?view=o365-worldwide
            Static_Entra_Connect_Health                     =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Entra_Connect_Health.txt")                                                                                                                                                                                      # https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-agent-install
            Static_Azure_Devops                             =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Azure_Devops.txt")                                                                                                                                                                                              # https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url?view=azure-devops&tabs=IP-V4
            #Static_Azure_Devops_Custom_URLs                 =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Azure_Devops_Custom_URLs.txt")                                                                                                                                                                                 # https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url?view=azure-devops&tabs=IP-V4
            Static_Azure_Automation                         =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Azure_Automation.txt")                                                                                                                                                                                          # https://learn.microsoft.com/en-us/azure/automation/how-to/automation-region-dns-records
            #Static_Azure_Automation_PrivateLink_URLs        =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Azure_Automation_PrivateLink.txt")                                                                                                                                                                             # https://learn.microsoft.com/en-us/azure/automation/how-to/automation-region-dns-records
            Static_Microsoft_App_Proxy                      =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_App_proxy.txt")                                                                                                                                                                                                 # https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-configure-connectors-with-proxy-servers
            Static_Microsoft_PowerBI_Data_Gateway           =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_PowerBI_Data_Gateway.txt")                                                                                                                                                                                      # https://learn.microsoft.com/en-us/data-integration/gateway/service-gateway-communication
            Static_Microsoft_Azure_Information_Protection   =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Azure_Information_Protection.txt")                                                                                                                                                                              # https://learn.microsoft.com/en-us/azure/information-protection/requirements
            Static_Microsoft_Defender_Endpoint              =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Defender_Endpoint.txt")                                                                                                                                                                                         # https://learn.microsoft.com/en-us/defender-endpoint/configure-environment
            Static_Microsoft_Defender_Identity              =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Defender_Identity.txt")                                                                                                                                                                                         # https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy
            #Static_Microsoft_Defender_Identity_Custom_URLs  =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Defender_Identity_Custom_URLs.txt")                                                                                                                                                                            # https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy
            Static_Microsoft_Windows_Update                 =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Windows_Update.txt")                                                                                                                                                                                            # https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus
            Static_Microsoft_Intune                         =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Intune_MDM.txt")                                                                                                                                                                                                # https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services-using-mdm
            Static_Microsoft_Defender_Cloud_Apps            =       (Get-Content -Path "$($Script:Directories.StaticInputDir)\domains\Microsoft_Defender_Cloud_Apps.txt")                                                                                                                                                                                       # https://learn.microsoft.com/en-us/defender-cloud-apps/network-requirements

        })
    }

    process 
    {

        #region create dir if not exist
        #Create Directories if not exist
        foreach($Directory in $Script:Directories.psobject.Properties)
        {

            if(-not(Test-Path -Path $Directory.value))
            {
                $Directory.value
                New-Item -ItemType Directory -Path $Directory.value | Out-Null
            }
        }
        #endregion
        #

        #region archive and cleanup existing content
        #archive old output
        Compress-Archive -Path $Script:Directories.OutputRoot -DestinationPath "$($Script:Directories.ArchivePath)\Archive-$(Get-Date -Format yyyyMMdd-HHmmss).zip"

        #cleanup old output
        Remove-Item -Path "$($Script:Directories.OutputRoot)\*" -Recurse -Force
        #endregion

        #Create EDL ipv4 files
        foreach($list in $Script:IPs.psobject.Properties)
        {

            if(-not(Test-Path ($Script:Directories.EDLipv4OutputDir + "\" + $list.Name + ".txt")))
            {
                New-Item -ItemType File -Path ($Script:Directories.EDLipv4OutputDir + "\" + $list.Name + ".txt") -Force | Out-Null
                Add-Content -Path ($Script:Directories.EDLipv4OutputDir + "\" + $list.Name + ".txt") -Value ""
            }
            $list.value | Out-File -FilePath ($Script:Directories.EDLipv4OutputDir + "\" + $list.Name + ".txt") -Encoding utf8 -Force -Append
        }

        #dedup duplicate ips and store in variable for wpad building later
        $script:ipv4address = foreach($ip in $Script:IPs.psobject.Properties)
        {
            $ip.value
        }

        $script:domains = foreach($list in $Script:Domains.psobject.Properties)
        {
            $EDLListName = $list.Name
            foreach($domain in $list.Value)
            {
                #remove http:// and https:// prefixes
                $domain = $domain -replace '^https?://', ''

                # remove everything after first instance of / (including the /)
                $domain = $domain -replace '/.*$', ''

                #remove domains that contain .*. somewhere in the middle
                if($domain -match '\.\*\.')
                {
                    $domain = ""
                }

                #remove domains that are in the domain filter
                foreach($domainfilter in $script:DomainFilters)
                {
                    if($domain -eq $domainfilter)
                    {
                        $domain = ""
                    }
                }

                # Trim white space entries 
                $domain = $domain.Trim()

                # only report on domains with a value not "" and write them to the edl
                if($domain -ne "")
                {
                    if(-not(Test-Path ($Script:Directories.EDLdomainOutputDir + "\" + $EDLListName + ".txt")))
                    {
                        New-Item -ItemType File -Path ($Script:Directories.EDLdomainOutputDir + "\" + $EDLListName + ".txt") -Force | Out-Null
                        Add-Content -Path ($Script:Directories.EDLdomainOutputDir + "\" + $EDLListName + ".txt") -Value ""
                    }
                    
                    Add-Content -Path ($Script:Directories.EDLdomainOutputDir + "\" + $EDLListName + ".txt") -Value ($domain + "/")
                }

                # output domain to store in variable to structure wpad
                if($domain -ne "")
                {
                    $domain
                }
            }
        }
        
        # deduplicate records that appear in multiple feeds/lists and sort non-wildcard domains first
        # we do this because wpad uses first match, this speeds up client performance when querying domains by returning exact matches first and leaving wildcards to the end

        $script:domains_distinct = $domains | Select-Object -Unique | Sort-Object -Descending
        $script:ipv4address_distinct = $script:ipv4address | Select-Object -Unique

        #region beginning section of pac builder

        New-Item -Path $script:wpadfile -ItemType File -Force | Out-Null

        #region wpad static first line
        #$script:wpad:1 = 'function FindProxyForURL(url, host) {'

        $script:wpad:1 = @"
function FindProxyForURL(url, host) {

"@
        #endregion

        #region declare proxy
        $script:wpad:5 = @"
    // declare proxy server
    var ProxyServer = `"PROXY ${ProxyServerAddress}:${ProxyServerPort}`";

"@

        #endregion

        $script:wpad:10 = @"
    // set current clients ip address to variable myip
    var myip = myIpAddress();

    // create variable "proxy"
    var proxy;

"@
        $script:wpad:15 = @"
    // set proxy to proxyserver
    proxy = ProxyServer;
    
    
        
"@

        $script:wpad:20 = @"
    var resolved_ip = dnsResolve(host);
    if (isPlainHostName(host) || // bypass proxy if non fqdn
        isInNet(resolved_ip, "127.0.0.0", "255.0.0.0") ||      // bypass proxy if localhost network
        isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||       // bypass proxy if private subnet 10.0.0.0/8
        isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||   // bypass proxy if Private subnet 172.16.0.0/12
        isInNet(resolved_ip, "192.168.0.0", "255.255.0.0"))    // bypass proxy if Private subnet 192.168.0.0/16
    {
        return "DIRECT"; // Bypass proxy for plain hostnames, loopback, and private subnets
    }

"@
        # Initialize the WPAD content variable
        $script:wpad:30 = "`tif `n`t(" 

        foreach ($domain in $script:domains_distinct) {
            $script:wpad:30 += "`n`t`tshExpMatch(host, `"$domain`") ||"
        }

        # Remove the last ' || ' and add the final condition
        $script:wpad:30 = $script:wpad:30.TrimEnd(" ||")
        $script:wpad:30 += "`n`t) `n`t{`n"
        $script:wpad:30 += "`t`treturn `"DIRECT`"`; // Bypass proxy for domains`n"
        $script:wpad:30 += "`t}`n"


        $script:wpad:40 = "`tif `n`t(" # Start of the if block

        foreach ($ipRange in $script:ipv4address_distinct) {
            if ($ipRange -match "^(\d+\.\d+\.\d+\.\d+)/(\d+)$") {
                $ip = $matches[1]
                $cidr = [int]$matches[2]
                $mask = Convert-CIDRToNetmask -cidr $ipRange
            } else {
                $ip = $ipRange
                $mask = Convert-CIDRToNetmask -cidr $ipRange
            }

            $script:wpad:40 += "`n`t`tisInNet(resolved_ip, `"$ip`", `"$mask`") ||" # Add each condition on a new line with tab indentation
        }

        $script:wpad:40 = $script:wpad:40.TrimEnd(" ||")
        $script:wpad:40 += "`n`t)`n"
        $script:wpad:40 += " `t{`n"
        $script:wpad:40 += "`t`treturn `"DIRECT`"`; // Bypass proxy for IP ranges or addresses`n" # Add a tab indent for the return statement


        $script:wpad:40 += "`t}`n"


        $script:wpad:finalize = @"
    return proxy;
}

"@
        #build wpad.dat

        #region outputwpad
        $script:wpad:1 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:5 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:10 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:15 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:20 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:30 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        $script:wpad:40 | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force

        $script:wpad:finalize | Out-File -Path $script:wpadfile -Encoding utf8 -Append -Force
        #endregion


    }

    end 
    {
    }

}

Invoke-ProxyBuilder -ProxyServerAddress "abc.com" -ProxyServerPort "3129"
#