## #########################################################
## Created by Robert Janes    Last Modified 19 March 2025
##
## Beta version 0.99
## Network TCP/TLS troubleshoot engine to provide some troubleshooting information and display some recommendations based on findings.

<#
	.SYNOPSIS
		Test TCP and TLS connections to an endpoint. Recommendations may be provided if there are probable solutions.
	
	.DESCRIPTION
		This script will check TCP and TLS connections and associated certificates to determine if the certificate chain of trust is complete or broken.  The goal is to inform the user of what problems may occur and how the issue may be mitigated.
	
	
#	.PARAMETER ProxyUrl
		Explicitly set the proxy and proxy port that should be used for the connection "http://proxyserverfqdn.com:8080"
	
	.EXAMPLE
		Run the script to test connectivity to endpoint:
		.\Test-TlsConnection.ps1 -fqdn "login.microsoft.com"

	.EXAMPLE
		Run the script to test connectivitiy and specify a proxy to use:
		.\Test-TlsConnection.ps1 "login.microsoft.com" -proxyUrl "http://yourproxy:port"

	.EXAMPLE
		Run the script to test connectivity and specify fqdn, port,:
		.\Generate-Microsoft-Support-Logs.ps1 -fqdn "login.microsoft.com" -port 443
	
	.OUTPUTS
		A folder containing log files and diagnostic information. By default, the folder is created in the script's current directory or at `C:\temp\Test-TLSConnection-logs\$fqdn' and 'C:\temp\Test-TLSConnection-logs\$fqdn\certs'.
	
	.NOTES
		Beta script.  Sample size tested is fairly low so bugs and constructive feedback should be provided.

##KNOWN Limitations###
# When using proxy, tcp connection displayed is the proxy url and port.  
# When using proxy, revocation check output is incorrect as it does not currently use the proxy specified.  Ignore revocation warnings and only pay attention to the CRL connection checks.
# Does not check for certificate pinning.
#>
<#
[CmdletBinding()]
param (
    [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true,HelpMessage="Enter the FQDN or IP of the endpoint to test")]
    [string]$fqdn,
    [int]$port = 443,
    [string]$proxyUrl = $null,
    [Boolean]$startedByPs1 = $false
)
#>

function Test-TlsConnection {
    #[CmdletBinding()]
    param (
        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true,HelpMessage="Enter the FQDN or IP of the endpoint to test")]
        [string]$fqdn,
        [int]$port = 443,
        [string]$proxyUrl = $null
    )
    # Get OS information
    $os = Get-CimInstance Win32_OperatingSystem

    #initialize variables:
    $entry=""
    # Remove protocol portion of URL (http or https) if used 
    $fqdn = $fqdn -replace '^https?://', ''
    # Create a custom object to display fundamental information
    $ConnectionResults = New-Object PSObject -Property @{
        ConnectionSuccessfull             = $null
        ConnectionIFRevocationCheckForced = $null
        IsRevocationStatusUnknown         = $null
        IsRevoked                         = $null
        IsOfflineRevocation               = $null
        IsPartialChain                    = $null
        IsMissingIssuer                   = $null
        IsChainExpired                    = $null    
    }

    #Get environment details
    try {
        $isDomainJoined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        Write-Verbose "This computer is joined to the domain: $($domain.Name)"
    }
    catch {
        Write-Verbose "Computer is NOT domain joined"
    }
    #Get Computer Info 
    #$ComputerInfo = Get-ComputerInfo -Property Windowsproductname,csname,cspartofdomain

    #Get and Check local proxy configuration information
    $localSettings = New-Object psobject -Property @{
        LocalInternetOptionsProxy = $null
        LocalInternetOptionsProxyOverride = $null
        LocalSystemProxy = $null
        ProxyHttpsEnvironmentVariable = $null
        ProxyHttpEnvironmentVariable = $null
        NoProxyEnvironmentVariable = $null
    }
    $localSettings.LocalInternetOptionsProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
    $localSettings.LocalInternetOptionsProxyOverride = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -ErrorAction SilentlyContinue
    $localSettings.localSystemProxy = netsh winhttp show proxy
    $localSettings.proxyHttpsEnvironmentVariable = $env:HTTPS_PROXY
    $localSettings.proxyHttpEnvironmentVariable = $env:HTTPS_PROXY
    $localSettings.NoProxyEnvironmentVariable = $env:NO_PROXY

    
    #To test ouptut for proxy
    <#
    #$localSettings
    #or
    $localInternetOptionsProxyOverride.ProxyOverride
    $localInternetOptionsProxy.ProxyServer
    #>


    # Set up log files
    # Generate the current date in the desired format
    #$currentDate = (Get-Date).ToString("MMM-dd-yyyy")

    # Log directory
    $logDir = "C:\temp\Test-TLSConnection-logs\$fqdn"
    $certPath = "C:\temp\Test-TLSConnection-logs\$fqdn\Certs"

    # Ensure the directory exists, create if it does not
    if (!(Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }
    if (!(Test-Path -Path $certPath)) {
        New-Item -Path $certPath -ItemType Directory | Out-Null
    }
    # Create the log file name
    $logFileName = "generalinfo-$fqdn-log-$(Get-Date -Format 'MMM-dd-yyyy-hh-mm-tt').txt"
    $logFailuresName = "identified-issue-$fqdn-log-$(Get-Date -Format 'MMM-dd-yyyy-hh-mm-tt').txt"
    $logConsoleOutputName = "Console-Output.txt"

    # Define the full path for the log file (customize the directory as needed)
    $logFilePath = "$logdir\$logFileName"
    $logFailuresPath = "$logdir\$logFailuresName"
    $logConsoleOutputPath = "$logconsoleoutputname\$logConsoleOutputName"

    # Output Current time to the log file.
    @"
Local Machine Time (12-hour): $(Get-Date -Format 'MMM dd yyyy hh:mm tt')
UTC Time (12-hour): $((Get-Date).ToUniversalTime().ToString('MMM dd yyyy hh:mm tt'))
UTC Time (24-hour): $((Get-Date).ToUniversalTime().ToString('MMM dd yyyy HH:mm'))
"@ | Out-File -FilePath $logFilePath -Encoding UTF8 -Append

    # Get Time Sync source
    $TimeSyncSource = w32tm /query /source


    # Writing to the log file
    ##LOGGING
    "Log started at: $(Get-Date)`n" | Add-Content $logFilePath -Encoding UTF8
   # Check if the console is running in older versions of ISE or not.  If it is, then the console output will not be logged.
    if (($PSVersionTable.PSVersion -le [Version]"5.0") -and ($host.Name -match "ISE")) {
        Write-Warning "Console Output will not be logged (transcripting is not supported in older versions of ISE).  Use PowerShell Console (Not ISE)" 
    }
    else {
        Start-Transcript -Path "$logDir\ConsolOutput.txt"
    }
    Write-Output "`n############ Connecting to $fqdn ############`n------------------------------------------------------------"
      
    # Output the file name to the console for verification
  
    Write-Verbose "`nLocal Machine Time Sync Source: $TimeSyncSource`n"
    Write-Output "Local Machine Time Sync Source: $TimeSyncSource" | Add-Content $logFilePath -Encoding UTF8


    ##LOGGING
    Write-Output "`nTesting connectivity on:`n`n $fqdn" | Add-Content $logFilePath -Encoding utf8
    try {

        # Output Is Proxy Being used or not:
        if ($proxyUrl) {
            Write-Output "`nProxy has been explicitly set: $proxyUrl"
        }

        # Resolve fqdn to possible IP addresses (Uses DNS)
        $ipAddresses = [System.Net.Dns]::GetHostAddresses($fqdn) | Select-Object -ExpandProperty IPAddressToString
        Write-Output "Resolvable ipv4 IP/s: $ipAddresses"
        ##LOGGING
        Write-Output "Resolvable ipv4 IP/s: $ipAddresses" | Add-Content $logFilePath -Encoding UTF8
        Write-Output "All Resolvable IPS (ipv4 and ipv6)" | Add-Content $logFilePath -Encoding UTF8
        Resolve-DnsName $fqdn -ErrorAction SilentlyContinue -ErrorVariable ErrorDNS | Out-String | Add-Content $logFilePath -Encoding UTF8
            
        if ($ErrorDns -match "DNS name does not exist") {
            $ErrorDns | Out-String | Add-Content $logFailuresPath -Encoding UTF8
            write-output "DNS server did not resolve $fqdn  <- this is normal if an IP address is used rather than a URL and reverse DNS lookup zone is not configured"
        }
        if ($ErrorDns -match "No DNS servers configured for local system") {
            write-output "Cannot communicate to a DNS server.  Check network settings"
        }
        #Resolve-DnsName $fqdn | Out-String | Add-Content $logFilePath -Encoding UTF8

        # Create a TCP client
        $tcpClient = New-Object System.Net.Sockets.TcpClient
  
        #Set TCP Timeout:
        $timeout = 5000 # 5 seconds
        $tcpClient.ReceiveTimeout = $timeout
        $tcpClient.SendTimeout = $timeout
       

        # PROXY CONFIGURATION (IF PROVIDED)
        if ($proxyUrl) {
            $proxy = New-Object System.Net.WebProxy($proxyUrl)
            $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            $proxyUri = $proxy.GetProxy((New-Object Uri "http://$($fqdn):$port"))
          
            
            # Establish a connection to the proxy server
            $tcpClient.Connect($proxyUri.Host, $proxyUri.Port)
            
            #Get IP Address and Port used for the TCP connection
        $remoteEndPoint = $tcpClient.Client.RemoteEndPoint
        $remoteIP = $remoteEndPoint.Address
        $remotePort = $remoteEndPoint.Port
            if ($tcpClient.Connected) {
                Write-Output "Initial TCP to proxy connected? $($tcpClient.connected)"
                Write-Output "Port:$remotePort`n"
                $initialProxyTCPConnection = $true
            }
            
            # Send CONNECT request to the proxy server
            $connectRequest = "CONNECT $($fqdn):$port HTTP/1.1`r`nHost: $($fqdn):$port`r`nProxy-Connection: Keep-Alive`r`n`r`n"
            $proxyStream = $tcpClient.GetStream()

            $proxyStream.Write([System.Text.Encoding]::ASCII.GetBytes($connectRequest), 0, $connectRequest.Length)
            $proxyStream.Flush()
      

            # Read the proxy response
            $reader = New-Object System.IO.StreamReader($proxyStream)
             
            try {
                #Test if the proxy connection is successful
                $null = $reader.ReadLine()
            }
            Catch {
                if ($initialProxyTCPConnection){
                Write-Output "`nPROXY CONNECT FAILED: The proxy denied the TLS connection request. Initial TCP connection successful but TLS handshake failed.`n"
                Write-Output "`n---Potential Remediation(fix)--- `n1) Check if this machine is allowed (has permission) to access the proxy`nAND`n2) Verify that the proxy can successfully access the URL ($fqdn)`n"
                
                }
                #Write-Output "Possible reasons for this error:`n  - The proxy server is blocking the connection or this machine is not allowed to connected to proxy`n  - The proxy server is not configured to allow TLS connections`n  - The proxy server is not configured to allow connections to the specific port`n  - The proxy server is not configured to allow connections to the specific FQDN`n  - The proxy server is not configured to allow connections to the specific IP address`n  - A firewall is blocking the connection to the FQDN from the proxy server"
                $ProxyFail = $true
            }
        } 
        # Else if no Proxy explicitly set, connect without proxy
        else {
            $tcpClient.Connect($fqdn, $port)
        }
               
        # IF Not using a proxy, get the IP address and port used for the TCP connection           
        if (!$proxyUrl) {         
        # Get IP Address and Port used for the TCP connection
        $remoteEndPoint = $tcpClient.Client.RemoteEndPoint
        $remoteIP = $remoteEndPoint.Address
        $remotePort = $remoteEndPoint.Port
                
        Write-Output "Is TCP Connected? $($tcpClient.connected)"
        if ($tcpClient.Connected) {
            Write-Output "Initial TCP connection success: $remoteIP"
            Write-Output "Port:$remotePort`n"
            $initialTCPConnection = $true
        }
        else {
            if ($remoteIP){
            Write-Output "Bad/Failed TCP connection to $remoteIP"
            }    
        }
    }   

        # Get the network stream
        $networkStream = if ($proxyStream) { $proxyStream } else { $tcpClient.GetStream() }

        # Create an SSL stream
        $sslStream = New-Object System.Net.Security.SslStream -ArgumentList @($networkStream, $false, { $true }) # { $true } will always allow the connection.  Set to { $false } if you want cert check to always fail
        
        # Specify the allowed protocols and connect
        $sslStream.AuthenticateAsClient($fqdn, $null, [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13, $false) # $false sets to NOT do revocation check - set to $true
        #Write-Output "`nSSL STREAM:"
        #$sslStream
               

        $sslStream.LocalCertificate
        
        # Display SSL stream information
        #$sslStream | Select-Object -Property SslProtocol | Format-List #, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus | Format-List
        # Collect details of the handshake for Cipher Suite
        $cipherAlgorithm = $sslStream.CipherAlgorithm
        $cipherStrength = $sslStream.CipherStrength
        $hashAlgorithm = $sslStream.HashAlgorithm
        $hashStrength = $sslStream.HashStrength
        $keyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
        $keyExchangeStrength = $sslStream.KeyExchangeStrength
        $TLSVersion = $sslStream.SslProtocol

        Write-Output "Attempting to connect using TLS Version: $TLSVersion`n"
        #Create Certificate Object from the stream
        $certInfo = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $sslStream.RemoteCertificate
        
        # Export certificate to file 
        Export-Certificate -Cert $certInfo -FilePath "$certPath\$fqdn.cer" -Type CERT | Out-Null
        
        $WarningMessage = $null
        
        # Get the certificate's chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        # Build the chain using the certificate
        $chain.Build($certInfo) | Out-Null
        # Get any negative status reported from the chain
        $chainStatus = $Chain.ChainStatus
        if ($chainStatus) {
        #DEBUG
        $chainStatusList = $chain.ChainStatus
        $chainStatusList | Format-List | Out-String | Add-Content $logFailuresPath -Encoding UTF8

        }
        # If there is something wrong with the chain status, then output each status.  No output means no bad status.
        foreach ($status in $chain.ChainStatus) {
            #use if debugging
            #Write-Host "Status: $($status.Status), Info: $($status.StatusInformation)"
        }
        
        #debug
        #Write-Verbose $chainStatusList.tostring()
       
        
        # Count how many certificates are in the chain
        $CertCount = $chain.ChainElements.Count
        # Get Chain health/Status
        $isPartialChain = $chainstatus.Status -contains "PartialChain"
        $isChainRevoked = $chainstatus.Status -contains "Revoked"
        $isRevocationStatusUnknown = $chainStatus.Status -contains "RevocationStatusUnknown"
        $isOfflineRecovation = $chainStatus.Status -contains "OfflineRevocation"
        $isChainExpired = $chainStatus.Status -contains "NotTimeValid"
        $isUntrustedRoot = $chainStatus.Status -contains "UntrustedRoot"   

        # GET CERT AND MISSING ISSUER IF BROKEN CHAIN

        if ($isRevocationStatusUnknown) {
            write-output "CANNOT VERIFY IF CERTIFICATE IS REVOKED" | Add-Content $logFailuresPath -Encoding UTF8
        }

        $lastCertInChain = $chain.ChainElements.Certificate | Select-Object -Last 1
        if ($isPartialChain) {
            $isMissingIssuer = $true
        }

        if ($isChainRevoked) {
            Write-Warning "Is Certificate Chain Revoked? $($IsChainRevoked)"
        }

       



        # Display certificate/Chain information
        Write-Verbose "`n[CERTIFICATE INFO]:"
        #Write-Output "$CertCount certificates found in chain"
        #Write-Output "Certificate expired? $isChainExpired"
        #Write-Output "Revocation status Unknown? $IsRevocationStatusUnknown"    
        #Write-Output "Revocation offline? $IsOfflineRecovation"
      
        $isMissingIssuer = $false
        If ($IsPartialChain) {
            $isMissingIssuer = $true
            Write-Output "Certificate chain is broken."
            $subject = $lastCertInChain.Subject
            $issuer = $lastCertInChain.issuer
            Write-Output "  |This Certificate:`n  |Subject: $subject`n  |is missing its issuer:`n  |Issuer: $issuer"
            Write-warning "A missing issuer = there is a missing certificate on this local machine that is required to complete the certificate trust chain`n"
        }
        else {
            Write-Verbose "Is certificate chain broken (partial)? $IsPartialChain"
        }
        
      
        $ConnectionResults.isPartialChain = $isPartialChain
        $connectionResults.isRevoked = $isChainRevoked
        $ConnectionResults.isChainExpired = $isChainExpired
        $ConnectionResults.isOfflineRevocation = $isOfflineRecovation
        $ConnectionResults.isMissingIssuer = $isMissingIssuer
        
        $ConnectionResults.isRevocationStatusUnknown = $isRevocationStatusUnknown

        

        If ($IsOfflineRecovation -and $IsRevocationStatusUnknown) {
            $ConnectionResults.IsRevoked = "Unknown - Cannot connect to check if certificate is revoked."
        }
        Else {
            Write-Verbose "Certificate Revoked? $IsChainRevoked"
        }
        

        # $certInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
        # write-verbose $certInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint | Out-String | Add-Content $logFilePath -Encoding utf8
        # write-verbose $certInfo | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint
        Write-Verbose "`nIssuer (CA): $($certInfo.Issuer)" 
        Write-Verbose "Subject: $($certInfo.Subject)" 
        Write-Verbose "Thumbprint: $($certInfo.Thumbprint)" 
        Write-Verbose "Valid Start Date: $($certinfo.NotBefore)" 
        Write-Verbose "Expiry Date: $($certinfo.NotAfter)" 
        Write-Verbose ""

        # Get the last certificate in the chain (the top level / CA certificate) and print it to
        $caCertificate = $chain.ChainElements.Certificate | Select-Object -Last 1
        ##LOGGING
        Write-Output "Certificate Authority:" | Add-Content $logFilePath -Encoding utf8
        $caCertificate | Format-List | Out-String | Add-Content $logFilePath -Encoding utf8
        # Are first cert and last cert the same (indicates that no cert chain)
   

        # Check if CA Cert is currently installed on machine:
        # Access the Trusted Root Certification Authorities store
        $trustedRootStore = Get-ChildItem -Path Cert:\LocalMachine\Root
        $trustedIntermidiateStore = Get-ChildItem -Path Cert:\LocalMachine\CA

        # Check if the certificate exists in the stores
        $existsRoot = $trustedRootStore | Where-Object {
            $_.Thumbprint -eq $lastCertInChain.Thumbprint
        }
        $existsIntermediate = $trustedIntermidiateStore | Where-Object {
            $_.Thumbprint -eq $lastCertInChain.Thumbprint
        }
        #$caCertificate.thumbprint

        if ($existsRoot) {
            Write-Verbose "The top level (root) certificate in this certificate chain ALREADY exists in the local machine account 'Trusted Root Certification Authorities' store."
            $TopLevelCertIsInstalled = $true
        }
        else {
            Write-Output "The top level certificate in the certificate chain (usually the root CA certificate) does NOT exist in the local machine 'Trusted Root Certification Authorities' store." | Add-Content $logFailuresPath -Encoding utf8
            $TopLevelCertIsInstalled = $false
        }


        if ($existsRoot -and !$isChainExpired -and !$isChainRevoked -and !$isMissingIssuer -and $TLSVersion -and $($tcpClient.Connected)) {
            $ConnectionResults.ConnectionSuccessfull = $true
        }
        else {
            $ConnectionResults.ConnectionSuccessfull = $false
        }
        
       #CHECKPOINT

        # Assuming $chain is your X509Chain object
        $CertSelfSigned = ($chain.ChainElements.Count -eq 1) -and ($chain.ChainElements[0].Certificate.Issuer -eq $chain.ChainElements[0].Certificate.Subject)

        if ($CertSelfSigned) {
            Write-Output "The certificate is self-signed."
            Write-Output "The certificate is self-signed." | Add-Content $logFilePath -Encoding UTF8
            
        }
        else {
            Write-Output "The certificate is not self-signed.`n" | Add-Content $logFilePath -Encoding UTF8
        }

           
        # Iterate through each element in the chain
        Write-Output "Certificate Chain:" | Add-Content $logFilePath -Encoding utf8
            foreach ($element in $chain.ChainElements) {
                # Export certificates to file 
                Export-Certificate -Cert $element.Certificate -FilePath "$certPath\$($element.Certificate.Thumbprint).cer" -Type CERT | Out-Null
                Write-Output "Issuer (CA): $($element.Certificate.Issuer)" | Add-Content $logFilePath -Encoding utf8
                Write-Output "Subject: $($element.Certificate.Subject)" | Add-Content $logFilePath -Encoding utf8
                Write-Output "Thumbprint: $($element.Certificate.Thumbprint)" | Add-Content $logFilePath -Encoding utf8
                Write-Output "Valid Start Date: $($element.Certificate.NotBefore)" | Add-Content $logFilePath -Encoding utf8
                Write-Output "Expires: $($element.Certificate.NotAfter)" | Add-Content $logFilePath -Encoding utf8
                Write-Output "" | Add-Content $logFilePath -Encoding utf8             
            }


        if ($isChainExpired) {
            #Write-output "Certificate: $($element.Certificate)"
            write-output "Certificate: $($element.Certificate)" | Add-Content $logFailuresPath -Encoding utf8
            write-output "!!! EXPIRED CERT !!!" | Add-Content $logFailuresPath -Encoding utf8
            write-output "" | Add-Content $logFailuresPath -Encoding utf8
            Write-Verbose "!!! EXPIRED CERTIFICATE CHAIN !!!"
            #throw "Remote endpoint |$fqdn| Certificate IS EXPIRED: Trust cannot be established"
        }
      
        #TOGGLE
        #$softProxyCertFix = $true
        # Define backup path for the registry
        $backupPathUser = "c:\temp\ProxyIESettingsUser.reg"
        $backupPathSystem = "C:\temp\ProxyIESettingsMachie.reg"
        if ($softProxyFix) {
            # Export the user and system internet proxy settings
            reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "$backupPathSystem" /y
            reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "$backupPathUser" /y
        }

        if ((Test-Path $backupPathUser) -and (Test-Path $backupPathSystem) -and $softProxyFix) {
            # Set the proxy server for system-wide Internet settings
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -Value "http://10.10.10.99:3128"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyOverride" -Value "<local>"

            # You can also set for the user if needed
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 1
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -Value "http://10.10.10.99:3128"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyOverride" -Value "<local>"
        }
        elseif ($softProxyCertFix) {      
            $softProxyCertFix = $false
        }

        Write-Output "[Certificate chain status]"
        write-output "`ncertificate chain status:" >> $logFilePath
        write-output "CERT-CHAIN STATUS:" | Add-Content $logFilePath -Encoding UTF8
        $chainStatus | Out-String | Add-Content $logFilePath -Encoding UTF8

        # Get each certificate in the chain to get the CRLs and test connectivity     
        foreach ($chainElement in $chain.ChainElements) { 
            $counter ++   
            $cert = $chainElement.Certificate
           
            write-output "Cert $($counter): $($cert.subject) | Thumbprint: $($cert.thumbprint)" | Format-List

            $CertutilResponse = $null
            $CertutilResponse = certutil -urlfetch -v -verify $certPath\$($cert.Thumbprint).cer
            
            # Get the "next date" from CRL urls fetched from the loacl cached cert dump, 
            $CRLNextUpdateList += $CertutilResponse -match "next"
            
            # Add the full certutil response to log (may not need/want to log all of this)
            $CertutilResponse >> $logFilePath
     
            # Output Certutil response (important items like the URL or errors)
            foreach ($line in $CertutilResponse) {
                if ($line -match "Error retrieving" -or $line -like "*http://*" -or $line -match "A certificate chain" -or $line -match "next") {
                    Write-Verbose "$line"
                    Write-Output "$line" | Out-String | Add-Content $logFailuresPath -Encoding UTF8
                }
            }
            

            $crldetails = certutil -dump C:\temp\certs\DigiCertGlobalRootG2.crl

            # If there is a partial chain status, this means there is a missing issuer.  Show missing issuer (The issuer of this certificate is not accessible/installed)

            write-output "`nIndividual Certificate Status:" >> $logFilePath
            $chainElement.ChainElementStatus >> $logFilePath
            $isCertRevoked = $chainElement.ChainElementStatus.Status -contains "Revoked"
            $isCertExpired = $chainElement.ChainElementStatus.Status -contains "NotTimeValid"
            if ($isCertRevoked) {
                Write-Warning "Is Certificate Revoked? $IsCertRevoked"
            }
            if ($isCertExpired) {
                write-warning "Is Certificate Expired? $isCertExpired"
            }


            # Check if the certificate exists in the stores
            $existsRoot = $trustedRootStore | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            $existsIntermediate = $trustedIntermidiateStore | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            if ($existsRoot) { write-output " -Cert $counter exists in local computer's 'Trusted Root Certificates' store: | Thumprint: $($existsRoot.Thumbprint)" }
            if ($existsIntermediate) { write-output " -Cert $counter exists in 'Intermediate Certificates Authorities' store: | Thumprint: $($existsIntermediate.Thumbprint)" }


            # Get Certificate Revocation List from Each Certificate in the certitifate chain
            $CRLsList = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -like 'CRL Distribution Point*' }
            $CRTDownloadList = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -like 'Authority Information Acces*' }
            #"CRTDownloadList:"
            #$CRTDownloadList
            #$cert | gm
    
            if ($CRLsList) {
                $CRLsList = $CRLsList.format($true)
                #$CRLsList
                $crlSections = $CRLsList -split "\[.*\]CRL Distribution Point"

                foreach ($section in $crlSections) {
                    if ($section -match "Distribution Point Name") {
                        #$CrlURLs += [regex]::Matches($section, 'http(s)?://[^()<>]+')
                        $CrlURLs += [regex]::Matches($section, 'http(s)?:\/\/[^()<>\n]+')
                        #$CrlURLs

                }
                }
                
            
     ""
            
                $crlLdap += ([regex]'ldaps?:\/\/[^\s()<>"]*?(?:%20[^\s<>"]*?)*cRLDistributionPoint').Matches($CRLsList)
            }
        

            # Get Certificate Download locations for each certificate in the certificate chain (If the machine is unable to download the certificates in the chain, it may not be able to trust the endpoint
            if ($CRTDownloadList) {
                #Write-Output "CRTDownloadList: "
                $CRTDownloadList = $CRTDownloadList.format($true)
                #$CRTDownloadList

                # Split the data into sections by '[x]Authority Info Access'
                $aiaSections = $CRTDownloadList -split "\[.*\]Authority Info Access"
                #$aiaSections
                # Extract the URL for the Certification Authority Issuer
                foreach ($section in $aiaSections) {
                    if ($section -match "Access Method=Certification Authority Issuer \(1\.3\.6\.1\.5\.5\.7\.48\.2\)") {
                        #$CrtURLs += [regex]::Matches($section, 'http(s)?://[^()<>]+')
                        $CrtURLs += [regex]::Matches($section, 'http(s)?:\/\/[^()<>\n]+')               
                        #$CrtURLs
                    }
                }
            }    
        }
        if ($softProxyCertFix) {
            # Restore the original user and system internet proxy settings
            reg import "$backupPathUser"
            reg import "$backupPathSystem"
            write-output "`n"
        }
    
        if ($CrlURLs){
        #List CRL URLS found.  -VERBOSE required to view in output
        $Crlurls | ForEach-Object {[string[]]$CRLurlsarraytemp += $_.Value.trim()} | out-null
        $CRLurlsarray = $CRLurlsarraytemp | ForEach-Object {$_ -replace ' ', '%20'}
        $CRLurlsarray = $CRLurlsarray | Sort-Object -unique
        #$CRLurlsarray
        
        $CRLurlsarray | ForEach-Object { write-verbose "CRL URL IS: $($_)" }
        $CRLurlsarray | ForEach-Object { Write-Output "CRL URL IS: $($_)" >> $logFilePath }
        #$CRLurlsarray.count
        If ($CRLurlsarray.count -eq 0) {
            write-verbose "CRL count: $($CRLurlsarray.count)"
            $CRLurlsarray = $null
        }
        }
        if ($crlLdap){
        #List LDAP CRL URLs Found
        $crlLdap | ForEach-Object { write-verbose "CRL LDAP URL IS: $($_.value)" }
        $crlLdap | ForEach-Object { Write-Output "CRL LDAP URL IS: $($_.value)" >> $logFilePath } 
        }
        If ($crlLdap.count -eq 0) {
            write-verbose "LDAP CRL count: $($crlldap.count)"
            $crlLdap = $null
        }
        if ($CrtURLs){
        #Clean up CRL list
        $Crturls | ForEach-Object {[string[]]$Crturlsarraytemp += $_.Value.trim()} | out-null
        $Crturlsarray = $Crturlsarraytemp | ForEach-Object {$_ -replace ' ', '%20'}
        $Crturlsarray = $Crturlsarray | Sort-Object -unique

        #List CRT URLs found
        $Crturlsarray | ForEach-Object { write-verbose "Certificate download URL is: $($_)" }
        $Crturlsarray | ForEach-Object { Write-Output "Certificate download URL is: $($_)" >> $logFilePath } 
        }

        Write-Output "`n`nChecking for connectivity issues (This may take several minutes to complete):"


        ### Attempt to download/connect each of the CRL url/endpoint
        if ($CRLurlsarray) {
            $CRLurlsarray | ForEach-Object {
                try {
                    $currentCrlUrl = $_
                    ## Download the .crl file from the URL (will be in form http://xxx.com/name.crl
                    Write-Verbose "Downloading CRL from: $_"
                    $webClient = New-Object System.Net.WebClient
                    #Set proxy for connection, if proxy is specified.      
                    if ($proxyUrl) {
                        $webClient.Proxy = $proxy
                    }
        
                    $crlData = $webClient.DownloadData($_)
     
                    ### If you want to 'really' download one of the crls to verify:
                    #$crlFile = $webClient.DownloadFile($_.Value, "C:\users\<yourUserName>\desktop\FileCRL.crl") 
                    if ($CRLData) {
                        Write-Output "Success Download/Accessing CRL : $_**"
                    }
                    if ($webClient) { 
                        $webClient.Dispose() 
                    }

                }
                catch {
        
                    if (!$CRLurlsarray) {
                        Write-Warning "There are no internet accessible CRL (Certificate Revocation Lists) configured for this certificate."
                        #export-certificate -Cert $caCertificate  -FilePath "$certPath\Certificate_Authority_Cert-For_$fqdn.cer" -Type CERT | Out-Null
                        #$caCertificate | fl
                    }
                    else {
                        Write-Verbose "Failed to access: $($currentCrlUrl)   | $PSItem.Exception.StackTrace"
                        Write-verbose "Either allow/whitelist the above URL through network blocker, and/or verify the associated certificate is trusted on the local machine."
                        $CRLDownloadFailed = $true
                        $CRLDownloadSucceeded = $false
                        [String[]]$CRLUrlsFailedList += $currentCrlUrl
                        #$CRLUrlsFailedList
                    }
                }
            }
        }
        ## ALPHA functionality - CRL VIA LDAP
        if ($crlLdap) {
            $crlLdap | ForEach-Object {
                try {
                    ## Verify LDAP connectivity to the CRL
                    Write-Verbose "`nChecking CRL from: $_"
                    #write-output "ALPHA testing for CRL on LDAP"
                    Write-Verbose "CRL has LDAP URL (Domain local)"
                    if ($crlldap.Count -ge 1 -and $CRLurlsarray.count -eq 0) {
                        Write-Verbose "CRL Certificate Revocation is ONLY accessible via ldap via AD domain joined machines."
                    }
                    if (!$CertSelfSigned -and $crlLdap) {
                        Write-Verbose "Checking LDAP access:"
                    }
       
        
                    # CRL with LDAPS
                    try {
           
                        # Define LDAP parameters
                        # Break the 'CRL OBJECT'S' LDAP details into pieces
                        $crlldapParsed = $crlldap -split "\?"
                        #"After Split"
                        foreach ($CRL_Attribute in $crlldapParsed) { Write-Verbose "$CRL_Attribute" }
                        #$crlldapParsed[0] # LDAP URI
                        #"Attribute = $($crlldapParsed[1])" # ATTRIBUTE
                        #"Base = $($crlldapParsed[2])" # Scope (base, one, or subtree)
                        #"Filter = $($crlldapParsed[3])" # LDAP Filter

                        $attribute = "$($crlldapParsed[1])"
                        $searchScope = "$($crlldapParsed[2])"
                        $filter = "$($crlldapParsed[3])"

                        # Create a DirectoryEntry object
                        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapUri)

                        # Create a DirectorySearcher object
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = $entry
                        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base # Query only the specified DN
                        $searcher.Filter = $filter

                        # Request the specific attribute
                        $searcher.PropertiesToLoad.Add($attribute) | Out-Null

                        # Perform the search / Create an LDAP connection
                        try {
                            # Utilize LDAP to search for and retrieve the CRL from the Domain
                            $result = $searcher.FindOne()
                            # If the result has the CRL list (encoded) in the properties, then successful retrieving CRL.
                            #$result.Properties
                            if ($result -and $result.Properties.certificaterevocationlist) {
                                $LDAPcrl = $result.Properties.certificaterevocationlist
                                Write-Output "CRL retrieved from LDAP successfully"
                                #Write-Output $result.Properties
                            }
                            else {
                                Write-Output "No CRL found at the specified 'LDAP' location."
                            }
                        } 
                        catch {
                            Write-warning "LDAP search failed."
                            if ($entry) { 
                                $searcher.Dispose()
                                $CRLLdapConnectFailed = $true
                                $CRLLdapFailedList += $ldapuri
                            }   
                        }        
                    }
                    catch {
                        Write-warning "Failed to set connection test to $ldapUri --> $_"
                        #return $false
                    }
    
                } 
                catch {
        
                    if (!$crlLdap) {
                        "Should not get here - bug check."
                        Write-Warning "There are no AD (Active Directory) CRL (Certificate Revocation Lists) configured on this certificate."
                    }
                    else {
                        Write-Warning "Failed to download or process Certificate Revocation List (LDAP): $PSItem.Exception.StackTrace"
                        Write-Warning "This machine may not be part of a workgroup or unable to connect to verify revocation via AD domain."
                        $CRLLdapConnectFailed = $true
        
                    }
                }
            }
        }

        
        if ($Crturlsarray) {
            $Crturlsarray | ForEach-Object {
                try {
                    $currentCrtUrl = $_
                    ## Download the .crl file from the URL (will be in form http://xxx.com/name.crt
                    Write-verbose "Downloading Certificate from: $_"
                    $webClient = New-Object System.Net.WebClient
                    #Set proxy for connection, if proxy is specified.      
                    if ($proxyUrl) {
                        Write-Verbose "Using specified Proxy for Certificate download URL"
                        $webClient.Proxy = $proxy
                    }
                    # Download the Certificate (only downloads to memory - not to disk)
                    $null = $webClient.DownloadData($_)
     
                    ### If you want to 'really' download one of the Certificate to disk to verify:
                    #$crlFile = $webClient.DownloadFile($_, "C:\users\<yourUserName>\desktop\$fqdn.crt") 
                    Write-Output "Success Download/Accessing Certificate : $_"
                    if ($webClient) { $webClient.Dispose() }

                }
                catch {

                    Write-Verbose "Failed to access: $($currentCrtUrl)   | $PSItem.Exception.StackTrace"
                    Write-Verbose "Either allow/whitelist the above URL through network blocker, and/or verify the associated certificate is trusted on the local machine."
                    $CRTDownloadFailed = $true
                    [String[]]$CRTUrlsFailedList += $currentCrtUrl
                    #$CRTUrlsFailedList
        
                }
            }
        }
        If (!$CRLurlsarray -and $IsMissingIssuer) {
            write-warning "No available path/location provided in certificate to download missing certificate issuer"
            $UntrustedRootWithNoDownloadPath = $true
        }
        if ($IsPartialChain -and $IsMissingIssuer -and !$UntrustedRootWithNoDownloadPath) {
            Write-Warning "A certificate chain could not be built to a trusted root authority.  This means that the certificate could not be automatically added/trusted to this computer because it was not accessible."
        }

        if (($CRLUrlsFailedList -or !$CRLurlsarray) -and ($CRLLdapFailedList -or !$crlLdap) -and ($IsRevocationStatusUnknown -or $IsOfflineRecovation)) {
            Write-verbose "Connections will fail if revocation check enabled."
           # export-certificate -Cert $caCertificate  -FilePath "$certPath\$fqdn_CA.cer" -Type CERT | Out-Null
        }






        if ($isPartialChain -or $isChainExpired -or $isRevocationStatusUnknown -or $isOfflineRecovation -or $isUntrustedRoot -or $isMissingIssuer -or $isChainRevoked) {
            $isCertTrusted = $false
        }
            else {
                $isCertTrusted = $true
            }
        $ConnectionResults.ConnectionIFRevocationCheckForced = $isCertTrusted
         #$ConnectionResults | ft
        if (!$ConnectionResults.ConnectionSuccessfull -or !$ConnectionResults.ConnectionIFRevocationCheckForced) {
            $ConnectionResults | Select-Object ConnectionSuccessfull, ConnectionIFRevocationCheckForced, IsMissingIssuer, IsRevocationStatusUnknown, IsPartialChain, IsOfflineRevocation, IsRevoked, IsChainExpired | Format-List
        }
            else {
                $ConnectionResults | Select-Object ConnectionSuccessfull, ConnectionIFRevocationCheckForced | Format-List
                $ConnectionResults | Format-List | Out-String | Add-Content $logFilePath -Encoding UTF8
                Write-Verbose $ConnectionResults | Format-List
                #$ConnectionResults | fl
            }

        Write-Output "Based on above, the current status of the certificate chain is 'fully' trusted: $isCertTrusted`n"

       
  
        if ($CRLurlsarray = $null -and $crlLdap) { 
            Write-Verbose "No online CRL listed / Only LDAP CRL listed" 
        }

        if ($CRLUrlsFailedList -or $CRTDownloadFailed) {
            Write-Output " Download Failures Detected..."
        }

        if ($CRLUrlsFailedList) {
            Write-Warning "Inaccessible CRL endpoints:"
            foreach ($CRL in $CRLUrlsFailedList) { Write-Output " $CRL" }
        }
    

        if ($CRLLdapFailedList) {
            Write-Warning "Inaccessible LDAP endpoints:"
            foreach ($CRL in $CRLLdapFailedList) { Write-Output " $CRL" }
        }
        if ($CRTUrlsFailedList){
            Write-Warning "Inaccessible Certificate download locations:"
            foreach ($certlocation in $CRTUrlsFailedList){Write-Output " $certlocation"}
        }

        #extract this information to prove - currently the below is assumed.
        if ($CRLDownloadFailed -and !$isOfflineRecovation -and !$isRevocationStatusUnknown){
            Write-Output "$($CertutilResponse -match "next")"    
        }

  
        


       
        ###
        ### 
        ###
        ### FINAL RESULTS
        ##############################################################
       
        #### RECOMMENDATIONS
        $CRLNextUpdateList = $CRLNextUpdateList | Select-Object -Unique
        Write-Output "`n`n#### RECOMMENDATION(s) #### `n"
        if ($ConnectionResults.ConnectionSuccessfull -and $connectionResults.ConnectionIFRevocationCheckForced){
            Write-Output "No recommendation required.  Connection Successful and certificate chain is fully trusted."
        }
        if ($CRLDownloadFailed -and !$isOfflineRecovation -and !$isRevocationStatusUnknown -and $isCertTrusted) {
            Write-Output "-Revocation check relying on cached CRLs | Cannot access online revocation list |  When cached revocation list timer is up, connections that require revocation checks may no longer work."
            Write-Output "-Cached CRLs require refresh on -> $CRLNextUpdateList.  After the 'NextUpdate' date, if the download fails, connections requiring forced revocation checks may no longer work thus the certificate chain will lose 'fully' trusted status."
        }
        if ($CRTDownloadFailed -and !$isOfflineRecovation -and !$isRevocationStatusUnknown -and $isCertTrusted -and $TopLevelCertIsInstalled){
            Write-Output "Certificate online download location/s failed connection test.  If you manually install certificates, this is not an issue, but if this is unexpected, verify network blockers (firewall/proxy,etc.) are blocking the URL, and IF you trust $fqdn, consider whitelisting/allowing the URL/s (listed above)."
        }
    
        If ($IsChainExpired) {
            write-output "Certificate is expired.  $fqdn will need to replace the certificate before it can/will be properly trusted"
        }
        if ($IsPartialChain -and $IsMissingIssuer -and $UntrustedRootWithNoDownloadPath) {
            Write-Output "The root CA certificate is not currently trusted on this local machine. The certificate on $fqdn did not specify the download source for its CA certificate.  If you trust the certificate, you will need to obtain it an manually install it."
            Write-Warning "Make sure you trust the endpoint before installing any certificate on your local machine."
        }
        if ($CertSelfSigned -and $IsUntrustedRoot) {
            Write-Output "Certificate is self signed and is not installed in the 'local computer' account 'Trusted Root Certification Authorities' store. "
            Write-Output "If you trust $fqdn, you can install the certificate manually (find the cert $certPath)"
        }
    
        If ($IsChainRevoked) {
            Write-Output "$fqdn's Certificate has been REVOKED.  The remote endpoint will need a new certificate before it can be trusted."
        }

        if ($IsPartialChain -and $IsMissingIssuer -and ($CRLurlsarray -or $CRLurlsarray) -and !$proxyUrl -and !$crlLdap) {
            Write-Output "If URLs are listed above, Examine the URLs that are not allowing access to CRL and Cert downloads.  IF certificate URLs above were successful downloading, try to run the -softfix arguement and run this command again.`nOtheriwse, Consider allowing/whitelisting them on network blockers so security checks can properly complete."
        }
        if (!$CRLurlsarray -and $crlLdap) {
            #write-verbose "This machine, in almo st all cases, will need to be domain joined and have network access to the Certificate Authority Server (CA Server) to properly verify CRLs.  However, if the certificate authority's certificate is trusted (installed on the local machines's 'Trusted Root Certification Authorities' certificate store), connection may be successful. (forced revocation will prevent connections though)"
            Write-Output "Certificate revocation checks are 'Domain/LDAP' dependant"
        }
        if (!$CRLurlsarray -and $crlLdap -and $TopLevelCertIsInstalled -and !$isDomainJoined) {
            Write-Output "Connections will be successfull because the domain's CA certificate is trusted/installed on this machine.  However, connections that require/force revocation checks will fail."
            Write-Output ""
        }
        if (($CRLDownloadFailed -or $CRLLdapFailedList -or $CRLUrlsFailedList) -and $TopLevelCertIsInstalled -and !$IsPartialChain -and !$crlLdap) {
            write-output "If the connection is working through your application, then no changes are currently required. Not all applications force revocation checks.  However, if your application forces revocation checks, then you will have connection issues to $fqdn.  Please allow/whitelist the URLs listed below on any network blockers (such as firewall and proxy):`n  $CRLUrlsFailedList`n  $CRTUrlsFailedList`n"
            write-output " --Potential Remediation(fix)-- Machines that do not allow certification revocation checks (because of network blocking or otherwise) may be a security concern for you or your company.  Allow connections to verify certificate revocation endpoints, when possible, to avoid allowing insecure certificates to continue running if they have been revoked."
        }
        elseif ($crlLdap -and !$isDomainJoined -and !$TopLevelCertIsInstalled) { Write-Output "This machine is not domain joined and the certificate revocation check requires LDAP in order to verify revocation status." }
        If (!$TopLevelCertIsInstalled -and $IsPartialChain -and $CRLurlsarray -and !$crlLdap -and !$proxyUrl) {
            Write-Output "Certificate's root authority is not trusted on this local machine - if this computer unable to access the .crt and .crl files listed above you will need to either:`n1) manaully download and install the certificates to the local computer account's 'Trusted Root Certification Authorities' store.`n2) Verify and whitelist (allow) URL/s shown above on network blockers such as firewall, proxies, etc."
        }

        if (!$TopLevelCertIsInstalled -and $IsPartialChain -and $IsMissingIssuer -and $proxyUrl -and !$crlLdap -and !$CRLDownloadFailed -and !$CRTDownloadFailed) {
            Write-Output "--The certificate chain for endpoint $fqdn could not be built to a trusted root authority.`n" 
           # Write-Output "--Potential Remediation(fix)-- Since you are using a proxy, you can try using the -softProxyFix argument, which will backup current settings then temporarily enable/set internet options proxy, contact endpoint, then change settings to as they were. After you run the script with the -softProxyCertFix argument, proceed to rerun this script without the arguement."
            write-output "--Potential Remediation(fix)-- Enable/Turn on 'internet options' proxy using the proxy settings provided when you ran this script (either internet options or settings -> search for proxy).  Then rerun this script.  If successful, then you will need to leave proxy 'internet options' enabled to update certificate chains.`n*Reason: The certificate download and caching process requires that the applications involved in certificate verification can access the endpoints.  Although those certificate endpoints are accessible when adding the proxy to this script, the application for certificate utilities cannot use the proxy specified in this script to download and cache the certificates.  Therefore, you must set this machine's internet proxy in order for the application to access the certificates (then the application will be able to check and download/cache the certificate)"
            write-output "`nOnce you have set the proxy, rerun this script.  [enable via 'internet options' proxy  or  Start -> Settings -> seacrch for 'Proxy' -> choose Proxy Settings -> Set the proxy "
        }
         if (!$TopLevelCertIsInstalled -and $IsPartialChain -and $IsMissingIssuer -and $proxyUrl -and !$crlLdap -and ($CRLDownloadFailed -or $CRTDownloadFailed)) {
            Write-Output "--The certificate chain for endpoint $fqdn could not be built to a trusted root authority.`n" 
            write-output "It's likely that the proxy is unable to access the endpoints required to verifiy revocation download and cache the certificates.  Make sure any network blockers (firewalls, etc.) whitelist the CRL and CRT URLs listed above."
        }
        If (!$TopLevelCertIsInstalled -and $IsPartialChain -and !$CRLurlsarray -and $crlLdap) {
            Write-Output "--Potential Remediation(fix)-- Certificate's root authority is not trusted on this computer - If you trust $fqdn, Manually obtain and install the domain's Root CA certificate/s to the local computer account's 'Trusted Root Certification Authorities' store. Then try to run this script again."
        }
        If ($TopLevelCertIsInstalled -and !$existsIntermediate -and ($CertCount -ge 3) -and $IsPartialChain) {
            write-output "Root Certificate is installed`nIntermediate certificate is NOT installed`nConnection may still be successful, because the root certificate is trusted, but some scenarios require intermediate cerficates to be installed.  If you are having issues connecting, install the intermediate certificate listed and try script again"
        }
        If ($TopLevelCertIsInstalled -and !$isCertTrusted -and !$isMissingIssuer -and $isRevocationStatusUnknown -and !$isChainExpired -and $proxyUrl) {
            Write-Output "Connections to $fqdn without revocation checks will be successful because the root CA certificate is installed locally in this computer account's certificate store.  However, this computer cannot currently verify if the certificate has been revoked - which may be considered a security concern."
            Write-Output ""
            write-output "--Potential Remediation(fix)-- Since you specified a proxy to run this script, enabling the same proxy information in your 'internet options' may resolve this issue.  `nDepending on your version of Windows, you should enable proxy either from the start -> Settings OR from Control Panel -> internet options -> Connections tab -> Configure proxy settings.`nRun the script again once proxy is enabled to update certificates and cache."
        }
        write-output ""
      
        Write-Verbose -Verbose "Log files and certs saved to: $logdir\"
        Write-Output "`n############ END $fqdn ############`n`n`n"
    } 
    
    catch {

        if ($_ -match "SSPI Failed") {

            $os = Get-CimInstance Win32_OperatingSystem
            Write-Output "`nTLS Connection: Failed`n"
            Write-Warning "SSPI Failed (cipher suite or TLS version issue)." #VERIFY Server 2012R2 WITH MISSING Ciphers causes this and add the requirements to this line. 
            Write-Output "SSPI Failed - Server may throw this error if it cannot trust the connection (cipher suite or TLS version)." | Add-Content $logFailuresPath -Encoding utf8
            $required2012KB = Get-HotFix | Where-Object -Property HotFixID -match 2919355  | Format-List | Out-String | Add-Content $logFailuresPath -Encoding utf8
            #Add a check for 2012 r2 ciphers and link the KB update to get relevant ciphers for 2012r2 here.
            if (($PSVersionTable.PSVersion -le [Version]"5.0") -and ($os.Caption -like "*Server 2012 R2*")) {
                Write-Output "Cipher Suites Enabled on this machine:" | Out-String | Add-Content $logFailuresPath -Encoding utf8
                $localCiphers = (get-itemproperty HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions).Functions
                $localCiphers | Out-String | Add-Content $logFailuresPath -Encoding utf8
                write-ouTput "`nServer 2012R2: Checking if KB2919355 is installed:"
                
                if (!$required2012KB) {
                    Write-Output "`nKB2919355 is NOT currently installed - Windows Update KB2919355 is required for 2012R2 to enable relevant/newer TLS 1.2 cipher suites.`n`n1) Install KB2919355`nhttps://www.microsoft.com/en-US/download/details.aspx?id=42334&msockid=1766e8e229ce6891375dfc5f28dd69e9`n  Direct Download Link:`nhttps://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2919355-x64.msu`n2) OR check for updates via Windows Update Service and install the latest available updates before trying to connect again"
                    Write-output "KB2919355 is NOT installed - Windows Update KB2919355 is required for 2012R2 to enable current/relevant/newer TLS 1.2 cipher suites.`n1) Install KB2919355: https://www.microsoft.com/en-US/download/details.aspx?id=42334&msockid=1766e8e229ce6891375dfc5f28dd69e9`nDirect Download Link:`nhttps://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2919355-x64.msu`n2) Update OS to latest available updates before trying to connect again" | Out-String | Add-Content $logFailuresPath -Encoding utf8
                    $log = Write-Output "SOLUTION: Install Windows Updates and verify that KB2919355 is installed.  After Updates you will need to reboot for the changes to take effect."
                    Write-Output $log | Out-String | Add-Content $logFailuresPath -Encoding utf8
                }
                elseif ($required2012KB) {
                    Write-Output "KB2919355 is installed`n1) Check enabled ciphers by re-running this script and use the -cipherCheck " + '$true'
                    Write-Output "Possible Solution: SSPI errors indicate that there may be a cipher suite error/issue.  Verify cipher suites enabled on the local machine and compare to results when checking $fqdn via https://www.ssllabs.com/ssltest/"
                }
                
            }
            
        }  
        #"Error: $_"
        # Did TCP connection fail?
        if (!$tcpClient.Connected) {
            #proxy check for the same occurs earlier so it's not checked here.
            #Check if the initial TCP connection was successful, but the connection was closed during TLS handshake, then the firewall will show 'allow' on tcp but denied the rest of the connection.  This would be Firewall configuration issue.
            if (!$tcpClient.Connected -and !$initialTCPConnection -and !$proxyUrl){
            Write-Output "TCP Connection Failed"
            }
            if (!$tcpClient.Connected -and $initialTCPConnection) {
            Write-Output "TCP Connection was interrupted"
            }

            # If initial TCP was successful, but the connection was closed during TLS handshake, then the firewall will show 'allow' on tcp but denied the rest of the connection.  This would be Firewall configuration issue.
            if ($initialTCPConnection) {
                Write-Output "TCP connection was initially allowed, but the connection was terminated.  This indicates the TLS secure connection was blocked to $fqdn but initial TCP connection was allowed.  Company/User that deployed firewall/proxy (and/or other network blocker) should investigate internally to determine why the TLS connection was blocked from this machine.`n"
                Write-Output "--Potential Remediation(fix)-- Allow/whitelist the URL '$fqdn' on the firewall and/or other network blockers and try this script again.`n"
                write-output "--Potential Remediation(fix)-- Should this connection be using a proxy to connect?  If so, use the proxy argument ( -proxyUrl 'http://yourproxy.com:portnumber') and run the script again.`n"
            }

            $ResolvedDns = Resolve-DnsName $fqdn -ErrorAction SilentlyContinue -ErrorVariable ErrorDNS | Out-Null
            
            if ($ErrorDns -match "DNS name does not exist") {
                $ErrorDns | Out-String | Add-Content $logFailuresPath -Encoding UTF8
                write-output "DNS server did not resolve $fqdn  <-- this is normal if an IP address is used rather than a URL and reverse DNS lookup zone is not configured"
            }
            if ($ErrorDns -match "No DNS servers configured for local system") {
                write-output "Cannot reach a DNS server.  Check network settings"
            }
            if (($ResolvedDns -notmatch 0.0.0.0) -and ($ResolvedDns)) {
                Write-Warning "Initial TCP Connection Failed!`n1) Is the HostName or IP,and port correct/valid?`n2) Check if local network is connected`n3) Verify if any network blockers are preventing the connection to $fqdn"
                write-warning "TLS Session: No attempt to create TLS session because initial TCP connection failed."
            }
            $ResolvedDNS = Resolve-DnsName $fqdn
            if ($_ -match "no data of the requested type was found") {
                #Write-Output "Check ciphers - do cipher suites enabled on this machine match the endpoint's ($fqdn) allowed cipher suites?) <-- Can check using ssllabs.com"
                write-output "DNS RESOLVED $fqdn to:"
                $ResolvedDns
            }
            ### ADD TODO ### Add hosts file check in the 'if' statement below to see if endpoint is currently in the HOSTS file (and report if so to the logs.  Searching in particular to see if old private IP is still being used, or any incorrect IP).
            if (($ResolvedDNS -match 0.0.0.0) -and ($ResolvedDNS) -and $proxyUrl -and ($_ -match "forcibly closed")) {
                #$_ -match "forcibly closed"
                Write-Output "`n---Potential Remediation(fix)--- `n** The connection was refused by the proxy host or the proxy host does not exist.`n1) Check if this machine is allowed (has permission) to access the proxy AND verify that the proxy can access the URL ($fqdn)`n"
            }
            elseif (($ResolvedDNS -match 0.0.0.0) -and ($ResolvedDNS) -and ($_ -match "host has failed to respond")) {
                Write-Output "Timeout occured.  Is the IP address or fqdn correct?"
                if ($proxyUrl){
                    Write-Output "Since a proxy was specified, check if the proxy is reachable and if the proxy can access the URL ($fqdn)"
                }
            }
            elseif (($ResolvedDNS -match 0.0.0.0) -and ($ResolvedDNS) -and (!$initialProxyTCPConnection -and !$initialTCPConnection)) {
                Write-Output "`n--Potential Remediation(fix)--DNS resolved $fqdn IP to: 0.0.0.0 - Resolving DNS name to 0.0.0.0 IP address usually indicates `n1) No network connection `n2) Network blocking (firewall or proxy blocker) and/or DNS blackhole configured.  `n`nPotential Solutions(Fixes): `n1) Check if this local machine is connected to a network `n2) Allow/Whitelist $fqdn on all network blockers (Firewall, Proxy, and any other blocker) and try running the script again. `n3) Check hosts file (C:\Windows\System32\Drivers\etc\hosts) `nExample: Is $fqdn listed in the hosts file? If so, is the IP correct?"`n
            } 
          
              
        }



        # Display SSL stream information.  Do not show SSL stream information if cert is not trusted (reason: script is set to ignore trust issue to get certificate regardless if TLS handshake completes - so this ssl stream will show a tls connection occured, but ONLY because we planned to ignore the initial trust failure to gather certificate and check 'why' TLS failed).
        if ($TLSVersion -and !$IsPartialChain -and !$IsChainExpired -and !$IsRevocationStatusUnknown -and !$IsOfflineRecovation -and !$IsUntrustedRoot -and !$IsMissingIssuer -and !$IsChainRevoked) {
            
            # Display certificate information
            #$sslStream | Select-Object -Property SslProtocol, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus | Format-List
            #$certInfo = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $sslStream.RemoteCertificate
            #$certInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
        }

        Write-Warning "Failed to connect to: $($fqdn):$port - $($_.Exception.Message)`n"
      
        ##LOGGING
        write-output "Failed to connect to: $($fqdn):$port - $($_.Exception.Message)" | Add-Content $logFailuresPath -Encoding utf8
        #$_
        write-output $_ | Add-Content $logFailuresPath -Encoding utf8

        ## LOG SPECIFIC PROBLEMS
        if (!$isCertTrusted -and $IsChainExpired) {
            write-warning "The Endpoint |$fqdn| is using an expired certificate which will need to be replaced on the (web server's)/(endpoint's) side before this endpoint can be trusted."
            write-output "The Endpoint |$fqdn| is using an expired certificate which will need to be replaced on the (web server's)/(endpoint's) side before this endpoint can be trusted." | Add-Content $logFailuresPath -Encoding utf8
            #if ($repair){} # REPAIR/FIX STEPS
        }
        <#
        "error: "
        $PSItem.Exception.Message
        $PSItem.Exception.StackTrace
        #>
        write-output ""
        Write-Verbose -Verbose "Log files and certs saved to: $logdir\"
        Write-Output "############ END $fqdn ############`n`n`n`n"
         
    }

    finally {
         # Check if the console is running in older versions of ISE or not.  If it is, then the console output will not be logged.
        if (($PSVersionTable.PSVersion -le [Version]"5.0") -and ($host.Name -match "ISE")) {
            Write-Warning "Console Output will not be logged (transcripting is not supported in older versions of ISE).  If this is Server 2012R2 or older, use the PowerShell Console (Not ISE) to get console output.`n -> Since you are using ISE, PLEASE COPY THE OUTPUT ABOVE MANUALLY AND SAVE IT TO A TEXT FILE IN THE LOG DIRECTORY BELOW!" 
        }
        else {
            Stop-Transcript
        }
        # Close the SSL stream and TCP client
        if ($sslStream) {
            #$sslStream.Close()
            $sslStream.Dispose()
        }
        if ($networkStream) {
            $networkStream.Close()
        }
        if ($tcpClient) {
            #$tcpClient.Close()
            $tcpClient.Dispose()
        }
        if ($webClient) {
            $webClient.Dispose()
        }
        if ($searcher) { #used to be $entry rather than searcher - verify 
            $searcher.Dispose()
        }      
    }
}



### Usage: Test-TlsConnection -fqdn "example.com" -port 443 -proxyUrl "http://proxyserver:port"




#Test-TlsConnection "gbl.his.arc.azure.com" #-proxyUrl "http://10.10.10.99:3128"
#Test-TlsConnection "login.microsoftonline.com"
