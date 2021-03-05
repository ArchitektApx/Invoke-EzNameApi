class EzNameAPIClient {
    <# 
        Class Properties
    #> 
    hidden [hashtable] $Header
    hidden [PSCustomObject] $APIConfig
    hidden [string] $EzNameUrl = 'https://api.easyname.com'

    <#
        Constructors 
    #>
    # Default Constructor
    EzNameAPIClient ([string] $APIKey, [string] $APISalt, [string] $APIUserID, [string] $APIUserMail, [string] $APISigningSalt, [bool]$debug) {
        $this.APIConfig = [PSCustomObject]@{
            APIKey         = ConvertTo-SecureString -AsPlainText $APIKey -Force
            APISalt        = ConvertTo-SecureString -AsPlainText $APISalt -Force
            APIUserID      = $APIUserID
            APIUserMail    = $APIUserMail
            APISigningSalt = ConvertTo-SecureString -AsPlainText $APISigningSalt -Force
            APIDebug       = $debug
        }
        $this.APIConfigToAuthHeader([PSCustomObject]$this.APIConfig)
    }
    # Construtctor for FilePath
    EzNameAPIClient ([string]$FilePath, [bool]$debug) {
        $this.APIConfig = Import-Clixml -Path $FilePath
        $this.APIConfigToAuthHeader([PSCustomObject]$this.APIConfig)

        # override the Debug value of the config file if -Debug parameter was set
        if ($debug -eq $true) {
            $this.APIConfig.APIDebug = $true
        }
    }

    <# 
        Helper Methods
    #>
    # helper method for both constructors 
    hidden [void] APIConfigToAuthHeader([PSCustomObject]$APIConfig) {
        $AuthString = $this.InitAuthString($this.APIConfig.APISalt, $this.APIConfig.APIUserID, $this.APIConfig.APIUsermail)
        $this.Header = $this.InitAuthHeader($this.APIConfig.APIKey, $AuthString)
    }
    # Method to create the authentication stringd
    hidden [string] InitAuthString([securestring]$AuthSalt, [string]$ID, [string]$Email) { 
        $PlainSalt = $this.SecureStringToPlain($AuthSalt)

        # replace just like sprintf in PHP does
        [regex]$R = '%s'
        $String = $R.Replace($R.Replace($PlainSalt, $ID, 1), $Email, 1)

        # MD5 of String
        $MD5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $UTF8 = [System.Text.UTF8Encoding]::new()
        $MD5Hash = ([System.BitConverter]::ToString($MD5.ComputeHash($UTF8.GetBytes($String)))).ToLower() -replace '-', '' 

        # remove the plaintexts from memory
        $PlainSalt = $null
        $String = $null 
        [System.GC]::Collect()

        # Base64 return
        return [Convert]::ToBase64String($UTF8.GetBytes($MD5Hash))
    }
    # Method to create Header from auth string and api key
    hidden [HashTable] InitAuthHeader([securestring] $APIKey, [string] $AuthString) {
        $Output = @{
            'X-User-ApiKey'         = $APIKey
            'X-User-Authentication' = $AuthString
            'Content-Type'          = 'application/json'
        }
        return $Output
    }

    # Method to save APIConfig to File for later use with $FilePath Constructor
    [void] APIConfigToFile ([string]$FilePath) {
        $this.APIConfig | Export-Clixml -Path $FilePath 
    }

    hidden [string] SecureStringToPlain([securestring]$SecureString) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $Plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $Plain
    }

    # Main Method for all Requests to the API
    # null|int|array $filter 
    hidden [Object[]] DoRequest([string]$type, [string]$resource, [int]$id, [string]$subResource, [int]$subId, $data, [string]$perform, [int]$limit, [int]$offset, $filter) {

        $uri = '/' + $resource

        if ($id) {
            $uri += '/' + [string]$id
        }
        if ($subResource) {
            $uri += '/' + $subResource
        }
        if ($subId) {
            $uri += '/' + [string]$subId
        }
        if ($perform) {
            $uri += '/' + $perform
        }

        $uriParameters = @{}

        if ($type -eq 'GET') {
            if ($null -ne $offset) {
                $uriParameters['offset'] = [int]$offset
            }
            if ($null -ne $limit) {
                $uriParameters['limit'] = [int]$limit
            }
            if ($null -ne $filter) {
                if ($filter -is [array]) {
                    $uriParameters['filter'] = $filter -join ','
                } else {
                    $uriParameters['filter'] = [int]$filter
                }
            }
        }

        if ($this.APIConfig.APIDebug -eq $true) {
            $this.Header['X-Readable-JSON'] = [int]$this.APIConfig.APIDebug
        }

        if ($uriParameters.keys.count -gt 0) {
            $uri += '?'
            $uri += ($uriParameters.keys | ForEach-Object { $_ + '=' + $uriParameters[$_] }) -join '&'
        }

        $url = $this.EzNameUrl + $uri

        $Body = $null 
        if ($type -eq 'POST') {
            $Body = $this.createBody($data)
        }

        $this.WriteDebug(($type + ':' + $url))

        try {
            $PlainHeader = $this.Header.Clone()
            $PlainHeader['X-User-ApiKey'] = $this.SecureStringToPlain($this.Header['X-User-ApiKey'])

            $response = Invoke-RestMethod -Method $type -Uri $url -Headers $PlainHeader -Body $Body

            $PlainHeader = $null
            [System.GC]::Collect()
        } catch {
            throw $_
        }

        $this.WriteDebug($response)

        return $response
    }

    hidden [string] CreateBody($data) {
        if (!$data) {
            $data = @()
        }

        [int]$timestamp = [int]([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()

        $body = [ordered]@{
            data      = [Object]$data
            timestamp = $timestamp
            signature = $this.SignRequest($data, $timestamp)
        }

        return [uri]::EscapeDataString(($body | ConvertTo-Json -Depth 100 -Compress))
    }
     
    hidden [string] SignRequest([array] $data, [int]$timestamp) {
        $string = ''
        $Keys = ($data.Keys + @('timestamp')) | Sort-Object

        foreach ($Key in $Keys) {
            if ($Key -ne 'timestamp') {
                $string += [string]$data.$Key
            } else {
                $string += [string]$timestamp
            }
        }

        $length = if (($string.Length % 2) -eq 0) { [int]($string.Length / 2) } else { [int][math]::Ceiling(($string.Length / 2)) }
        $signatureString = $string.Substring(0, $length) + $this.SecureStringToPlain($this.APIConfig.APISigningSalt) + $string.Substring($length)
        $MD5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $UTF8 = [System.Text.UTF8Encoding]::new()
        $MD5Hash = ([System.BitConverter]::ToString($MD5.ComputeHash($UTF8.GetBytes($signatureString)))).ToLower() -replace '-', '' 
        
        $signatureString = $null
        [System.GC]::Collect()

        return [Convert]::ToBase64String($UTF8.GetBytes($MD5Hash))
    }

    hidden [void] WriteDebug($data) {
        if ($this.APIConfig.APIDebug -eq $true) {
            Write-Debug $(Get-Date).ToString() 
            if ($data -is [string]) {
                Write-Debug ($data + [System.Environment]::NewLine)
            } else {
                Write-Debug ($data | Out-String).Trim()
            }
        }
    }

    <#
        Methods for API Requests
    #>
    # Get specific Domain by ID
    [Object] GetDomain([int]$DomainID) {
        return $this.DoRequest('GET', 'domain', $DomainID, $null, $null, $null, $null, $null, $null, $null)
    }

    # List all active Domains 
    [Object[]] ListDomain() {
        return $this.ListDomain($null, $null, $null)
    }
    [Object[]] ListDomain($limit, $offset) {
        return $this.ListDomain($limit, $offset, $null)
    }
    [Object[]] ListDomain($limit, $offset, $filter) {
        # This Request seems to be limited to 50 Domains 
        # there seems to be no indication on the total amount therefore we just have to try
        if ($null -ne $limit -and $null -ne $offset) {
            $Result = $this.DoRequest('GET', 'domain', $null, $null, $null, $null, $null, $limit, $offset, $filter)
        } else {
            $offset = 0
            $Result = do {
                $ThisRequest = $this.DoRequest('GET', 'domain', $null, $null, $null, $null, $null, $limit, $offset, $filter)
                $ThisRequest
                $offset += 50
                Start-Sleep -Milliseconds 20
            } while ($ThisRequest.data.count -ne 0)
        }

        $Output = [PSCustomObject]@{
            data      = $Result.data
            status    = $Result[-1].status
            timestamp = $Result[-1].timestamp
        }
    
        return $Output  
    }

    # Register a new Domain
    [Object[]] CreateDomain([string]$domain, [int]$registrantContact, [int]$adminContact, [int]$techContact, [int]$zoneContact, [array]$nameservers, [bool]$trustee) {
        $tmpNameservers = @{}
        for ($i = 0; $i -lt 6; $i++) {
            if ($nameservers[$i]) {
                $tmpNameservers[$('nameserver' + $($i + 1))] = $nameservers[$i]
            }
        }      
        $DataHt = [ordered]@{
            domain            = $domain
            registrantContact = $registrantContact
            adminContact      = $adminContact
            techContact       = $techContact
            zoneContact       = $zoneContact
            trustee           = [int]$trustee
            transferIn        = 1
        }
        $Merge = $DataHt + $tmpNameservers
        return $this.DoRequest('POST', 'domain', $null, $null, $null, $Merge, $null, $null, $null, $null)
    }

    # Transfer an existing domain name.
    [Object[]] TransferDomain([string]$domain, [int]$registrantContact, [int]$adminContact, [int]$techContact, [int]$zoneContact, [array]$nameservers, [bool]$trustee, [string]$transferAuthcode) {
        $tmpNameservers = @{}
        for ($i = 0; $i -lt 6; $i++) {
            if ($nameservers[$i]) {
                $tmpNameservers[$('nameserver' + $($i + 1))] = $nameservers[$i]
            }
        }
        $tmpTransferAuthcode = @{transferAuthcode = $transferAuthcode }
        
        $DataHt = [ordered]@{
            domain            = $domain
            registrantContact = $registrantContact
            adminContact      = $adminContact
            techContact       = $techContact
            zoneContact       = $zoneContact
            trustee           = [int]$trustee
            transferIn        = 1
        }

        $Merge = $DataHt + $tmpNameservers + $tmpTransferAuthcode
        
        return $this.DoRequest('POST', 'domain', $null, $null, $null, $Merge, $null, $null, $null, $null)
    }

    # Delete a specific domain instantly by id
    [Object[]] DeleteDomain([int]$id) {
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $null, 'delete', $null, $null, $null)
    }

    # Re-purchase a previously deleted domain.
    [Object[]] RestoreDomain([int]$id) {
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $null, 'restore', $null, $null, $null)
    }

    # Set an active domain to be deleted on expiration
    [Object[]] ExpireDomain([int]$id) {
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $null, 'expire', $null, $null, $null)
    }

    # Undo a previously commited expire command
    [Object[]] UnexpireDomain([int]$id) {
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $null, 'unexpire', $null, $null, $null)
    }

    # Change the owner of an active domain
    [Object[]] ChangeOwnerOfDomain([int]$id, [int]$registrantContact) {
        return $this.DoRequest('POST', 'domain', $id, $null, $null, @{registrantContact = $registrantContact }, 'ownerchange', $null, $null, $null)
    }

    # Change additional contact of an active domain
    [Object[]] ChangeContactOfDomain([int]$id, [int]$adminContact, [int]$techContact, [int]$zoneContact) {
        $DataHt = [ordered]@{
            adminContact = $adminContact
            techContact  = $techContact
            zoneContact  = $zoneContact
        }
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $DataHt, 'contactchange', $null, $null, $null) 
    }

    # Change the nameserver settings of a domain
    [Object[]] ChangeNameserverOfDomain([int]$id, [array]$nameservers) {
        $tmpNameservers = @{}
        for ($i = 0; $i -lt 6; $i++) {
            if ($nameservers[$i]) {
                $tmpNameservers[$('nameserver' + $($i + 1))] = $nameservers[$i]
            }
        }
        return $this.DoRequest('POST', 'domain', $id, $null, $null, $tmpNameservers, 'nameserverchange', $null, $null, $null)
    }

    <#
        Contact related Methods
    #>

    # Get information for specific contact by id
    [Object[]] getContact([int]$id) {
        return $this.DoRequest('GET', 'contact', $id, $null, $null, $null, $null, $null, $null, $null)
    }

    # Get List all Contacts 
    [Object[]] ListContact() {
        return $this.ListContact($null, $null, $null)
    }
    [Object[]] ListContact($limit, $offset) {
        return $this.ListContact($limit, $offset, $null)
    }
    [Object[]] ListContact($limit, $offset, $filter) {
        # This Request seems to be limited to 50 Contacts 
        # there seems to be no indication on the total amount therefore we just have to try
        if ($null -ne $limit -and $null -ne $offset) {
            $Result = $this.DoRequest('GET', 'contact', $null, $null, $null, $null, $null, $limit, $offset, $filter)
        } else {
            $offset = 0
            $Result = do {
                $ThisRequest = $this.DoRequest('GET', 'contact', $null, $null, $null, $null, $null, $limit, $offset, $filter)
                $ThisRequest
                $offset += 50
                Start-Sleep -Milliseconds 20
            } while ($ThisRequest.data.count -ne 0)
        }

        $Output = [PSCustomObject]@{
            data      = $Result.data
            status    = $Result[-1].status
            timestamp = $Result[-1].timestamp
        }
    
        return $Output  
    }

    # Create a contact
    # array|null $additionalData
    [Object[]] CreateContact([string]$type, [string]$alias, [string]$name, [string]$address, [string]$zip, [string]$city, [string]$country, [string]$phone, [string]$email, $additionalData) {
        if (!$additionalData) {
            $additionalData = @()
        }
        $DataHt = [ordered]@{
            type    = $type
            alias   = $alias
            name    = $name
            address = $address
            $zip    = $zip
            $city   = $city
            $phone  = $phone
            $email  = $email 
        }
        $Merged = $DataHt + $additionalData
         
        return $this.DoRequest('POST', 'contact', $null, $null, $null, $Merged, $null, $null, $null, $null)
    }

    # Modify a specific contact
    # array|null $additionalData
    [Object[]] UpdateContact([int] $id, [string] $alias, [string]$address, [string]$zip, [string] $city, [string]$phone, [string]$email, $additionalData) {
        if (!$additionalData) {
            $additionalData = @()
        }
        $DataHt = [ordered]@{
            alias   = $alias
            address = $address
            $zip    = $zip
            $city   = $city
            $phone  = $phone
            $email  = $email 
        }
        $Merged = $DataHt + $additionalData

        return $this.DoRequest('POST', 'contact', $id, $null, $null, $Merged, $null, $null, $null, $null)
    }

    # Delete a specific contact
    [Object[]] DeleteContact([int]$id) {
        return $this.DoRequest('DELETE', 'contact', $id, $null, $null, $null, $null, $null, $null, $null)
    }

    <#
        DNS specific methods
        CAUTION: these methods are not officially supported: https://github.com/easyname/php-sdk/commit/c31a41681bf280dd7155017de3af9e3db6226a7d
        but some of them seem to work properly nevertheless
    #>

    # Fetch information about a single DNS record
    # Seems to work 
    [Object[]] GetDns([int]$domainID, [int]$id) {
        return $this.DoRequest('GET', 'domain', $domainid, 'dns', $id, $null, $null, $null, $null, $null)
    }

    # List all DNS Records for specific Domain via DomainID
    # Seems to work 
    [Object[]] ListDns([int]$id) {
        return $this.DoRequest('GET', 'domain', $id, 'dns', $null, $null, $null, $null, $null, $null)
    }
    
    # Create a DNS record for a specific domain
    # Error 400 returned - > doesn't seem to work
    [Object[]] CreateDns([int]$domainID, [string]$name, [string]$type, [string]$content, [int]$priority, [int]$ttl) {
        $DataHt = [ordered]@{
            name     = $name
            type     = $type
            content  = $content
            priority = $priority
            ttl      = $ttl
        }
        return $this.DoRequest('POST', 'domain', $domainID, 'dns', $null, $DataHt, $null, $null, $null, $null)
    }

    # Modify a specific DNS Record
    # Internal Error 500 returned -> doesn't seem to work 
    [Object[]] UpdateDns([int]$domainID, [int]$id, [string]$name, [string]$type, [string]$content, [int]$priority, [int]$ttl) {
        $DataHt = [ordered]@{
            name     = $name
            type     = $type
            content  = $content
            priority = $priority
            ttl      = $ttl
        }
        return $this.DoRequest('POST', 'domain', $domainID, 'dns', $id, $DataHt, $null, $null, $null, $null)
    }

    # Delete a specific DNS record 
    # Seems to work 
    [Object[]] DeleteDns([int]$domainID, [int]$id) {
        return $this.DoRequest('POST', 'domain', $domainID, 'dns', $id, $null, 'delete', $null, $null, $null)
    }

    <#
        User specific methods
    #>

    # Get User Balance
    [Object[]] GetUserBalance() {
        return $this.DoRequest('GET', 'user', $this.APIConfig.APIUserID, 'balance', $null, $null, $null, $null, $null, $null)
    }

}