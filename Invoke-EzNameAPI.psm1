#Requires -version 5
<#
.SYNOPSIS
    A Powershell Client for the easyname.com API
.DESCRIPTION
    A Powershell Client for the easyname.com API base on the PHP SDK
    at https://github.com/easyname/php-sdk

    All sensitive informations are handled as SecureStrings.
    The API Client tries its best to keep all Values as SecureStrings
    for as long as possible and clear all plaintext informations from 
    Memory as soon as possible.
.PARAMETER APIKey
    Your EasyName API Key
.PARAMETER APISalt
    Your EasyName API Authentication Salt
.PARAMETER APIUserID
    Your EasyName Customer ID
.PARAMETER APISigningSalt
    Your EasyName API Signing Salt
.PARAMETER FilePath
    A Filepath to an api config file generated by this API-Client 
.EXAMPLE
    Invoke the Client based on your API Credentials 
    $APIClient = Invoke-EzNameAPI -APIKey <..> -APISalt <..> -APIUserID >..> -APIUserMail <..> -APISigningSalt <..>

    Please use this only for the first time you use this Client.
    You can save your APIConfig as a File with $APIClient.APIConfigToFile("<Your Filepath>") for later use
    all sensitve data will be stored as a SecureString and is therefore
    encrypted by the Microsoft Data Protection API
.EXAMPLE 
    Invoke the Client on a saved Config File
    $APIClient = Invoke-EzNameAPI -FilePath <your config clixml>
.EXAMPLE

    # Domain related Methods

    $APIClient.listDomain() - List all of your domains
    $APIClient.getDomain(1) - Get specific informations on a domain by its domainID
    $APIClient.createDomain("example.com", 23, 23, 23, 23, array(), false) - Create a new domain
    $APIClient.transferDomain("example.com", 23, 23, 23, 23, array(), false, 'aaaaaa') - Transfer a domain
    $APIClient.changeOwnerOfDomain(1, 23) - Change the Owner of a domain
    $APIClient.changeContactOfDomain(1, 23, 23, 23) - Change the Contact information of a domain
    $APIClient.changeNameserverOfDomain(1, array('ns1.example.com', 'ns2.example.com')) - change the nameservers of a domain
    $APIClient.expireDomain(1) - Set an active domain to be deleted on expiration
    $APIClient.unexpireDomain(1) - Undo a previously commited expire command
    $APIClient.deleteDomain(1) - delete a Domain
    $APIClient.restoreDomain(1) - Re-purchase a previously deleted domain.

    # Contact related Methods 

    $APIClient.listContact() - get all contacts
    $APIClient.getContact(1) - get a specific contact 
    $APIClient.createContact('person', 'John Doe (person)', 'John Doe', 'Street 12/34', '1234', 'Vienna', 'AT', '+4312345678', 'me@example.com', @('birthday' = '1970-01-31')) - create new contact
    $APIClient.updateContact(1, 'John Doe (person)', 'Other Street 56/7', '1234', 'Vienna', '+4312345678', 'me@example.com', @('birthplaceCity' = 'Vienna')) - update a contact
    $APIClient.deleteContact(1) - delete a contact 

    # Account related Methods 

    $APIClient.GetUserBalance() - get your accounts balance

    # DNS related Methods 
    # CAUTION: these methods are not officially supported: https://github.com/easyname/php-sdk/commit/c31a41681bf280dd7155017de3af9e3db6226a7d
    # but some of them seem to work properly nevertheless

    $APIClient.GetDns(1,1) - Get a specific DNS Record by Domain and Record ID
    $APIClient.ListDns(1) - Get all DNS records of a Domain by its ID
    $APIClient.CreateDns() - not working - @EasyName: Please fix this Guys, its 2021 we need this :(
    $APIClient.UpdateDns() - not working - @EasyName: Please fix this Guys, its 2021 we need this :(
    $APIClient.DeleteDns(1) - Delete a specific DNS Record by Domain and Record ID

    Please take a look at the Methods in EzNameClass.ps1 as there is no 
    official documentation by EasyName besiders their PHP-SDK
#>
function Invoke-EzNameAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'FromStrings')]
        [string]$APIKey,
        [Parameter(Mandatory = $true, ParameterSetName = 'FromStrings')]
        [string]$APISalt,
        [Parameter(Mandatory = $true, ParameterSetName = 'FromStrings')]
        [ValidateNotNullOrEmpty()]
        [string]$APIUserID, 
        [Parameter(Mandatory = $true, ParameterSetName = 'FromStrings')]
        [ValidateNotNullOrEmpty()]
        [string]$APIUserMail,
        [Parameter(Mandatory = $true, ParameterSetName = 'FromStrings')]
        [string]$APISigningSalt,
        [Parameter(Mandatory = $true, ParameterSetName = 'FromFilePath')]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )
    
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'FromStrings' {
                [EzNameAPIClient]::New($APIKey, $APISalt, $APIUserID, $APIUserMail, $APISigningSalt, $PSBoundParameters['Debug'].IsPresent)
                $APIKey = $null
                $APISalt = $null
                $APISigningSalt = $null
                Remove-Variable -Name APIKey
                Remove-Variable -Name APISalt
                Remove-Variable -Name APISigningSalt
                [System.GC]::Collect()
            }
            'FromFilePath' {
                [EzNameAPIClient]::New($FilePath, $PSBoundParameters['Debug'].IsPresent)
            }
        }
    }

}

Export-ModuleMember -Function Invoke-EzNameAPI