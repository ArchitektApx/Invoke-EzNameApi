# Invoke-EzNameApi
A Powershell Module that provides a Client for the easyname.com API base on the PHP SDK
at https://github.com/easyname/php-sdk

All sensitive informations are handled as SecureStrings.
The API Client tries its best to keep all values as SecureStrings
for as long as possible and clear all plaintext informations from 
memory as soon as possible.

## First Time Use 
Invoke the Client based on your API Credentials 
Please use this only for the first time you use this Client.

```powershell   
$APIClient = Invoke-EzNameAPI -APIKey <..> -APISalt <..> -APIUserID >..> -APIUserMail <..> -APISigningSalt <..>
```

## Save your API Config securely
You can save your APIConfig securely and encrypted as a File for later use

```powershell  
$APIClient.APIConfigToFile("<Your Filepath>")
```

This saves a CliXML where all sensitve data is stored as a SecureString 
and is therefore encrypted by the Microsoft Data Protection API

## Use your encrypted API Config

Invoke the Client on a saved Config File
```powershell 
    $APIClient = Invoke-EzNameAPI -FilePath <your config clixml>
```

## Methods 

Unfortunately there is no documentation on the API besides the PHP-SDK
Take a look at the Powershell Help for Invoke-EzNameAPI and the 
Methods in EzNameClass.ps1 to see all available Methods and their parameters