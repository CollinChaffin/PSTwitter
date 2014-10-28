#=======================================================================#
#
# Author:				Collin Chaffin
# Last Modified:		10/28/2014 12:15 AM
# Filename:				PSTwitter.psd1
#
#
# Changelog:
#
#	v 1.0.0.1	:	10/18/2014	:	Initial release
#	v 1.0.0.2	:	10/28/2014	:	Added 7 new special char to pre(hex) escape
#									and altered code to deal with powershell
#									throwing ex for already valid param length
#									due to escaping adding % char length
#
# Notes:
#
#	This module utilizes personal Twitter's user-specific API
#	information to perform OAuth connection to Twitter and submit either a
#	Tweet or a direct message to a single Twitter recipient.  This module
#	was inspired by Adam Bertram and others but became a rewrite to more formal modular
#	functions using objects which perhaps can spur additional development
#	interest and community-contributed growth and hopefully simplify required
#	code changes to address Twitter API changes in the future!
#
#
# Installation Instructions:
#
#	Run the MSI installer or, if installing manually, copy the
#	PSTwitter.psm1 and PSTwitter.psd files to:
#	"%PSModulePath%PSTwitter"
#
#	HINT: To manually create the module folder prior to copying:
#	mkdir "%PSModulePath%PSTwitter"
#
#	Once installed/copied, open Windows Powershell and execute:
#	Import-Module PSTwitter
#
#	Store your Twitter API information by executing:
#	Set-TwitterOAuthTokens
#
#	If you have gotten this far, you should be able to send your
#	first Tweet by executing:
#	Send-TwitterTweet -TweetMessage "Testing the #PSTwitter #Powershell Module!"
#
# Verification:
#
#	Check "%PSModulePath%PSTwitter\Logs" folder for a daily rotating log.
#	Example log for successful Tweet:
#
#	10/18/2014 21:48:57 :: [INFO] :: START  - Set-TwitterOAuthTokens function execution
#	10/18/2014 21:48:58 :: [INFO] :: FINISH - Set-TwitterOAuthTokens function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Send-TwitterTweet function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - ConvertTo-HexEscaped function execution
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - ConvertTo-HexEscaped function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Connect-OAuthTwitter function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Loading DOTNET assemblies
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - Loading DOTNET assemblies
#	10/18/2014 21:51:07 :: [INFO] :: START  - Retrieving Twitter API settings from registry
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - Retrieving Twitter API settings from registry
#	10/18/2014 21:51:07 :: [INFO] :: START  - New-TwitterOAuthNonce function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Generating oAuthNonce string
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - Generating oAuthNonce string
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - New-TwitterOAuthNonce function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - New-TwitterOAuthTimeStamp function execution
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - New-TwitterOAuthTimeStamp function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - New-TwitterOAuthSignature function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Building OAuth signature
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - Building OAuth signature
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - New-TwitterOAuthSignature function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - New-TwitterOAuthString function execution
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - New-TwitterOAuthString function execution
#	10/18/2014 21:51:07 :: [INFO] :: FINISH - Connect-OAuthTwitter function execution
#	10/18/2014 21:51:07 :: [INFO] :: START  - Sending HTTP POST via REST to Twitter
#	10/18/2014 21:51:08 :: [INFO] :: FINISH - Sending HTTP POST via REST to Twitter
#	10/18/2014 21:51:08 :: [INFO] :: FINISH - Send-TwitterTweet function execution
#
#=======================================================================#

@{

# Script module or binary module file associated with this manifest
ModuleToProcess = 'PSTwitter.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.2'

# ID used to uniquely identify this module
GUID = '0c629d29-f943-4428-bd9a-7cabd82a453c'

# Author of this module
Author = 'Collin Chaffin'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2014. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PSTwitter Windows Powershell Module - Provides OAuth-based access to Twitter API'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '2.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '2.0.50727'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing
# this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to
# importing this module
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in
# ModuleToProcess
NestedModules = @()

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''

}







