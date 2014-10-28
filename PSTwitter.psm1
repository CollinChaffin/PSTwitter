#=======================================================================#
#
# Author:				Collin Chaffin
# Last Modified:		10/28/2014 12:15 AM
# Filename:				PSTwitter.psm1
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


#region Globals

#########################################################################
# 							Global Variables							#
#########################################################################

# General Variables
# Disable psTwitterDebugging for zero output and logging
$psTwitterDebugging = $true
$psTwitterLogging = $true

# Twitter-specific API variables that may change in the future
$Global:psTwitterEndpointTweet			= 'https://api.twitter.com/1.1/statuses/update.json'
$Global:psTwitterEndpointDirectMessage	= 'https://api.twitter.com/1.1/direct_messages/new.json'
$Global:psTwitterOAuthSignatureMethod	= 'HMAC-SHA1'
$Global:psTwitterOAuthVersion			= '1.0'

# Paths
$Global:psTwitterInvocationPath = $([System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition) + "\")
$Global:psTwitterLogPath = $($psTwitterInvocationPath) + "Logs\"
# Override this with a static manual path, if so desired or it defaults to \Logs folder in Module location

#########################################################################

#endregion

#region Functions

#########################################################################
# 								Functions								#
#########################################################################

function Connect-OAuthTwitter
{
	<#
	.SYNOPSIS
		This function utilizes personal Twitter's user-specific API information to perform
		OAuth connection to Twitter and set up the final OAuth string needed to then post a
		Tweet or a direct message to a single Twitter recipient using the REST API.
		
	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function utilizes personal Twitter's user-specific API
						information to perform OAuth connection to Twitter and submit either a 
						Tweet or a direct message to a single Twitter recipient.
	
	.PARAMETER TweetMessage
		Tweet message text
	
	.PARAMETER DirectMessage
		Direct message text
	
	.PARAMETER To
		Single Twitter recipient to whom you are sending a direct message
	
	.EXAMPLE
		This example generates all required OAuth information and sets up final OAuth string to
		then send a direct message using the REST API:
			$oAuthRequestString = (Connect-OAuthTwitter -DirectMessage "The #PSTwitter Powershell Module is working!" -To "CollinChaffin")
			Invoke-RestMethod .....-Headers @{ 'Authorization' = $oAuthRequestString }.....
	
	.EXAMPLE
		This example generates all required OAuth information and sets up final OAuth string to
		then send a tweet using the REST API:
			$oAuthRequestString = (Connect-OAuthTwitter -TweetMessage "Testing the #PSTwitter Windows Powershell module for Twitter!")
			Invoke-RestMethod .....-Headers @{ 'Authorization' = $oAuthRequestString }.....
	#>
	[CmdletBinding(DefaultParameterSetName = 'Tweeting')]
	[OutputType([System.String])]
	param	(		
		[Parameter(ParameterSetName = 'Tweeting', Mandatory = $true, HelpMessage = 'Please enter tweet message text')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$TweetMessage,
		[Parameter(ParameterSetName = 'Direct',
			Mandatory = $true,
			HelpMessage = 'Please enter your direct message text and note the TO switch is also required for target recipient')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$DirectMessage,
		[Parameter(ParameterSetName = 'Direct',
			Mandatory = $true,
			HelpMessage = 'Please enter Twitter recipient to whom you are sending a direct message')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$To
	)	
	BEGIN
	{		
		(Write-Status -Message "START  - Connect-OAuthTwitter function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
		try
		{
			(Write-Status -Message "START  - Loading DOTNET assemblies" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			[Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null
			[Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null
			[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
			(Write-Status -Message "FINISH - Loading DOTNET assemblies" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE LOADING REQUIRED DOTNET ASSEMBLIES " + $_.Exception.Message)			
		}
		
		# Retrieve required user-specific Twitter API info from registry
		try
		{			
			if ($((Test-Path -Path HKCU:\Software\PSTwitter) -eq $false) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret") -eq $null)
			   )
			{
				(Write-Status -Message "Twitter API settings not found - prompting operator" -Status "WARNING" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
				# Call Set-TwitterOAuthTokens function to prompt for credentials and store them
				Set-TwitterOAuthTokens
			}
			else
			{
				(Write-Status -Message "START  - Retrieving Twitter API settings from registry" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
				$global:apiKey				= (Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey")
				$global:apiSecret			= (Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret")
				$global:accessToken			= (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken")
				$global:accessTokenSecret	= (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret")
				(Write-Status -Message "FINISH - Retrieving Twitter API settings from registry" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			}			
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE LOADING REQUIRED TWITTER API INFORMATION " + $_.Exception.Message)
		}
	}
	PROCESS
	{
		try
		{
			# Create a custom PSObject to store all require oAuth info and simply pass a single object to helper functions			
			$objOAuth = @()
			$objOAuth = New-Object -TypeName PSObject
			$objOAuth | Add-Member -Name 'oauth_consumer_key' -Value $($apiKey) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_signature_method' -Value $($psTwitterOAuthSignatureMethod) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_token' -Value $($accessToken) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_version' -Value $($psTwitterOAuthVersion) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_urlAPIendpoint' -Value $(switch ($PsCmdlet.ParameterSetName) { "Tweeting"{ $psTwitterEndpointTweet }; "Direct"{ $psTwitterEndpointDirectMessage }; }) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_consumer_key_secret' -Value $($APISecret) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'oauth_token_secret' -Value $($accessTokenSecret) -MemberType NoteProperty -Force
			
			# Generate Nonce key PSObject property using helper function
			$objOAuth | Add-Member -Name 'oauth_nonce' -Value $(New-TwitterOAuthNonce) -MemberType NoteProperty -Force
			
			# Generate OAuth epoch-based timestamp PSObject property using helper function
			$objOAuth | Add-Member -Name 'oauth_timestamp' -Value $(New-TwitterOAuthTimeStamp) -MemberType NoteProperty -Force
			
			# Determine are we tweeting or sending a direct message on our parameter set call
			switch ($PSCmdlet.ParameterSetName)
			{
				'Tweeting'
				{
					# Since we are tweeting, add the tweet message to the custom PSObject as property required for signature
					$objOAuth | Add-Member -Name 'oauth_tweetmessage' -Value $($TweetMessage) -MemberType NoteProperty -Force
					
					# Generate OAuth signature for tweet request
					$oAuthSignature = (New-TwitterOAuthSignature -objOAuth $objOAuth -Tweeting)
				}
				'Direct'
				{
					# Since we are sending a direct message, add the message text and recipient to the custom PSObject as property required for signature
					$objOAuth | Add-Member -Name 'oauth_directmessage' -Value $($DirectMessage) -MemberType NoteProperty -Force
					$objOAuth | Add-Member -Name 'oauth_directrecipient' -Value $($To) -MemberType NoteProperty -Force
					
					# Generate OAuth signature for direct message request
					$oAuthSignature = (New-TwitterOAuthSignature -objOAuth $objOAuth -Direct)
				}
			}
			
			# Add the generated final signature as a property to the same custom PSObject
			$objOAuth | Add-Member -Name 'oauth_signature' -Value $($oAuthSignature) -MemberType NoteProperty -Force
			
			# Finally, generate the final OAuth request string with all the above generated information passing one single custom PSObject			
			[string]$oAuthRequestString = (New-TwitterOAuthString -objOAuth $objOAuth)
			
			# Return the one single oAuth request POST string to hand back to calling function (tweet or direct message) to POST it
			Return $oAuthRequestString;
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE BUILDING OAUTH REQUEST " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Connect-OAuthTwitter function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}


function New-TwitterOAuthNonce
{
	<#
	.SYNOPSIS
		Generate a new Nonce key for Twitter oAuth

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function generates a new Nonce key for Twitter oAuth
		
	.EXAMPLE
		$Nonce = New-TwitterOAuthNonce
		
		$Nonce
		s70FjIUXCOXeSX063Oop1ysZfCvlKQvJ9u1gqrVMuCU1		
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
	)
	BEGIN
	{
		(Write-Status -Message "START  - New-TwitterOAuthNonce function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{
			(Write-Status -Message "START  - Generating oAuthNonce string" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			# Create RNGCryptoServiceProvider object and call methods to generate oAuthNonce
			$barrayKey = New-Object byte[](32)
			$cryptoGen = New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider
			$cryptoGen.GetBytes($barrayKey)			
			[string]$oAuthNonce = [System.Web.HttpServerUtility]::UrlTokenEncode($barrayKey)
			
			(Write-Status -Message "FINISH - Generating oAuthNonce string" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			return $oAuthNonce;
		}
		catch
		{
			Throw $("ERROR OCCURRED GENERATING NEW NONCE KEY " + $_.Exception.Message)
		}
		finally
		{
			# Dispose of RNGCryptoServiceProvider object
			$cryptoGen.Dispose()
		}
	}
	END
	{
		(Write-Status -Message "FINISH - New-TwitterOAuthNonce function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}

function New-TwitterOAuthTimeStamp
{
	<#
	.SYNOPSIS
		Generate a new OAuth timestamp for Twitter oAuth based on epoch time

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function generates a new OAuth timestamp for
						Twitter oAuth based on epoch time
		
	.EXAMPLE
		$oAuthTimeStamp = New-TwitterOAuthTimeStamp
		
		$oAuthTimeStamp
		1412487014
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
	)
	BEGIN
	{
		(Write-Status -Message "START  - New-TwitterOAuthTimeStamp function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{
			[string]$oAuthTimeStamp = [INT](New-TimeSpan "01 January 1970 00:00:00" $((Get-Date).ToUniversalTime())).TotalSeconds			
			return $oAuthTimeStamp;
		}
		catch
		{
			Throw $("ERROR OCCURRED GENERATING NEW OAUTH EPOCH TIMESTAMP KEY " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - New-TwitterOAuthTimeStamp function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}

function New-TwitterOAuthSignature
{
	<#
	.SYNOPSIS
		Generate a new signature for Twitter oAuth request

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function generates a new signature for Twitter oAuth request
		
	.PARAMETER objOAuth
		[PSObject] Custom PSObject containing all required OAuth information
	
	.EXAMPLE
		$oAuthSignature = (New-TwitterOAuthSignature -objOAuth $objOAuth -Tweeting)
	
		$oAuthSignature
		ptUHUftvP0l6JQoJ+7yBa//uZcE=
	#>
	[CmdletBinding(DefaultParameterSetName = 'Tweeting')]
	[OutputType([System.String])]
	param (
		[Parameter(Position = 0, ParameterSetName = 'Tweeting', Mandatory = $true)]
		[Parameter(Position = 0, ParameterSetName = 'Direct', Mandatory = $true)]
			[ValidateNotNullOrEmpty()]
			[PSObject]
			$objOAuth,
		[Parameter(ParameterSetName = 'Tweeting',Mandatory = $false)]		
			[Switch]
			$Tweeting,
		[Parameter(ParameterSetName = 'Direct', Mandatory = $false)]		
			[Switch]
			$Direct	
	)
	BEGIN
	{
		(Write-Status -Message "START  - New-TwitterOAuthSignature function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{
			(Write-Status -Message "START  - Building OAuth signature" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			# Build base signature authorization parameters
			$oAuthSignatureBase = 'POST&'
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_urlAPIendpoint"].Value)")+"&"			
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_consumer_key"].Name)=$($objOAuth.PSObject.Properties["oauth_consumer_key"].Value)&")
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_nonce"].Name)=$($objOAuth.PSObject.Properties["oauth_nonce"].Value)&")
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_signature_method"].Name)=$($objOAuth.PSObject.Properties["oauth_signature_method"].Value)&")
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_timestamp"].Name)=$($objOAuth.PSObject.Properties["oauth_timestamp"].Value)&")
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_token"].Name)=$($objOAuth.PSObject.Properties["oauth_token"].Value)&")
			$oAuthSignatureBase += [System.Uri]::EscapeDataString("$($objOAuth.PSObject.Properties["oauth_version"].Name)=$($objOAuth.PSObject.Properties["oauth_version"].Value)&")
			
			# Add final values to signature authorization parameters depending on whether it is a Tweet or direct message
			switch ($PSCmdlet.ParameterSetName)
			{
				'Tweeting'
				{
					$oAuthSignatureBase += [System.Uri]::EscapeDataString("status=$($objOAuth.PSObject.Properties["oauth_tweetmessage"].Value)")
				}
				'Direct'
				{
					$oAuthSignatureBase += [System.Uri]::EscapeDataString("screen_name=$($objOAuth.PSObject.Properties["oauth_directrecipient"].Value)&")
					$oAuthSignatureBase += [System.Uri]::EscapeDataString("text=$($objOAuth.PSObject.Properties["oauth_directmessage"].Value)")					
				}
			}
			$oAuthSignatureBase = $oAuthSignatureBase | sort
			
			# Create a SHA1 hash from the oAuth signature using apisecret+accesstokensecret as HMACSHA1 key
			$signatureKey = [System.Uri]::EscapeDataString($($objOAuth.PSObject.Properties["oauth_consumer_key_secret"].Value)) + "&" + [System.Uri]::EscapeDataString($($objOAuth.PSObject.Properties["oauth_token_secret"].Value))
			
			# Create HMACSHA1 object and call method using key to create hash
			$objSHA1 = New-Object -TypeName System.Security.Cryptography.HMACSHA1
			$objSHA1.Key = [System.Text.Encoding]::ASCII.GetBytes($signatureKey)
			$oAuthSignature = [System.Convert]::ToBase64String($objSHA1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($oAuthSignatureBase)));
			
			(Write-Status -Message "FINISH - Building OAuth signature" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			return $oAuthSignature;
		}
		catch
		{
			Throw $("ERROR OCCURRED GENERATING NEW OAUTH SIGNATURE " + $_.Exception.Message)
		}
		finally
		{
			# Dispose of HMACSHA1 object
			$objSHA1.Dispose()
		}
	}
	END
	{
		(Write-Status -Message "FINISH - New-TwitterOAuthSignature function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}


function New-TwitterOAuthString
{
	<#
	.SYNOPSIS
		Generate a new string for Twitter oAuth request

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function generates a new string for Twitter oAuth request
		
	.PARAMETER objOAuth
		[PSObject] Custom PSObject containing all required OAuth information
		
	.EXAMPLE
		$oAuthRequestString = (New-TwitterOAuthString -objOAuth $objOAuth)						
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
		[Parameter(Position = 0, Mandatory = $true)]
			[ValidateNotNullOrEmpty()]
			[PSObject]
			$objOAuth		
	)
	BEGIN
	{
		(Write-Status -Message "START  - New-TwitterOAuthString function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{
			# Build full oAuth string now that the object is complete and this string unlike signature does NOT include tweet message, etc.
			$oAuthRequestString = 'OAuth '
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_consumer_key"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_consumer_key"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_nonce"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_nonce"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_signature"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_signature"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_signature_method"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_signature_method"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_timestamp"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_timestamp"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_token"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_token"].Value) + '", ')
			$oAuthRequestString += (($objOAuth.PSObject.Properties["oauth_version"].Name) + '="' + [System.Uri]::EscapeDataString($objOAuth.PSObject.Properties["oauth_version"].Value) + '"')
			
			return $oAuthRequestString;			
		}
		catch
		{
			Throw $("ERROR OCCURRED GENERATING NEW OAUTH REQUEST STRING " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - New-TwitterOAuthString function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}


function Write-Status
{
	<#
	.SYNOPSIS
		Write a status message to console and log if debugging

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function writes a status message out to console
						appending exact time/date of command execution and will
						optionally write to daily log

	.PARAMETER Message
		[String] Message to write
			
	.PARAMETER Status
		[String] Status code string
	
	.PARAMETER Debugging
		[Bool] If this switch is true then output debugging to console
	
	.EXAMPLE
		Write-Status -Message "Public Tweet sent successfully" -Status "SUCCESS" -Debugging $debugging
	
		10/18/2014 21:00:00 :: [SUCCESS] :: Public Tweet sent successfully	
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]		
			[System.String]
			$Message,		
		[Parameter(Mandatory = $false)]
			[System.String]
			$Status = "INFO",
		[Parameter(Mandatory = $false)]
			[Switch]
			$Debugging,
		[Parameter(Mandatory = $false)]
			[Switch]
			$Logging,
		[Parameter(Mandatory = $false)]
			[System.String]
			$LogPath = $(($psTwitterInvocationPath) + "Logs\")
	)
	BEGIN
	{
		try
		{	
			# Do not do anything unless global script debugging is true
			If ($Debugging -eq $true)
			{
				# Set up variables and log file/path
				[String]$statusTime = (Get-Date -Format "MM/dd/yyyy HH:mm:ss")
				
				# If -Logging passed, set up logging a a DAILY log file (change path in globals at top of script)
				if ($Logging -eq $true)
				{
					If (!(Test-Path $psTwitterLogPath)) { New-Item -ItemType Directory -Force -Path ($psTwitterLogPath) | Out-Null }
					[String]$logFileDate = (Get-Date -Format "MM-dd-yyyy")
					[String]$logFile = $($psTwitterLogPath) + "PSTwitter-" + $logFileDate + ".log"
				}
			}				
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE WRITING OUTPUT " + $_.Exception.Message)
		}
	}
	PROCESS
	{
		try
		{
			# Do not do anything unless global script debugging is true
			If ($Debugging -eq $true)
			{
				# Ensure custom status is always uppercase
				$Status = $Status.ToUpper()
				
				# Format output message
				$Message = "$statusTime :: [$Status] :: $Message"
				
				# Write out to console
				Write-Host $Message -ForegroundColor Cyan
					
				# If -Logging passed, set up logging a a DAILY log file (change path in globals at top of script)
				if ($Logging -eq $true)
				{				
					Add-Content -Path $logFile -Value ($Message)
				}
			}
		}
		catch
		{
			Throw $("ERROR OCCURRED WRITING STATUS" + $_.Exception.Message)
		}
	}
	END
	{
	}
}

Function Set-TwitterOAuthTokens
{
  <#
	.SYNOPSIS
		Stores required Twitter API OAuth settings providing both GUI wizard and
		command-line options
		

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function stores the required Twitter API settings
						provided by the operator interactively into the HKCU
						registry hive for subsequent sessions providing both
						GUI wizard and command-line options

	.PARAMETER Force
		[Switch] Clear existing stored Twitter API information and repopulate

	.PARAMETER APIKey
		[String] Twitter API Key

	.PARAMETER APISecret
		[String] Twitter API Secret

	.PARAMETER AccessToken
		[String] Twitter Access Token

	.PARAMETER AccessTokenSecret
		[String] Twitter Access Token Secret

	.EXAMPLE
		Set-TwitterOAuthTokens

		If Twitter API settings are not found in the registry, prompt the operator
		interactively via a GUI wizard to provide and open the Twitter API webpage
		to assist operator in locating their user-specific Twitter application information
		
		NOTE: Only missing information will be requested via wizard interface

	.EXAMPLE
		Set-TwitterOAuthTokens -Force

		Remove existing Twitter API information from registry and repopulate via
		GUI wizard

	.EXAMPLE
		Set-TwitterOAuthTokens -Force -APIKey "01234567890"

		Remove existing Twitter API information from registry and repopulate via
		automatically detected "command-line" mode.  In this case because all
		four required pieces of information were not provided, the missing three
		will be interactively prompted but via standard commandline text prompting
	#>
	[CmdletBinding(DefaultParameterSetName = 'Wizard')]
	[OutputType([System.String])]
	param
	(
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false)]
		[Parameter(ParameterSetName = 'Wizard', Mandatory = $false)]
			[Switch]
			$Force,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false, HelpMessage = 'Please enter your personal Twitter APPLICATION API Key:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$APIKey,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false, HelpMessage = 'Please enter your personal Twitter APPLICATION API Secret:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$APISecret,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false, HelpMessage = 'Please enter your personal Twitter APPLICATION Access Token:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$AccessToken,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false, HelpMessage = 'Please enter your personal Twitter APPLICATION Access Token Secret:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$AccessTokenSecret
		
	)
	BEGIN
	{
		(Write-Status -Message "START  - Set-TwitterOAuthTokens function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		# If we were passed -Force switch
		if ($Force.IsPresent)
		{
			try
			{				
					# Force switch used, remove/clear all stored API info and drop to either wizard or cmdline to repopulate
					if ($((Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey") -ne $null)) { Remove-ItemProperty HKCU:\Software\PSTwitter -name "APIKey" }
					if ($((Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret") -ne $null)) { Remove-ItemProperty HKCU:\Software\PSTwitter -name "APISecret" }
					if ($((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken") -ne $null)) { Remove-ItemProperty HKCU:\Software\PSTwitter -name "AccessToken" }
					if ($((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret") -ne $null)) { Remove-ItemProperty HKCU:\Software\PSTwitter -name "AccessTokenSecret" }				
			}
			catch
			{
				Throw $("ERROR OCCURRED CLEARING TWITTER API INFORMATION FROM REGISTRY " + $_.Exception.Message)
			}
		}
		
		# (Re)Populate the registry with 4 pieces of required Twitter OAuth info
		try
		{	
			# If any single piece of info is missing, start the process
			if ($((Test-Path -Path HKCU:\Software\PSTwitter) -eq $false) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken") -eq $null) `
			   -or $((Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret") -eq $null)
			   )
			{
				Write-Host "`nPlease configure your personal Twitter application from which you must store the following pieces of information:`n`n""API key""`n""API secret""`n""Access Token""`n""Access Token Secret""`n`nOpening default browser to: https://apps.twitter.com" -ForegroundColor Yellow
				
				Start-Process "https://apps.twitter.com/"
				
				# Entire reg key is missing so create it
				if (!(Test-Path -Path HKCU:\Software\PSTwitter))
				{
					(Write-Status -Message "START  - PSTwitter registry key creation" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
					New-Item -Path HKCU:\Software -Name PSTwitter | out-null
					(Write-Status -Message "FINISH - PSTwitter registry key creation" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
				}
				
				Switch ($PSCmdlet.ParameterSetName)
				{
					'Wizard'
					{
						# Now that we are sure reg key exists, call the wizard form and prompt only for missing value(s)
						# NOTE: If reg key exists and only 2 pieces of info are missing, operator only receives a wizard with 2 pages with 4 being all info missing
						Call-PSTwitter-API_psf | Out-Null
					}
					'CmdLine'
					{
						if (!$APIKey)
						{
							Write-Host "`n`nEnter Twitter API Key:" -ForegroundColor Yellow -NoNewline
							$APIKey = Read-Host							
							if ($APIKey) { New-ItemProperty HKCU:\Software\PSTwitter -name "APIKey" -value "$APIKey" | out-null }
						}
						else
						{
							New-ItemProperty HKCU:\Software\PSTwitter -name "APIKey" -value "$APIKey" | out-null
						}
						if (! $APISecret)
						{
							Write-Host "Enter Twitter API Secret:" -ForegroundColor Yellow -NoNewline
							$APISecret = Read-Host
							if ($APISecret) { New-ItemProperty HKCU:\Software\PSTwitter -name "APISecret" -value "$APISecret" | out-null }
						}
						else
						{
							New-ItemProperty HKCU:\Software\PSTwitter -name "APISecret" -value "$APISecret" | out-null
						}
						if (! $AccessToken)
						{
							Write-Host "Enter Twitter Access Token:" -ForegroundColor Yellow -NoNewline
							$AccessToken = Read-Host
							if ($AccessToken) { New-ItemProperty HKCU:\Software\PSTwitter -name "AccessToken" -value "$AccessToken" | out-null }
						}
						else
						{
							New-ItemProperty HKCU:\Software\PSTwitter -name "AccessToken" -value "$AccessToken" | out-null
						}
						if (! $AccessTokenSecret)
						{
							Write-Host "Enter Twitter Access Token Secret:" -ForegroundColor Yellow -NoNewline
							$AccessTokenSecret = Read-Host
							if ($AccessTokenSecret) { New-ItemProperty HKCU:\Software\PSTwitter -name "AccessTokenSecret" -value "$AccessTokenSecret" | out-null }
							Write-Host "`n"
						}
						else
						{
							New-ItemProperty HKCU:\Software\PSTwitter -name "AccessTokenSecret" -value "$AccessTokenSecret" | out-null
						}
					}
				}
			}
		}
		catch
		{
			Throw $("ERROR OCCURRED WRITING TWITTER API INFORMATION TO REGISTRY " + $_.Exception.Message)
		}
		finally
		{
			# Now that the reg values are present regardless of method, read back in the values and set our globals
			$global:apiKey = (Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey")
			$global:apiSecret = (Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret")
			$global:accessToken = (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken")
			$global:accessTokenSecret = (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret")
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Set-TwitterOAuthTokens function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	
}

function ConvertTo-HexEscaped
{
	<#
	.SYNOPSIS
		Hex escapes specific set of special characters that Twitter API does
		not handle properly

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	Hex escapes specific set of special characters that Twitter API does
						not handle properly

	.PARAMETER InputText
		[String] Twitter text to hex escape
	
	.EXAMPLE
		ConvertTo-HexEscaped -InputText "Testing!"
		Testing%21			
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
		[Parameter(Mandatory = $true)]		
		[System.String]
		$InputText
	)
	BEGIN
	{
		(Write-Status -Message "START  - ConvertTo-HexEscaped function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{			
			# Handle the special characters Twitter does not handle properly and escape them
			[string[]] $specialChar = @('%', '=', "+", "&", '[', ']', "!", "*", "'", "(", ")", ",")
			
			for ($i = 0; $i -lt $specialChar.Length; $i++)
			{
				$InputText = $InputText.Replace($specialChar[$i], [System.Uri]::HexEscape($specialChar[$i]))				
			}			
			return $InputText
		}
		catch
		{
			Throw $("ERROR OCCURRED CONVERTING SPECIAL CHARACTERS " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - ConvertTo-HexEscaped function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}


function Send-TwitterTweet
{
	<#
	.SYNOPSIS
		Sends a Twitter Tweet
	
	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	Sends a Twitter Tweet using OAuth and REST							
	
	.PARAMETER TweetMessage
		The message text of the tweet to be posted
	
	.EXAMPLE
		Send-TwitterTweet -TweetMessage "This is my first tweet using the #PSTwitter Powershell Module!"
	
		This example will send a tweet with the above tweet text
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateLength(1, 140)]
		[System.String]
		$TweetMessage
	)
	BEGIN
	{
		(Write-Status -Message "START  - Send-TwitterTweet function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{			
			# Twitter does not handle a few special characters properly so let's hexescape them
			$fixedTweetMessage = $(ConvertTo-HexEscaped -InputText $TweetMessage)
			
			# Call our main connect routine to do the oAuth heavy lifting
			$oAuthRequestString = (Connect-OAuthTwitter -TweetMessage $fixedTweetMessage)
			
			# Set up the HTTP POST body
			$httpBody = "status=$fixedTweetMessage"
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Twitter" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			# Call the REST API to handle the final OAUTH POST
			Invoke-RestMethod -URI $psTwitterEndpointTweet -Method Post -Body $httpBody -Headers @{ 'Authorization' = $oAuthRequestString } -ContentType "application/x-www-form-urlencoded" | Out-Null
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Twitter" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED SENDING TWEET " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Send-TwitterTweet function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}

function Send-TwitterDirect
{
	<#
	.SYNOPSIS
		Sends a Twitter direct message to another single Twitter user by screen name
	
	.DESCRIPTION
			Author:  		Collin Chaffin
			Description:	Sends a Twitter direct message to another single Twitter user by screen name
							using OAuth and REST	
	
	.PARAMETER DirectMessage
		Text of the direct message
	
	.PARAMETER To
		Single recipient screen name
	
	.EXAMPLE
		Send-TwitterDirect -Message "The #PSTwitter Powershell Module is working!" -To "CollinChaffin"
				
	.NOTES
		There is a maximim limit of 250 direct messages in a 24 hour period!
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateLength(1, 140)]
		[System.String]
		$DirectMessage,
		[Parameter(Mandatory = $true)]
		[System.String]
		$To
	)
	
	BEGIN
	{
		(Write-Status -Message "START  - Send-TwitterDirect function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
	PROCESS
	{
		try
		{
			# Twitter does not handle a few special characters properly so let's hexescape them
			$fixedDirectMessage = $(ConvertTo-HexEscaped -InputText $DirectMessage)
			
			# Call our main connect routine to do the oAuth heavy lifting
			$oAuthRequestString = (Connect-OAuthTwitter -DirectMessage $fixedDirectMessage -To $To)
			
			# Should not have to do this but run recipient though standard escaping just in case
			$To = [System.Uri]::EscapeDataString($To)
			
			# Set up the HTTP POST body
			$httpBody = "text=$fixedDirectMessage&screen_name=$To"
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Twitter" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
			
			# Call the REST API to handle the final OAUTH POST
			Invoke-RestMethod -URI $psTwitterEndpointDirectMessage -Method Post -Body $httpBody -Headers @{ 'Authorization' = $oAuthRequestString } -ContentType "application/x-www-form-urlencoded" | Out-Null
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Twitter" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED SENDING DIRECT MESSAGE " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Send-TwitterDirect function execution" -Status "INFO" -Debugging:$psTwitterDebugging -Logging:$psTwitterLogging -Logpath $psTwitterLogPath)
	}
}

#########################################################################

#endregion

#region Call-PSTwitter-API_psf

function Call-PSTwitter-API_psf
{
	#----------------------------------------------
	#region Import the Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load('mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[void][reflection.assembly]::Load('System.Xml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[void][reflection.assembly]::Load('System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.ServiceProcess, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	#endregion Import Assemblies
	
	#----------------------------------------------
	#region  Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$frmTwitterAPIInformation = New-Object 'System.Windows.Forms.Form'
	$buttonCancel = New-Object 'System.Windows.Forms.Button'
	$buttonBack = New-Object 'System.Windows.Forms.Button'
	$buttonFinish = New-Object 'System.Windows.Forms.Button'
	$tabcontrolWizard = New-Object 'System.Windows.Forms.TabControl'
	$tabpageStep1 = New-Object 'System.Windows.Forms.TabPage'
	$txtAPIKey = New-Object 'System.Windows.Forms.TextBox'
	$labelAPIKey = New-Object 'System.Windows.Forms.Label'
	$tabpageStep2 = New-Object 'System.Windows.Forms.TabPage'
	$txtAPISecret = New-Object 'System.Windows.Forms.TextBox'
	$labelAPISecret = New-Object 'System.Windows.Forms.Label'
	$tabpageStep3 = New-Object 'System.Windows.Forms.TabPage'
	$txtAccessToken = New-Object 'System.Windows.Forms.TextBox'
	$labelAccessToken = New-Object 'System.Windows.Forms.Label'
	$tabpageStep4 = New-Object 'System.Windows.Forms.TabPage'
	$txtAccessTokenSecret = New-Object 'System.Windows.Forms.TextBox'
	$labelAccessTokenSecret = New-Object 'System.Windows.Forms.Label'
	$buttonNext = New-Object 'System.Windows.Forms.Button'
	$InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'
	#endregion  Form Objects
	
	
	function Validate-WizardPage
	{
		[OutputType([boolean])]
		param ([System.Windows.Forms.TabPage]$tabPage)
		
		if ($tabPage -eq $tabpageStep1)
		{
			if (-not $txtAPIKey.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep2)
		{
			if (-not $txtAPISecret.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep3)
		{
			if (-not $txtAccessToken.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep4)
		{
			if (-not $txtAccessTokenSecret.Text)
			{
				return $false
			}
			
			return $true
		}
		return $false
	}
	
	$buttonFinish_Click = {
		if ($txtAPIKey.Text) { New-ItemProperty HKCU:\Software\PSTwitter -name "APIKey" -value "$($txtAPIKey.Text)" | out-null }
		if ($txtAPISecret.Text) { New-ItemProperty HKCU:\Software\PSTwitter -name "APISecret" -value "$($txtAPISecret.Text)" | out-null }
		if ($txtAccessToken.Text) { New-ItemProperty HKCU:\Software\PSTwitter -name "AccessToken" -value "$($txtAccessToken.Text)" | out-null }
		if ($txtAccessTokenSecret.Text) { New-ItemProperty HKCU:\Software\PSTwitter -name "AccessTokenSecret" -value "$($txtAccessTokenSecret.Text)" | out-null }
	}
	
	#region Events and Functions
	$frmTwitterAPIInformation_Load = {
		Update-NavButtons
		
		# Reg key is there, but we must have a missing value(s)
		$apiKey = (Get-Item HKCU:\Software\PSTwitter).getvalue("APIKey")
		$apiSecret = (Get-Item HKCU:\Software\PSTwitter).getvalue("APISecret")
		$accessToken = (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessToken")
		$accessTokenSecret = (Get-Item HKCU:\Software\PSTwitter).getvalue("AccessTokenSecret")
		
		# Check for any single missing values and prompt for those that are missing
		if ($apiKey)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep1)
		}
		if ($apiSecret)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep2)
		}
		if ($accessToken)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep3)
		}
		if ($accessTokenSecret)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep4)
		}
	}
	
	function Update-NavButtons
	{
		<# 
			.DESCRIPTION
			Validates the current tab and Updates the Next, Prev and Finish buttons.
		#>
		$enabled = Validate-WizardPage $tabcontrolWizard.SelectedTab
		$buttonNext.Enabled = $enabled -and ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		$buttonBack.Enabled = $tabcontrolWizard.SelectedIndex -gt 0
		$buttonFinish.Enabled = $enabled -and ($tabcontrolWizard.SelectedIndex -eq $tabcontrolWizard.TabCount - 1)
		#Uncomment to Hide Buttons
		#$buttonNext.Visible = ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		#$buttonFinish.Visible = ($tabcontrolWizard.SelectedIndex -eq $tabcontrolWizard.TabCount - 1)
	}
	
	$script:DeselectedIndex = -1
	$tabcontrolWizard_Deselecting = [System.Windows.Forms.TabControlCancelEventHandler]{
		#Event Argument: $_ = [System.Windows.Forms.TabControlCancelEventArgs]
		# Store the previous tab index
		$script:DeselectedIndex = $_.TabPageIndex
	}
	
	$tabcontrolWizard_Selecting = [System.Windows.Forms.TabControlCancelEventHandler]{
		#Event Argument: $_ = [System.Windows.Forms.TabControlCancelEventArgs]
		# We only validate if we are moving to the Next TabPage.
		# Users can move back without validating
		if ($script:DeselectedIndex -ne -1 -and $script:DeselectedIndex -lt $_.TabPageIndex)
		{
			#Validate each page until we reach the one we want
			for ($index = $script:DeselectedIndex; $index -lt $_.TabPageIndex; $index++)
			{
				$_.Cancel = -not (Validate-WizardPage $tabcontrolWizard.TabPages[$index])
				
				if ($_.Cancel)
				{
					# Cancel and Return if validation failed.
					return;
				}
			}
		}
		Update-NavButtons
	}
	
	$buttonBack_Click = {
		#Go to the previous tab page
		if ($tabcontrolWizard.SelectedIndex -gt 0)
		{
			$tabcontrolWizard.SelectedIndex--
		}
	}
	
	$buttonNext_Click = {
		#Go to the next tab page
		if ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		{
			$tabcontrolWizard.SelectedIndex++
		}
	}
	
	#endregion
	
	#------------------------------------------------------
	# Events: Call Update-NavButtons to trigger validation
	#------------------------------------------------------
	
	$txtAPIKey_TextChanged = {
		Update-NavButtons
	}
	
	$txtAPISecret_TextChanged = {
		Update-NavButtons
	}
	
	$txtAccessToken_TextChanged = {
		Update-NavButtons
	}
	
	$txtAccessTokenSecret_TextChanged = {
		Update-NavButtons
	}
	
	
	$tabcontrolWizard_SelectedIndexChanged = {
		Update-NavButtons
	}
	
	$buttonCancel_Click = {
		$frmTwitterAPIInformation.Close()
	}
	
	#----------------------------------------------
	#region cleanup Events
	#----------------------------------------------
	
	$Form_StateCorrection_Load =
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$frmTwitterAPIInformation.WindowState = $InitialFormWindowState
	}
	
	$Form_StoreValues_Closing =
	{
		#Store the control values
		$script:PSTwitter_API_txtAPIKey = $txtAPIKey.Text
		$script:PSTwitter_API_txtAPISecret = $txtAPISecret.Text
		$script:PSTwitter_API_txtAccessToken = $txtAccessToken.Text
		$script:PSTwitter_API_txtAccessTokenSecret = $txtAccessTokenSecret.Text
	}
	
	
	$Form_Cleanup_FormClosed =
	{
		#Remove all event handlers from the controls
		try
		{
			$buttonCancel.remove_Click($buttonCancel_Click)
			$buttonBack.remove_Click($buttonBack_Click)
			$buttonFinish.remove_Click($buttonFinish_Click)
			$txtAPIKey.remove_TextChanged($txtAPIKey_TextChanged)
			$txtAPISecret.remove_TextChanged($txtAPISecret_TextChanged)
			$txtAccessToken.remove_TextChanged($txtAccessToken_TextChanged)
			$txtAccessTokenSecret.remove_TextChanged($txtAccessTokenSecret_TextChanged)
			$tabcontrolWizard.remove_SelectedIndexChanged($tabcontrolWizard_SelectedIndexChanged)
			$tabcontrolWizard.remove_Selecting($tabcontrolWizard_Selecting)
			$tabcontrolWizard.remove_Deselecting($tabcontrolWizard_Deselecting)
			$buttonNext.remove_Click($buttonNext_Click)
			$frmTwitterAPIInformation.remove_Load($frmTwitterAPIInformation_Load)
			$frmTwitterAPIInformation.remove_Load($Form_StateCorrection_Load)
			$frmTwitterAPIInformation.remove_Closing($Form_StoreValues_Closing)
			$frmTwitterAPIInformation.remove_FormClosed($Form_Cleanup_FormClosed)
		}
		catch [Exception]
		{ }
	}
	#endregion cleanup Events
	
	#----------------------------------------------
	#region  Form Code
	#----------------------------------------------
	$frmTwitterAPIInformation.SuspendLayout()
	$tabcontrolWizard.SuspendLayout()
	$tabpageStep1.SuspendLayout()
	$tabpageStep2.SuspendLayout()
	$tabpageStep3.SuspendLayout()
	$tabpageStep4.SuspendLayout()
	#
	# frmTwitterAPIInformation
	#
	$frmTwitterAPIInformation.Controls.Add($buttonCancel)
	$frmTwitterAPIInformation.Controls.Add($buttonBack)
	$frmTwitterAPIInformation.Controls.Add($buttonFinish)
	$frmTwitterAPIInformation.Controls.Add($tabcontrolWizard)
	$frmTwitterAPIInformation.Controls.Add($buttonNext)
	$frmTwitterAPIInformation.AcceptButton = $buttonFinish
	$frmTwitterAPIInformation.CancelButton = $buttonCancel
	$frmTwitterAPIInformation.ClientSize = '537, 180'
	$frmTwitterAPIInformation.FormBorderStyle = 'FixedDialog'
	$frmTwitterAPIInformation.MaximizeBox = $False
	$frmTwitterAPIInformation.Name = "frmTwitterAPIInformation"
	$frmTwitterAPIInformation.StartPosition = 'CenterScreen'
	$frmTwitterAPIInformation.Text = "Twitter API Information"
	$frmTwitterAPIInformation.add_Load($frmTwitterAPIInformation_Load)
	#
	# buttonCancel
	#
	$buttonCancel.Anchor = 'Bottom, Right'
	$buttonCancel.DialogResult = 'Cancel'
	$buttonCancel.Location = '369, 145'
	$buttonCancel.Name = "buttonCancel"
	$buttonCancel.Size = '75, 23'
	$buttonCancel.TabIndex = 4
	$buttonCancel.Text = "&Cancel"
	$buttonCancel.UseVisualStyleBackColor = $True
	$buttonCancel.add_Click($buttonCancel_Click)
	#
	# buttonBack
	#
	$buttonBack.Anchor = 'Bottom, Left'
	$buttonBack.Location = '13, 145'
	$buttonBack.Name = "buttonBack"
	$buttonBack.Size = '75, 23'
	$buttonBack.TabIndex = 1
	$buttonBack.Text = "< &Back"
	$buttonBack.UseVisualStyleBackColor = $True
	$buttonBack.add_Click($buttonBack_Click)
	#
	# buttonFinish
	#
	$buttonFinish.Anchor = 'Bottom, Right'
	$buttonFinish.DialogResult = 'OK'
	$buttonFinish.Location = '450, 145'
	$buttonFinish.Name = "buttonFinish"
	$buttonFinish.Size = '75, 23'
	$buttonFinish.TabIndex = 3
	$buttonFinish.Text = "&Finish"
	$buttonFinish.UseVisualStyleBackColor = $True
	$buttonFinish.add_Click($buttonFinish_Click)
	#
	# tabcontrolWizard
	#
	$tabcontrolWizard.Controls.Add($tabpageStep1)
	$tabcontrolWizard.Controls.Add($tabpageStep2)
	$tabcontrolWizard.Controls.Add($tabpageStep3)
	$tabcontrolWizard.Controls.Add($tabpageStep4)
	$tabcontrolWizard.Anchor = 'Top, Bottom, Left, Right'
	$tabcontrolWizard.Location = '13, 12'
	$tabcontrolWizard.Name = "tabcontrolWizard"
	$tabcontrolWizard.SelectedIndex = 0
	$tabcontrolWizard.Size = '512, 127'
	$tabcontrolWizard.TabIndex = 0
	$tabcontrolWizard.add_SelectedIndexChanged($tabcontrolWizard_SelectedIndexChanged)
	$tabcontrolWizard.add_Selecting($tabcontrolWizard_Selecting)
	$tabcontrolWizard.add_Deselecting($tabcontrolWizard_Deselecting)
	#
	# tabpageStep1
	#
	$tabpageStep1.Controls.Add($txtAPIKey)
	$tabpageStep1.Controls.Add($labelAPIKey)
	$tabpageStep1.Location = '4, 22'
	$tabpageStep1.Name = "tabpageStep1"
	$tabpageStep1.Padding = '3, 3, 3, 3'
	$tabpageStep1.Size = '504, 101'
	$tabpageStep1.TabIndex = 0
	$tabpageStep1.Text = "API Key"
	$tabpageStep1.UseVisualStyleBackColor = $True
	#
	# txtAPIKey
	#
	$txtAPIKey.Location = '168, 43'
	$txtAPIKey.Name = "txtAPIKey"
	$txtAPIKey.Size = '259, 20'
	$txtAPIKey.TabIndex = 1
	$txtAPIKey.add_TextChanged($txtAPIKey_TextChanged)
	#
	# labelAPIKey
	#
	$labelAPIKey.AutoSize = $True
	$labelAPIKey.Location = '87, 46'
	$labelAPIKey.Name = "labelAPIKey"
	$labelAPIKey.Size = '45, 13'
	$labelAPIKey.TabIndex = 0
	$labelAPIKey.Text = "API Key"
	#
	# tabpageStep2
	#
	$tabpageStep2.Controls.Add($txtAPISecret)
	$tabpageStep2.Controls.Add($labelAPISecret)
	$tabpageStep2.Location = '4, 22'
	$tabpageStep2.Name = "tabpageStep2"
	$tabpageStep2.Padding = '3, 3, 3, 3'
	$tabpageStep2.Size = '504, 101'
	$tabpageStep2.TabIndex = 1
	$tabpageStep2.Text = "API Secret"
	$tabpageStep2.UseVisualStyleBackColor = $True
	#
	# txtAPISecret
	#
	$txtAPISecret.Location = '168, 42'
	$txtAPISecret.Name = "txtAPISecret"
	$txtAPISecret.Size = '259, 20'
	$txtAPISecret.TabIndex = 3
	$txtAPISecret.add_TextChanged($txtAPISecret_TextChanged)
	#
	# labelAPISecret
	#
	$labelAPISecret.AutoSize = $True
	$labelAPISecret.Location = '87, 45'
	$labelAPISecret.Name = "labelAPISecret"
	$labelAPISecret.Size = '58, 13'
	$labelAPISecret.TabIndex = 2
	$labelAPISecret.Text = "API Secret"
	#
	# tabpageStep3
	#
	$tabpageStep3.Controls.Add($txtAccessToken)
	$tabpageStep3.Controls.Add($labelAccessToken)
	$tabpageStep3.Location = '4, 22'
	$tabpageStep3.Name = "tabpageStep3"
	$tabpageStep3.Size = '504, 101'
	$tabpageStep3.TabIndex = 2
	$tabpageStep3.Text = "Access Token"
	$tabpageStep3.UseVisualStyleBackColor = $True
	#
	# txtAccessToken
	#
	$txtAccessToken.Location = '168, 43'
	$txtAccessToken.Name = "txtAccessToken"
	$txtAccessToken.Size = '259, 20'
	$txtAccessToken.TabIndex = 5
	$txtAccessToken.add_TextChanged($txtAccessToken_TextChanged)
	#
	# labelAccessToken
	#
	$labelAccessToken.AutoSize = $True
	$labelAccessToken.Location = '87, 46'
	$labelAccessToken.Name = "labelAccessToken"
	$labelAccessToken.Size = '76, 13'
	$labelAccessToken.TabIndex = 4
	$labelAccessToken.Text = "Access Token"
	#
	# tabpageStep4
	#
	$tabpageStep4.Controls.Add($txtAccessTokenSecret)
	$tabpageStep4.Controls.Add($labelAccessTokenSecret)
	$tabpageStep4.Location = '4, 22'
	$tabpageStep4.Name = "tabpageStep4"
	$tabpageStep4.Padding = '3, 3, 3, 3'
	$tabpageStep4.Size = '504, 101'
	$tabpageStep4.TabIndex = 3
	$tabpageStep4.Text = "Access Token Secret"
	$tabpageStep4.UseVisualStyleBackColor = $True
	#
	# txtAccessTokenSecret
	#
	$txtAccessTokenSecret.Location = '168, 44'
	$txtAccessTokenSecret.Name = "txtAccessTokenSecret"
	$txtAccessTokenSecret.Size = '259, 20'
	$txtAccessTokenSecret.TabIndex = 7
	$txtAccessTokenSecret.add_TextChanged($txtAccessTokenSecret_TextChanged)
	#
	# labelAccessTokenSecret
	#
	$labelAccessTokenSecret.AutoSize = $True
	$labelAccessTokenSecret.Location = '52, 46'
	$labelAccessTokenSecret.Name = "labelAccessTokenSecret"
	$labelAccessTokenSecret.Size = '110, 13'
	$labelAccessTokenSecret.TabIndex = 6
	$labelAccessTokenSecret.Text = "Access Token Secret"
	#
	# buttonNext
	#
	$buttonNext.Anchor = 'Bottom, Right'
	$buttonNext.Location = '288, 145'
	$buttonNext.Name = "buttonNext"
	$buttonNext.Size = '75, 23'
	$buttonNext.TabIndex = 2
	$buttonNext.Text = "&Next >"
	$buttonNext.UseVisualStyleBackColor = $True
	$buttonNext.add_Click($buttonNext_Click)
	$tabpageStep4.ResumeLayout()
	$tabpageStep3.ResumeLayout()
	$tabpageStep2.ResumeLayout()
	$tabpageStep1.ResumeLayout()
	$tabcontrolWizard.ResumeLayout()
	$frmTwitterAPIInformation.ResumeLayout()
	#endregion  Form Code
	
	#----------------------------------------------
	
	#Save the initial state of the form
	$InitialFormWindowState = $frmTwitterAPIInformation.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$frmTwitterAPIInformation.add_Load($Form_StateCorrection_Load)
	#Clean up the control events
	$frmTwitterAPIInformation.add_FormClosed($Form_Cleanup_FormClosed)
	#Store the control values when form is closing
	$frmTwitterAPIInformation.add_Closing($Form_StoreValues_Closing)
	#Show the Form
	return $frmTwitterAPIInformation.ShowDialog()
}

#endregion

Export-ModuleMember Send-TwitterTweet
Export-ModuleMember Send-TwitterDirect
Export-ModuleMember Set-TwitterOAuthTokens
	