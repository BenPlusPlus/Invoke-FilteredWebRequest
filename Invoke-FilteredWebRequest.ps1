#========================================================================
# Created on:   3/23/2015 3:24 PM
# Created by:   Ben Baird
# Filename:     Invoke-FilteredWebRequest.ps1
# Description:
# 	A proxy function for the built-in Invoke-WebRequest function, but has
# 	extra checks and workarounds for the McAfee Web Gateway to allow the
# 	downloading of files by waiting for the proxy's virus scan.
#
#   The modified behavior is intended to mimic McAfee's JavaScript status
#   checker that runs in the browser. Once the threat scan is complete,
#   this function will return the content that was actually requested by
#   the caller.
#========================================================================
[CmdletBinding(HelpUri='http://go.microsoft.com/fwlink/?LinkID=217035')]
param(
    [switch]
    ${UseBasicParsing},

    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [uri]
    ${Uri},

    [Microsoft.PowerShell.Commands.WebRequestSession]
    ${WebSession},

    [Alias('SV')]
    [string]
    ${SessionVariable},

    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    ${Credential},

    [switch]
    ${UseDefaultCredentials},

    [ValidateNotNullOrEmpty()]
    [string]
    ${CertificateThumbprint},

    [ValidateNotNull()]
    [System.Security.Cryptography.X509Certificates.X509Certificate]
    ${Certificate},

    [string]
    ${UserAgent},

    [switch]
    ${DisableKeepAlive},

    [int]
    ${TimeoutSec},

    [System.Collections.IDictionary]
    ${Headers},

    [ValidateRange(0, 2147483647)]
    [int]
    ${MaximumRedirection},

    [Microsoft.PowerShell.Commands.WebRequestMethod]
    ${Method},

    [uri]
    ${Proxy},

    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    ${ProxyCredential},

    [switch]
    ${ProxyUseDefaultCredentials},

    [Parameter(ValueFromPipeline=$true)]
    [System.Object]
    ${Body},

    [string]
    ${ContentType},

    [ValidateSet('chunked','compress','deflate','gzip','identity')]
    [string]
    ${TransferEncoding},

    [string]
    ${InFile},

    [string]
    ${OutFile},

    [switch]
    ${PassThru})

begin
{
    try {
		$unixEpochStart = New-Object DateTime 1970,1,1,0,0,0,([DateTimeKind]::Utc)
		$removedOutFile = ''
		$removedPassThru = $false

        $outBuffer = $null
        if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
        {
            $PSBoundParameters['OutBuffer'] = 1
        }
		if ($PSBoundParameters['PassThru']) {
			$removedPassThru = $true # -PassThru must be removed because we must remove OutFile, which would invalidate the use of PassThru
			$PSBoundParameters.Remove('PassThru')
		}
		if ($PSBoundParameters['OutFile']) {
			$removedOutFile = $PSBoundParameters['OutFile'] # must be removed to prevent ultimate output from being overwritten
			$PSBoundParameters.Remove('OutFile')
		}

        $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Invoke-WebRequest', [System.Management.Automation.CommandTypes]::Cmdlet)
        $scriptCmd = { & $wrappedCmd @PSBoundParameters | foreach {
			# ======= BEGIN OWNAGE =======
			$result = $_

			if ($result.Headers.ContainsKey('Via') -and $result.Headers.Via.Contains('McAfee Web Gateway')) {
				Write-Verbose 'McAfee Web Gateway detected, attempting to set up status checks'
				$content = $result.Content
				if ($content -match '/mwg-internal/(.*?)/files/') {
					# Yep. (Most likely, anyway)
					$URLPart1 = $matches[1]
					Write-Verbose "Detected internal URL with folder '$URLPart1'"
					if ($content -match '<meta id="progresspageid" content="(.*?)">') {
						$RequestID = $matches[1]
						Write-Verbose "Detected request ID of '$RequestID'"

						$requestDomain = $PSBoundParameters['Uri'].ToString().Split('/')[0..2] -join '/' # gets first part of Uri (no folders)
						$statusComplete = $false
						while (!$statusComplete) {
							Start-Sleep -Seconds 3
							# This is the Uri we use to find out whether McAfee has finished scanning and
							# we can download the file. Presumably the Unix timestamp at the end purposes
							# to prevent cached responses.
							$statusUri = "$requestDomain/mwg-internal/$URLPart1/progress?id=$RequestID&a=1&$([Int64]([DateTime]::UtcNow - $unixEpochStart).TotalMilliseconds)"
							Write-Verbose "Requesting status URI: $statusUri"
							$PSBoundParameters['Uri'] = $statusUri
							$result = Invoke-WebRequest @PSBoundParameters
							if ($result.StatusCode -eq 200) {
								$colStat = $result.Content.Split(';')
								if ($colStat[3] -eq 1 -or $colStat[3] -eq $null) {
									Write-Verbose "Detected completion status. Attempting request of original content"
									$statusComplete = $true
									$PSBoundParameters['Uri'] = "$requestDomain/mwg-internal/$URLPart1/progress?id=$RequestID&dl"
									$result = Invoke-WebRequest @PSBoundParameters
									if ($removedPassThru) {
										# Caller wanted PassThru, so emit the result object
										$result
									}
									if ($removedOutFile.Length -gt 0) {
										Set-Content -Path $removedOutFile -Value $($result.Content) -Encoding 'Byte'
									}
								}
								elseif ($colStat[4] -eq 0) {
									Write-Verbose "Downloaded $($colStat[0]) of $($colStat[1])"
								}
								else {
									Write-Verbose "Scanning in progress ($($colStat[4])s)"
								}
							}
						} # while
					}
				}
			}
			else {
				if ($removedOutFile.Length -gt 0) {
					Set-Content -Path $removedOutFile -Value $($result.Content) -Encoding 'Byte'
				}
			}
		} }

        $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
        $steppablePipeline.Begin($PSCmdlet)
    } catch {
        throw
    }
}

process
{
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
}

end
{
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
}
<#

.ForwardHelpTargetName Invoke-WebRequest
.ForwardHelpCategory Cmdlet

#>
