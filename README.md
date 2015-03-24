# Invoke-FilteredWebRequest.ps1
A PowerShell proxy function for Invoke-WebRequest.

### What does it do?
If you ever have occasion to automate the download of a web-based file from behind a corporate proxy, then this script just might be for you. Invoke-FilteredWebRequest detects McAfee Web Gateway download interceptions, waits for the McAfee virus scan to complete, then returns the requested content.

I should probably note that I don't really know that much about the McAfee Web Gateway product. All I really know is that this script works for me, and that the MWG download page footer in my web browser contains the string `WEBGTWY03`, which might be the version number of the McAfee product that Invoke-FilteredWebRequest supports.

### How do I use it?

It's designed to be called without dot sourcing or importing as a module (though it could easily be modified to do either). Here's an example of how I've used it in my own work. The following (simplified) snippet downloads the latest .msi installer for Node.js to a subfolder named `.\cache`:

```powershell
$PROXY_URL = 'http://proxy.mycompany.org:8080/'

# Find the latest release of Node.js
#
$nodesite = Invoke-WebRequest -Uri 'https://nodejs.org/download/' -Proxy $PROXY_URL -ProxyUseDefaultCredentials
$idx = $nodesite.Content.IndexOf('Current version: ')
if ($idx -eq $null -or $idx -lt 0) {
	Write-Error 'Node.js current version label was not found on the web site. Fail :('
	exit
}
$content = $nodesite.Content.Substring($idx)
if ($content -match '<b>(.*?)</b>') {
	# at this point, $matches[1] should contain the version number without tags
	$NodeURL = "http://nodejs.org/dist/$($matches[1])/x64/node-$($matches[1])-x64.msi"
	$DestFile = ".\cache\node-$($matches[1])-x64.msi"
	if (Test-Path $DestFile) { Remove-Item -Path $DestFile -Force }
	.\Invoke-FilteredWebRequest.ps1 -Uri $NodeURL -OutFile $DestFile -Proxy $PROXY_URL -ProxyUseDefaultCredentials | Out-Null
}
```

### Is it production ready?

Not really. It works, but there could be more error-checking and detection for failure conditions. This quick-and-dirty script was mainly something I needed for the larger project of a script that can download and install all the latest stuff for my dev stack. For me, as long as it can do that job, I'm not likely to make more changes to it.

### Conclusion

Feel free to make suggestions, or even to make changes yourself.
