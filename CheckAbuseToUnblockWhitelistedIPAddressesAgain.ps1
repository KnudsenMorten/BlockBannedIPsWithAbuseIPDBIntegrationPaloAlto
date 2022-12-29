#Requires -Version 5.0
<#
    .SYNOPSIS
    This script will build a list of banned IPs which is uploaded to a web-site
    Then the firewall, in this example Palo Alto, will read the banned IP list

    .NOTES
    VERSION: 2212

    .COPYRIGHT
    @mortenknudsendk on Twitter
    Blog: https://mortenknudsen.net
    
    .LICENSE
    Licensed under the MIT license.

    .WARRANTY
    Use at your own risk, no warranty given!
#>

#--------------------------------------------------------
# PS Modules
#--------------------------------------------------------
    # Install-Module -Name PSFTP

    Import-module -Name PSFTP

#------------------------------------------------------------------------------------------------------------
# Connect to Azure
#------------------------------------------------------------------------------------------------------------
    Connect-AzAccount

#--------------------------------------------------------
# Variables
#--------------------------------------------------------

    <# 
    AbuseIPDB ConfidenScore definition
    Our confidence of abuse is a rating (scaled 0-100) of how confident we are, based on user reports, that an IP address is entirely malicious. 
    So a rating of 100 means we are sure an IP address is malicious, while a rating of 0 means we have no reason to suspect it is malicious. 
    Don't be disheartened if your report only increases this value by a few percentage points; the confidence rating is a very conservative value.
    Because this metric may be used as a basis to block connections, we take great care to only condemn addresses that a strong number of AbuseIPDB users testify against.

    The confidence rating is determined by reports and their age. The base value is the natural logarithmic value of distinct user reports 
    combined with the logarithmic value of distinct anonymous reports. Anonymous reporters have a diminished weight. All report weights decay 
    with time. Confidence ratings for all reported addresses are recalculated daily to apply the time decay. 
    Certain user traits can also slightly increase weight such as webmaster and supporter statuses.

    The formula is carefully designed to ensure no one reporter can overpower the ratings. Only by working together can we build an effective net of trust.
    #>

    # ConfidenceScore will be checked again this value. Using 0 will include ALL greater than 0
    $ConfidenceScore_Minimum = 0 

    # AbuseIPDB API Key
    $APIKey                  = "c5182c64aeb6905bf6cd03f1c6b168182cd4c2f9dfb6de352f2acaa5f9b56adc50df95f3546e0b0c"

    # Temporary Files Path
    $TempPath                = "C:\SCRIPTS\TEMP\PaloAlto_Firewall_Syslog"

    # Azure App - FTP config
    $FTPUserName             = 'cs-firewall-blocklist\$cs-firewall-blocklist'
    $FTPPassword             = 'xwmszqEQksSx2Nh7Ah3fs6yCHfkL92HL6mhjfxZw5orhfmpb1atcnF037BMu'
    $FTPURL                  = "ftp://waws-prod-am2-379.ftp.azurewebsites.windows.net/site/wwwroot"
    $FTPSecurePassword       = ConvertTo-SecureString -String $FTPPassword -asPlainText -Force
    $FTPCredentials          = New-Object System.Management.Automation.PSCredential($FTPUsername,$FTPSecurePassword)

    # Azure LogAnalytics Workspace
    $AzLAWorkspaceId         = "33e3c74f-d5cb-4919-8563-97c53c90874f"


#------------------------------------------------------------------------------------------------------------
# Initialization
#------------------------------------------------------------------------------------------------------------

    MD $TempPath -ErrorAction SilentlyContinue

    # ABUSE IPDB
    $Header = @{
	            'Key' = $APIKey;
               }

    $AbuseIPCheckArray = @()
    $NewBlockListArray = @()
    $BlockListArrayCount = $BlockListArray.IPAddresses.Count


#------------------------------------------------------------------------------------------------------------
# Step 1 - Set flag to suspend AbuseIPDB-Check from running until this script has completed
# Every 24 hours, banned list checking will be suspended during the daily re-check of all banned IPs
# This task is important, as it will remove any banned IPs, which has been whitelisted again
#
# Below is where this flag is set
#------------------------------------------------------------------------------------------------------------

    $Text = "Check to unblock whitelisted IP addresses in progress"
    $Text | Add-Content -Path "$($TempPath)\PAFW-WhiteListCheckingInProgress.txt" -Encoding UTF8



#------------------------------------------------------------------------------------------------------------
# Step 2 - build array of BlockList
# Banned on AbuseIPDB, IP should be blocked
#------------------------------------------------------------------------------------------------------------

    $BlockListCSV       = "$($TempPath)\PAFW-BlockList.csv"                   # Banned on AbuseIPDB, IP should be blocked
    $BlockListTXT       = "$($TempPath)\PAFW-BlockList.TXT"                   # Banned on AbuseIPDB, IP should be blocked

    # Importing if found - otherwise creating empty array
    If (test-path $BlockListCSV)
        {
            $BlockListArray  = Import-Csv $BlockListCSV -Delimiter ";" -Encoding UTF8 -ErrorVariable SilentlyContinue
        }
    Else
        {
            $BlockListArray  = @()
        }


#------------------------------------------------------------------------------------------------------------
# Step 3 - build array of exceptions
# Allow traffic from IP addresses, even though they are banned through AbuseIPDB
#------------------------------------------------------------------------------------------------------------

    $ExceptionListCSV   = "$($TempPath)\PAFW-ExceptionList.csv"               # Banned on ABuseITDB, but traffic should be allowed (e.g. customer being banned by mistake)
    $ExceptionListTXT   = "$($TempPath)\PAFW-ExceptionList.TXT"               # Banned on ABuseITDB, but traffic should be allowed (e.g. customer being banned by mistake)


    # Importing if found - otherwise creating empty array
    If (test-path $ExceptionListCSV)
        {
            $ExceptionListArray  = Import-Csv $ExceptionListCSV -Delimiter ";" -Encoding UTF8 -ErrorVariable SilentlyContinue
        }
    Else
        {
            $ExceptionListArray  = @()
        }


#-------------------------------------------------------------------------------------------------------------------------------------
# Step 4 - Existing Blocked IP Addresses
#-------------------------------------------------------------------------------------------------------------------------------------
    $Counter = 0

    Write-Output ""
    ForEach ($IPEntry in $BlockListArray)
        {
            $IP = $IPEntry.IPAddress
            $Counter = 1 + $Counter

            Write-Output ""
            Write-Output "[$($Counter) / $($BlockListArrayCount)] - Checking $($IP) against AbuseIPDB ...."
	        $URICheck = "https://api.abuseipdb.com/api/v2/check"
	        $BodyCheck = @{
		        'ipAddress' = $IP;
		        'maxAgeInDays' = '90';
		        'verbose' = '';
	        }
	            Try {
                    <#  GET abuse confidence score and set status if successful  #>
		                $AbuseIPDB = Invoke-RestMethod -Method GET $URICheck -Header $Header -Body $BodyCheck -ContentType 'application/json; charset=utf-8' 

	            }
	            Catch {
		            <#  If error, capture status number from message  #>
		            $ErrorMessage = $_.Exception.Message
		            [regex]$RegexErrorNum = "\d{3}"
		            $StatusNum = ($RegexErrorNum.Matches($ErrorMessage)).Value	
	            }

                Write-output "   IP Address           : $($IP)"
                Write-output "   ConfidenceScore      : $($ConfidenceScore)"
                Write-output "   isWhiteListed        : $($isWhiteListed)"
                Write-output "   CountryCode          : $($CountryCode)"
                Write-output "   CountryName          : $($CountryName)"
                Write-output "   ISP                  : $($ISP)"
                Write-output "   Domain               : $($Domain)"
                Write-output "   Last Reported At     : $($LastReportedAt)"
                Write-output "   Total Reports        : $($TotalReports)"

                    # Defining variables
		                $StatusNum = "200"
		                $ConfidenceScore = $AbuseIPDB.data.abuseConfidenceScore
		                $ConfidenceScore_Num = [Decimal]$ConfidenceScore
                        $isWhiteListed = $AbuseIPDB.data.isWhiteListed
                        $CountryCode = $AbuseIPDB.data.countryCode
                        $CountryName = $AbuseIPDB.data.countryName
                        $ISP = $AbuseIPDB.data.isp
                        $Domain = $AbuseIPDB.data.domain
                        $LastReportedAt = $AbuseIPDB.data.lastReportedAt
                        $TotalReports = $AbuseIPDB.data.totalreports

                    # Build entry to array
                        $AbuseIPCheck  = New-Object -TypeName PSObject
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value $IP
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "ConfidenceScore" -Value $ConfidenceScore
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "isWhiteListed" -Value $isWhiteListed
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "CountryCode" -Value $CountryCode
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "CountryName" -Value $CountryName
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "ISP" -Value $ISP
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "Domain" -Value $Domain
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "LastReportedAt" -Value $LastReportedAt
                        $AbuseIPCheck | Add-Member -MemberType NoteProperty -Name "TotalReports" -Value $TotalReports

                    # Add to Array
                        If ($ConfidenceScore_Num -eq 0)
                            {
                                Write-Output ""
                                Write-Output "   GOOD IP: $($IP) was NOT found in Abuse DB - skipping !"
                                Write-Output ""
                            }

                        ElseIf ( ($ConfidenceScore_Num -gt $ConfidenceScore_Minimum) -and ($isWhiteListed -match "False") )
                            {
                                If ($IP -in $ExceptionListArray.IPAddress)
                                    {
                                        Write-Output ""
                                        Write-Output "   EXCEPTION IP : $($IP) was found in Abuse DB with Confidence Score of $($ConfidenceScore) but IP address should be Allowed/Excepted"
                                        Write-Output ""
                                    }
                                ElseIf ($IP -notin $ExceptionListArray.IPAddress)
                                    {
                                        Write-Output ""
                                        Write-Output "   BANNED IP: $($IP) was found in Abuse DB with Confidence Score of $($ConfidenceScore) (total reports: $($TotalReports))"
                                        Write-Output ""
                                        $NewBlockListArray += $AbuseIPCheck
                                    }
                            }

                        ElseIf ($isWhiteListed -match "True")
                            {
                                Write-Output ""
                                Write-Output "WHITELIST IP: $($IP) was previously banned, but should be removed from blocklist"
                                Write-Output ""
                            }
        }


#-------------------------------------------------------------------------------------------------------------------------------------
# Step 5 - Saving Results to CSV and TXT-file
#-------------------------------------------------------------------------------------------------------------------------------------

    # Defining new BlockListArray - based on NewBlockListArray
        $BlockListArray = $NewBlockListArray

    # Writing BlockList to CSV-file
        Write-Output ""
        Write-Output "Writing blocklist to CSV file $($BlockListCSV)"
        Remove-Item $BlockListCSV  -ErrorAction SilentlyContinue
        $BlockListArray | Export-CSV -Path $BlockListCSV -Encoding UTF8 -Delimiter ";" -NoTypeInformation

    # Writing BlockList to TXT-file
        Write-Output ""
        Write-Output "Writing blocklist to TXT file $($BlockListTXT)"
        Remove-Item $BlockListTXT -ErrorAction SilentlyContinue
        $BlockListArray.IPAddress | Add-Content -Path $BlockListTXT -Encoding UTF8

#-------------------------------------------------------------------------------------------------------------------------------------
# Step 6 - Uploading to Azure App using FTP-protocol
#-------------------------------------------------------------------------------------------------------------------------------------

    # Connect to FTP server
        Write-Output ""
        Write-Output "Connecting to Azure App service using FTP - URL $($FTPUrl)"
        $Connect = Set-FTPConnection -Credentials $FTPCredentials -Server $FTPURL -Session FTPUPLOAD -ignoreCert -UsePassive -UseBinary

    # Upload file to FTP server
        $LocalFile = $BlockListTXT
        Write-Output ""
        Write-Output "Upload blocklist to Azure App service using FTP"
        $Upload = Add-FTPItem -Path "/" -LocalPath $LocalFile -Overwrite $true -Session FTPUPLOAD

    # Verifying blocklist matches local file
        Write-Output ""
        Write-Output "Checking file version match .... Please Wait !"
        $FTPFileSize = Get-FTPItemSize -Path "/PAFW-Blocklist.txt" -Silent -Session FTPUPLOAD
        $LocalFileSize = (Get-Item $BlockListTXT).length

        If ($LocalFileSize -eq $FTPFileSize)
            {
                Write-Output ""
                Write-Output "  SUCCESS: File was uploaded successfully (file-size match) !"
                Write-Output ""
                Write-output "  File can be read directly by using this path https://cs-firewall-blocklist.azurewebsites.net/PAFW-Blocklist.txt"
                Write-Output ""
            }
        Else
            {
                Write-Output ""
                Write-Output "  ERROR: File size mismatch between FTP version and local version !"
            }


#------------------------------------------------------------------------------------------------------------
# Step 7 - Delete lock on block-list
#------------------------------------------------------------------------------------------------------------
    Remove-Item "$($TempPath)\PAFW-WhiteListCheckingInProgress.txt"
