function Prompt-YesNo($message) {
    while ($true) {
        $response = Read-Host "$message (yes/no)"
        switch ($response.ToLower()) {
            'yes' { return $true }
            'no'  { return $false }
            default { Write-Host "Please answer 'yes' or 'no'" -ForegroundColor Yellow }
        }
    }
}

function Prompt-Choice($message, $options) {
    Write-Host $message
    for ($i = 0; $i -lt $options.Count; $i++) {
        Write-Host "[$i] $($options[$i])"
    }
    while ($true) {
        $choice = Read-Host "Enter your choice number"
        if ($choice -match '^\d+$' -and $choice -ge 0 -and $choice -lt $options.Count) {
            return $options[$choice]
        } else {
            Write-Host "Invalid choice. Try again." -ForegroundColor Red
        }
    }
}

function Run-CorrelationSummary {
    param ($LogPath)

    $UserCreationMap = @{}
    $UserGroupMap = @{}

    $events = Get-WinEvent -Path $LogPath | Where-Object { $_.Id -in @(4720, 4732) }

    foreach ($event in $events) {
        try {
            [xml]$xml = $event.ToXml()
        } catch {
            Write-Warning "Skipping malformed event..."
            continue
        }

        $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $nsMgr.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $dataNodes = $xml.SelectNodes("//e:EventData/e:Data", $nsMgr)

        $data = @{}
        foreach ($node in $dataNodes) {
            $name = if ($node.Attributes["Name"]) { $node.Attributes["Name"].Value } else { "Unknown" }
            $val = if ($node.'#text') { $node.'#text' } else { "null" }
            $data[$name] = $val
        }

        if ($event.Id -eq 4720) {
            $TargetUserName = $data["TargetUserName"]
            $TargetSid = $data["TargetSid"]
            $CreatedBy = $data["SubjectUserName"]
            $LogonId = $data["SubjectLogonId"]

            $UserCreationMap[$TargetSid] = @{
                UserName = $TargetUserName
                CreatedBy = $CreatedBy
                LogonId = $LogonId
            }

        } elseif ($event.Id -eq 4732) {
            $MemberSid = $data["MemberSid"]
            $GroupName = $data["TargetUserName"]

            if (-not $UserGroupMap.ContainsKey($MemberSid)) {
                $UserGroupMap[$MemberSid] = @()
            }
            $UserGroupMap[$MemberSid] += $GroupName
        }
    }

    Write-Host "`n===== User Creation + Group Membership Summary =====" -ForegroundColor Cyan
    foreach ($sid in $UserCreationMap.Keys) {
        $entry = $UserCreationMap[$sid]
        $groups = $UserGroupMap[$sid]

        Write-Host "`n[+] User Created: $($entry.UserName)" -ForegroundColor Green
        Write-Host "    Created By : $($entry.CreatedBy)"
        Write-Host "    LogonId    : $($entry.LogonId)"
        if ($groups) {
            $uniqueGroups = $groups | Sort-Object -Unique
            Write-Host "    Groups     : $($uniqueGroups -join ', ')" -ForegroundColor Yellow
        } else {
            Write-Host "    Groups     : None" -ForegroundColor DarkYellow
        }
    }

    Write-Host "`nDone." -ForegroundColor Cyan
}

function Run-LogRipper {
    $logPath = Read-Host "Enter full path to .evtx log file (or type 'exit' to quit)"
    if ($logPath -eq "exit") { exit }

    if (-not (Test-Path $logPath)) {
        Write-Host "File not found: $logPath" -ForegroundColor Red
        return
    }

    $idInput = Read-Host "Enter Event ID(s) to analyze (comma separated, e.g., 1074,4624)"
    $eventIDsToWatch = $idInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }

    # If analyzing user management events, ask if want auto summary
    $wantsAutoSummary = $false
    if ($eventIDsToWatch -contains 4720 -and $eventIDsToWatch -contains 4732) {
        $wantsAutoSummary = Prompt-YesNo "Want to run a User Creation + Group Membership Summary automatically"
    }

    if ($wantsAutoSummary) {
        Run-CorrelationSummary -LogPath $logPath
        return
    }

    # Normal filtering for other event IDs, or if user says no to summary
    $authEventIDs = @(4624, 4625)
    $advancedFilters = @{}

    if ($eventIDsToWatch | Where-Object { $authEventIDs -contains $_ }) {
        Write-Host "Authentication Event ID(s) Detected." -ForegroundColor Cyan
        if (Prompt-YesNo "Want to filter more") {
            if (Prompt-YesNo "Want to filter for LogonType") {
                $logonTypesInput = Read-Host "LogonType Number(s) (comma-separated, e.g., 3,10)"
                $advancedFilters.LogonTypes = $logonTypesInput -split "," | ForEach-Object { $_.Trim() }
            }
            if (Prompt-YesNo "Want to filter for TargetUserName") {
                $usernameFilter = Read-Host "TargetUserName (e.g., Administrator)"
                $advancedFilters.TargetUserName = $usernameFilter.Trim()
            }
            if (Prompt-YesNo "Want to filter for IpAddress") {
                $ipFilter = Read-Host "IpAddress (e.g., 10.10.53.248)"
                $advancedFilters.IpAddress = $ipFilter.Trim()
            }
        }
    }

    try {
        $events = Get-WinEvent -Path $logPath
    } catch {
        Write-Host "Failed to load events from $logPath" -ForegroundColor Red
        return
    }

    $filteredEvents = $events | Where-Object {
        $eventMatch = $eventIDsToWatch -contains $_.Id
        if (-not $eventMatch) { return $false }

        if ($authEventIDs -contains $_.Id -and $advancedFilters.Count -gt 0) {
            try {
                [xml]$xml = $_.ToXml()
                $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $nsMgr.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")

                $dataNodes = $xml.SelectNodes("//e:EventData/e:Data", $nsMgr)
                $dataHash = @{}
                foreach ($node in $dataNodes) {
                    $name = if ($node.Attributes["Name"]) { $node.Attributes["Name"].Value } else { "Unknown" }
                    $val = if ($node.'#text') { $node.'#text' } else { "" }
                    $dataHash[$name] = $val
                }

                if ($advancedFilters.LogonTypes -and ($dataHash["LogonType"] -notin $advancedFilters.LogonTypes)) {
                    return $false
                }

                if ($advancedFilters.TargetUserName -and ($dataHash["TargetUserName"] -ne $advancedFilters.TargetUserName)) {
                    return $false
                }

                if ($advancedFilters.IpAddress -and ($dataHash["IpAddress"] -ne $advancedFilters.IpAddress)) {
                    return $false
                }

            } catch {
                Write-Warning "Could not parse advanced filters for event"
                return $false
            }
        }

        return $true
    }

    $parsed = $filteredEvents | ForEach-Object {
        try {
            [xml]$xml = $_.ToXml()
        } catch {
            Write-Warning "Skipping malformed event..."
            return
        }

        $stringBuilder = New-Object System.Text.StringBuilder
        $xmlWriterSettings = New-Object System.Xml.XmlWriterSettings
        $xmlWriterSettings.Indent = $true
        $xmlWriterSettings.OmitXmlDeclaration = $true
        $xmlWriter = [System.Xml.XmlWriter]::Create($stringBuilder, $xmlWriterSettings)
        $xml.WriteTo($xmlWriter)
        $xmlWriter.Flush()
        $prettyXml = $stringBuilder.ToString()

        $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $nsMgr.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")

        $dataNodes = $xml.SelectNodes("//e:EventData/e:Data", $nsMgr)
        $dataFields = foreach ($node in $dataNodes) {
            $name = if ($node.Attributes["Name"]) { $node.Attributes["Name"].Value } else { "Unknown" }
            $val = if ($node.'#text') { $node.'#text' } else { "null" }
            [PSCustomObject]@{ Name = $name; Value = $val }
        }

        $system = $xml.SelectSingleNode("//e:System", $nsMgr)

        [PSCustomObject]@{
            TimeCreated    = $_.TimeCreated
            EventID        = $_.Id
            EventRecordID  = $system.SelectSingleNode("e:EventRecordID", $nsMgr).InnerText
            ProviderName   = $system.SelectSingleNode("e:Provider", $nsMgr).GetAttribute("Name")
            Version        = $system.SelectSingleNode("e:Version", $nsMgr).InnerText
            Level          = $system.SelectSingleNode("e:Level", $nsMgr).InnerText
            Task           = $system.SelectSingleNode("e:Task", $nsMgr).InnerText
            Opcode         = $system.SelectSingleNode("e:Opcode", $nsMgr).InnerText
            ProcessID      = $system.SelectSingleNode("e:Execution", $nsMgr).GetAttribute("ProcessID")
            ThreadID       = $system.SelectSingleNode("e:Execution", $nsMgr).GetAttribute("ThreadID")
            Channel        = $system.SelectSingleNode("e:Channel", $nsMgr).InnerText
            Computer       = $system.SelectSingleNode("e:Computer", $nsMgr).InnerText
            UserID         = $system.SelectSingleNode("e:Security", $nsMgr).GetAttribute("UserID")
            DataValues     = $dataFields
            PrettyXml      = $prettyXml
        }
    }

    foreach ($entry in $parsed) {
        Write-Host "─────────────── EVENT ───────────────" -ForegroundColor Cyan
        Write-Host ("{0,-15}: {1}" -f "TimeCreated",    $entry.TimeCreated)    -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "EventID",        $entry.EventID)        -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "EventRecordID",  $entry.EventRecordID)  -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "ProviderName",   $entry.ProviderName)   -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Version",        $entry.Version)        -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Level",          $entry.Level)          -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Task",           $entry.Task)           -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Opcode",         $entry.Opcode)         -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "ProcessID",      $entry.ProcessID)      -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "ThreadID",       $entry.ThreadID)       -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Channel",        $entry.Channel)        -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "Computer",       $entry.Computer)       -ForegroundColor Yellow
        Write-Host ("{0,-15}: {1}" -f "UserID",         $entry.UserID)         -ForegroundColor Yellow
        Write-Host "DataValues     :" -ForegroundColor Green

        $suspiciousScore = 0
        foreach ($field in $entry.DataValues) {
            $val = $field.Value
            $highlight = $false

            if ($val -match "shutdown|\.exe|MXNfYV|base64|powershell|cmd\.exe|wscript|reg add|bypass|Invoke-|curl|wget|whoami") {
                $highlight = $true
                $suspiciousScore++
            }

            if ($highlight) {
                Write-Host ("  - {0,-20} : {1}" -f $field.Name, $val) -ForegroundColor Red
            } else {
                Write-Host ("  - {0,-20} : {1}" -f $field.Name, $val) -ForegroundColor Green
            }
        }

        if ($suspiciousScore -gt 1) {
            Write-Host "POTENTIAL MALICIOUS ACTIVITY DETECTED (Score: $suspiciousScore)" -ForegroundColor Magenta
        }

        Write-Host "─────────────────────────────────────`n"
    }

    if (Prompt-YesNo "Do you want to export the results") {
        $format = Prompt-Choice "Choose export format:" @("JSON", "CSV")
        if ($format -eq "JSON") {
            $parsed | ConvertTo-Json -Depth 5 | Out-File "TheLogRipper_output.json"
            Write-Host "Exported to TheLogRipper_output.json" -ForegroundColor Cyan
        } elseif ($format -eq "CSV") {
            $parsed | Select-Object TimeCreated, EventID, ProviderName, UserID, Channel, EventRecordID | Export-Csv "TheLogRipper_output.csv" -NoTypeInformation
            Write-Host "Exported to TheLogRipper_output.csv" -ForegroundColor Cyan
        }
    }
}

while ($true) {
    Run-LogRipper
    Write-Host ""
}
