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

function Run-LogRipper {
    $logPath = Read-Host "Enter full path to .evtx log file (or type 'exit' to quit)"
    if ($logPath -eq "exit") {
        exit
    }

    if (-not (Test-Path $logPath)) {
        Write-Host "File not found: $logPath" -ForegroundColor Red
        return
    }

    $idInput = Read-Host "Enter Event ID(s) to analyze (comma separated, e.g., 1074,4624)"
    $eventIDsToWatch = $idInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }

    try {
        $events = Get-WinEvent -Path $logPath
    } catch {
        Write-Host "Failed to load events from $logPath" -ForegroundColor Red
        return
    }

    $filteredEvents = $events | Where-Object { $eventIDsToWatch -contains $_.Id }

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
            [PSCustomObject]@{
                Name  = $name
                Value = $val
            }
        }

        $system = $xml.SelectSingleNode("//e:System", $nsMgr)

        $providerNode  = $system.SelectSingleNode("e:Provider", $nsMgr)
        $providerName  = if ($providerNode) { $providerNode.GetAttribute("Name") } else { "Unknown" }

        $eventRecordIDNode = $system.SelectSingleNode("e:EventRecordID", $nsMgr)
        $eventRecordID = if ($eventRecordIDNode) { $eventRecordIDNode.InnerText } else { "Unknown" }

        $execution     = $system.SelectSingleNode("e:Execution", $nsMgr)
        $processID     = if ($execution) { $execution.GetAttribute("ProcessID") } else { "Unknown" }
        $threadID      = if ($execution) { $execution.GetAttribute("ThreadID") } else { "Unknown" }

        $channelNode   = $system.SelectSingleNode("e:Channel", $nsMgr)
        $channel       = if ($channelNode) { $channelNode.InnerText } else { "Unknown" }

        $computerNode  = $system.SelectSingleNode("e:Computer", $nsMgr)
        $computer      = if ($computerNode) { $computerNode.InnerText } else { "Unknown" }

        $security      = $system.SelectSingleNode("e:Security", $nsMgr)
        $userID        = if ($security) { $security.GetAttribute("UserID") } else { "Unknown" }

        $versionNode   = $system.SelectSingleNode("e:Version", $nsMgr)
        $version       = if ($versionNode) { $versionNode.InnerText } else { "Unknown" }

        $levelNode     = $system.SelectSingleNode("e:Level", $nsMgr)
        $level         = if ($levelNode) { $levelNode.InnerText } else { "Unknown" }

        $taskNode      = $system.SelectSingleNode("e:Task", $nsMgr)
        $task          = if ($taskNode) { $taskNode.InnerText } else { "Unknown" }

        $opcodeNode    = $system.SelectSingleNode("e:Opcode", $nsMgr)
        $opcode        = if ($opcodeNode) { $opcodeNode.InnerText } else { "Unknown" }

        [PSCustomObject]@{
            TimeCreated    = $_.TimeCreated
            EventID        = $_.Id
            EventRecordID  = $eventRecordID
            ProviderName   = $providerName
            Version        = $version
            Level          = $level
            Task           = $task
            Opcode         = $opcode
            ProcessID      = $processID
            ThreadID       = $threadID
            Channel        = $channel
            Computer       = $computer
            UserID         = $userID
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

# Main interactive loop
while ($true) {
    Run-LogRipper
    Write-Host ""
}
