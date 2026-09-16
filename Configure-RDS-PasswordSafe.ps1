<#
.SYNOPSIS
    Configures a single Windows Server (RDS Connection Broker + Session Host + Licensing)
    for use with BeyondTrust Password Safe RemoteApp / Application sessions.

.DESCRIPTION
    Implements the BeyondTrust KB checklist for RDS servers hosting Password Safe
    Application sessions, targeting an all-in-one-server deployment (all 3 RDS
    roles on one box). Each step is wrapped independently so a single failure is
    logged and the script continues to the remaining steps instead of aborting.

    Steps performed:
      1. Install RDS roles (Connection Broker, Session Host, Licensing) if missing
      2. Create the RDS session deployment (New-RDSessionDeployment) if one doesn't
         already exist - Install-WindowsFeature alone does not create this
      3. Create the 'PasswordSafe-<name>' RD Session Collection, and publish
         pbpslaunch.exe / ps_automate.exe / pbpsmon.exe as RemoteApps (command-line
         parameters allowed) for whichever of those actually exist under PbpsmonPath
      4. Allow multiple concurrent sessions per user (registry, matches GPO path)
      5. Set session time limits (disconnected / active / idle) via registry
      6. Set RemoteApp logoff delay via registry
      7. Set max simultaneous RDS connections
      8. Create Pbpslaunch / PSAutomate system environment variables
      9. Run gpupdate /force
      10. Print manual follow-up items (licensing activation/CALs, load balancer /
          firewall notes) that cannot be automated safely

    Safety features:
      - Pre-flight checks (Administrator, Server SKU, pending reboot, free disk space)
        must pass, or be explicitly bypassed, before any change is made.
      - Every registry key this script touches is exported to a timestamped .reg
        backup under -BackupPath before it is modified, and a matching
        Undo-<timestamp>.ps1 rollback script is generated alongside it.
      - Supports -WhatIf / -Confirm (SupportsShouldProcess) to preview changes
        without applying them.
      - Full session transcript is written to -BackupPath.
      - Ephemeral by default: the script deletes its own .ps1 file after it
        finishes running (registry backups, rollback script, and transcript
        under -BackupPath are always kept). Pass -NoSelfCleanup to keep the
        script file around.

.PARAMETER WhatIf
    Preview every change (registry, features, env vars, gpupdate) without applying it.

.EXAMPLE
    .\Configure-RDS-PasswordSafe.ps1 -WhatIf
    Dry run - shows exactly what would change, changes nothing.

.EXAMPLE
    .\Configure-RDS-PasswordSafe.ps1
    Applies the configuration, after pre-flight checks pass and after prompting
    for confirmation once (unless -Confirm:$false is passed).

.NOTES
    Must be run as Administrator on the target RDS server.
    Setup/licensing of Microsoft RDS itself is outside BeyondTrust support scope;
    consult Microsoft documentation for RDS licensing requirements.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Minutes to allow a disconnected session before ending it (1-7200). Default 60 min.
    [ValidateRange(1, 7200)]
    [int]$DisconnectedSessionLimitMinutes = 60,

    # Minutes for active-but-idle session timeout. 0 = do not set / leave as Never.
    [ValidateRange(0, 7200)]
    [int]$IdleSessionLimitMinutes = 0,

    # Minutes for max total active session length. 0 = do not set / leave as Never.
    [ValidateRange(0, 7200)]
    [int]$ActiveSessionLimitMinutes = 0,

    # Milliseconds delay before logging off a RemoteApp session after last app closes. 0 = immediate.
    [ValidateRange(0, 432000000)]
    [int]$RemoteAppLogoffDelayMs = 0,

    # Max simultaneous RDS connections allowed on this host.
    [ValidateRange(1, 999999)]
    [int]$MaxConnections = 999999,

    # Path to the BeyondTrust pbpsmon folder (holds pbpslaunch.exe / ps_automate.exe).
    [ValidateNotNullOrEmpty()]
    [string]$PbpsmonPath = 'C:\Program Files\BeyondTrust\pbpsmon',

    # Skip the RDS Windows feature installation step (use if roles are already installed
    # or being installed/managed separately).
    [switch]$SkipFeatureInstall,

    # Directory to store registry backups, generated rollback script, and transcript.
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = (Join-Path $env:ProgramData 'BeyondTrust\RDS-Config-Backups'),

    # Skip the pre-flight environment checks (Server SKU, pending reboot, disk space).
    # Only use if you have already verified the server manually.
    [switch]$SkipPreflightChecks,

    # Minimum free space (GB) required on the system drive before proceeding.
    [ValidateRange(1, 1000)]
    [int]$MinFreeDiskGB = 5,

    # RDS CAL licensing mode to configure on the license server (PerUser or PerDevice).
    # Must match the CALs you actually purchased - consult your Microsoft licensing agreement.
    [ValidateSet('PerUser', 'PerDevice')]
    [string]$LicenseMode = 'PerUser',

    # Name of the RD Session Collection to create/use for Password Safe RemoteApps.
    # Auto-prefixed with "PasswordSafe-" if you don't already include it.
    [ValidateNotNullOrEmpty()]
    [string]$CollectionName = 'PasswordSafe-Apps',

    # Skip auto-creating the RD Session Collection and publishing the pbpsmon RemoteApps.
    [switch]$SkipRemoteAppPublish,

    # Do not delete this script file after it finishes running. By default the
    # script self-deletes once it completes (registry backups, rollback script,
    # and transcript in -BackupPath are never deleted - only this .ps1 file is).
    [switch]$NoSelfCleanup
)

$ErrorActionPreference = 'Stop'
$script:results = New-Object System.Collections.Generic.List[pscustomobject]
$script:touchedKeys = New-Object System.Collections.Generic.List[pscustomobject]
$script:customValues = New-Object System.Collections.Generic.List[pscustomobject]
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($CollectionName -notmatch '^PasswordSafe-') {
    $CollectionName = "PasswordSafe-$CollectionName"
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $Name)) {
        Write-Host "`n==> $Name (skipped: -WhatIf)" -ForegroundColor DarkGray
        $script:results.Add([pscustomobject]@{ Step = $Name; Status = 'SKIPPED (WhatIf)'; Detail = '' })
        return
    }

    Write-Host "`n==> $Name" -ForegroundColor Cyan
    try {
        & $Action
        Write-Host "    OK: $Name" -ForegroundColor Green
        $script:results.Add([pscustomobject]@{ Step = $Name; Status = 'OK'; Detail = '' })
    }
    catch {
        Write-Host "    FAILED: $Name -> $($_.Exception.Message)" -ForegroundColor Yellow
        $script:results.Add([pscustomobject]@{ Step = $Name; Status = 'FAILED'; Detail = $_.Exception.Message })
    }
}

function Backup-RegistryKey {
    # Exports the key (if it exists) to a .reg file before it is first touched this run,
    # and records enough info to build an Undo script. Safe to call once per key.
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if ($script:touchedKeys.Path -contains $Path) { return }

    $regPath = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
    $existed = Test-Path $Path
    $backupFile = Join-Path $BackupPath ("{0}_{1}.reg" -f $stamp, ($Path -replace '[\\:]', '_'))

    if ($existed) {
        $p = Start-Process -FilePath 'reg.exe' -ArgumentList "export `"$regPath`" `"$backupFile`" /y" -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "reg.exe export of '$regPath' failed with code $($p.ExitCode)" }
    }

    $script:touchedKeys.Add([pscustomobject]@{
        Path        = $Path
        RegPath     = $regPath
        ExistedBefore = $existed
        BackupFile  = if ($existed) { $backupFile } else { $null }
    })
}

function Set-RegistryValue {
    # Additive/non-destructive by design:
    #   - value doesn't exist yet          -> set it (nothing lost, pure addition)
    #   - value exists and already matches -> no-op
    #   - value exists and equals a known "off"/unconfigured baseline (-OffValues) -> flip it to Value
    #   - value exists and is something else entirely -> leave it alone, just report it
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Type = 'DWord',
        [object[]]$OffValues = @()
    )

    $current = $null
    $exists = $false
    if (Test-Path $Path) {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($prop -and ($prop.PSObject.Properties.Name -contains $Name)) {
            $exists = $true
            $current = $prop.$Name
        }
    }

    if (-not $exists) {
        Backup-RegistryKey -Path $Path
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Host "    $Name was not configured - set to $Value."
        return
    }

    if ("$current" -eq "$Value") {
        Write-Host "    $Name already set to $Value - no change needed."
        return
    }

    if ($OffValues -contains $current) {
        Backup-RegistryKey -Path $Path
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Host "    $Name was $current (off/default) - changed to $Value."
        return
    }

    Write-Host "    $Name is already customized to $current (not the default/off state) - leaving as-is, NOT overwriting with $Value." -ForegroundColor DarkYellow
    $script:customValues.Add([pscustomobject]@{ Path = $Path; Name = $Name; CurrentValue = $current; RequestedValue = $Value })
}

function Invoke-PreflightChecks {
    Write-Host "`n===================== PRE-FLIGHT CHECKS =====================" -ForegroundColor Magenta
    $problems = New-Object System.Collections.Generic.List[string]

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($os.ProductType -eq 1) {
        $problems.Add("OS reports as a Workstation SKU (ProductType=1) - RDS Session Host roles require Windows Server.")
    }
    Write-Host "    OS: $($os.Caption) (Build $($os.BuildNumber))"

    $rebootPending = $false
    $rebootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($rp in $rebootPaths) {
        if (Test-Path $rp) { $rebootPending = $true }
    }
    try {
        if (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
            $rebootPending = $true
        }
    } catch {}
    if ($rebootPending) {
        $problems.Add("A reboot is already pending on this server. Installing RDS roles now may fail or require a second reboot mid-configuration.")
    }
    Write-Host "    Reboot pending: $rebootPending"

    $sysDrive = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'")
    $freeGB = [math]::Round($sysDrive.FreeSpace / 1GB, 1)
    Write-Host "    Free space on $($env:SystemDrive): $freeGB GB"
    if ($freeGB -lt $MinFreeDiskGB) {
        $problems.Add("Only $freeGB GB free on $($env:SystemDrive) - below the $MinFreeDiskGB GB minimum for a safe RDS role install.")
    }

    # New-RDSessionDeployment always talks to the broker over WinRM, even when broker
    # and session host are the same box. Check that up front - the raw RDS error for
    # this ("Unable to connect to the server by using Windows PowerShell remoting")
    # gives no hint about the actual cause.
    if (-not $SkipRemoteAppPublish) {
        try {
            Test-WSMan -ComputerName $env:COMPUTERNAME -ErrorAction Stop | Out-Null
            Write-Host "    WinRM (PowerShell remoting) to self: OK"
        }
        catch {
            $problems.Add("WinRM/PowerShell remoting to '$env:COMPUTERNAME' is not working ($($_.Exception.Message)). New-RDSessionDeployment requires this even for a single-server deployment. Run 'Enable-PSRemoting -Force' and confirm no firewall blocks TCP 5985, then re-run. Or pass -SkipRemoteAppPublish to skip deployment/collection/RemoteApp steps.")
        }

        $domain = (Get-CimInstance -ClassName Win32_ComputerSystem)
        if ($domain.PartOfDomain) {
            # nltest writes to stderr on failure; under $ErrorActionPreference='Stop' that
            # becomes a terminating error via 2>&1, so isolate it with its own EAP.
            $prevEAP = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            $dcTestOutput = & nltest /dsgetdc:$($domain.Domain) 2>&1 | Out-String
            $dcTestExitCode = $LASTEXITCODE
            $ErrorActionPreference = $prevEAP

            if ($dcTestExitCode -ne 0) {
                if ($dcTestOutput -match 'ERROR_NO_SUCH_DOMAIN') {
                    $problems.Add("Server believes it's joined to domain '$($domain.Domain)', but Windows cannot resolve that domain at all (ERROR_NO_SUCH_DOMAIN - no DNS SRV records found for it). This is not a transient connectivity issue: check the server's DNS server settings (ipconfig /all) point at a DNS server that hosts/forwards for '$($domain.Domain)', and confirm the domain name itself is correct. This also explains the gpupdate and WinRM-over-FQDN failures.")
                }
                else {
                    $problems.Add("Server is domain-joined to '$($domain.Domain)' but cannot locate/reach a domain controller (nltest /dsgetdc failed: $($dcTestOutput.Trim())). This also breaks gpupdate and WinRM-over-FQDN. Fix DNS/network connectivity to a DC before proceeding.")
                }
            }
            else {
                Write-Host "    Domain controller reachable for '$($domain.Domain)': OK"
            }
        }
        else {
            Write-Host "    Server is not domain-joined (workgroup) - gpupdate /force will always fail here; that's expected, not a script bug."
        }
    }

    if (Test-Path (Join-Path $PbpsmonPath 'pbpslaunch.exe')) {
        Write-Host "    pbpsmon tools found at $PbpsmonPath" -ForegroundColor Green
    } else {
        Write-Host "    pbpsmon tools NOT found at $PbpsmonPath (env vars will still be created, pointing at a path that doesn't exist yet)." -ForegroundColor DarkYellow
    }

    if ($problems.Count -gt 0) {
        Write-Host "`nPre-flight check FAILED:" -ForegroundColor Red
        $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "`nRe-run with -SkipPreflightChecks to proceed anyway (not recommended), after addressing the above." -ForegroundColor Red
        exit 1
    }

    Write-Host "Pre-flight checks passed." -ForegroundColor Green
}

Write-Host "BeyondTrust Password Safe - RDS Server Configuration" -ForegroundColor Magenta
Write-Host "Target: $env:COMPUTERNAME  |  Started: $(Get-Date)" -ForegroundColor Magenta

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Re-launch an elevated PowerShell session." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
}
$transcriptFile = Join-Path $BackupPath "Transcript-$stamp.txt"
try { Start-Transcript -Path $transcriptFile -Force | Out-Null } catch { Write-Host "    (Could not start transcript: $($_.Exception.Message))" -ForegroundColor DarkYellow }

if (-not $SkipPreflightChecks) {
    Invoke-PreflightChecks
}
else {
    Write-Host "`n(Skipping pre-flight checks per -SkipPreflightChecks - proceeding at your own risk)" -ForegroundColor DarkYellow
}

# 1. Install RDS roles (single-server deployment)
if (-not $SkipFeatureInstall) {
    Invoke-Step -Name 'Install RDS-Connection-Broker feature' -Action {
        $f = Get-WindowsFeature -Name RDS-Connection-Broker
        if ($f.Installed) { Write-Host '    Already installed.' } else { Install-WindowsFeature -Name RDS-Connection-Broker -IncludeManagementTools | Out-Null }
    }
    Invoke-Step -Name 'Install RDS-RD-Server (Session Host) feature' -Action {
        $f = Get-WindowsFeature -Name RDS-RD-Server
        if ($f.Installed) { Write-Host '    Already installed.' } else { Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools | Out-Null }
    }
    Invoke-Step -Name 'Install RDS-Licensing feature' -Action {
        $f = Get-WindowsFeature -Name RDS-Licensing
        if ($f.Installed) { Write-Host '    Already installed.' } else { Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools | Out-Null }
    }

    # Install-WindowsFeature only installs the role binaries - it does NOT create the
    # RDS "deployment" object that links Broker/Session Host/Licensing together, which
    # is what Server Manager > Remote Desktop Services > Overview actually checks for.
    # Without this, session collections/RemoteApp publishing cannot be configured even
    # though the underlying Windows features report as Installed.
    Invoke-Step -Name 'Create RDS session deployment (Broker + Session Host + Licensing)' -Action {
        Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        $existingDeployment = $null
        try { $existingDeployment = Get-RDServer -ErrorAction Stop } catch {}

        if ($existingDeployment) {
            Write-Host "    RDS deployment already exists (found $($existingDeployment.Count) role instance(s)) - skipping."
        }
        else {
            New-RDSessionDeployment -ConnectionBroker $fqdn -SessionHost $fqdn -WebAccessServer $fqdn -ErrorAction Stop | Out-Null
            Add-RDServer -Server $fqdn -Role RDS-LICENSING -ConnectionBroker $fqdn -ErrorAction Stop
            Set-RDLicenseConfiguration -LicenseServer $fqdn -Mode $LicenseMode -ConnectionBroker $fqdn -Force -ErrorAction Stop
        }
    }
}
else {
    Write-Host "`n(Skipping RDS feature install per -SkipFeatureInstall)" -ForegroundColor DarkYellow
}

if (-not $SkipRemoteAppPublish) {
    Invoke-Step -Name "Create RD Session Collection '$CollectionName'" -Action {
        Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        $anyExisting = @(Get-RDSessionCollection -ErrorAction SilentlyContinue)
        if ($anyExisting.Count -gt 0) {
            $useCollection = $anyExisting | Where-Object { $_.CollectionName -eq $CollectionName } | Select-Object -First 1
            if (-not $useCollection) {
                $useCollection = $anyExisting[0]
            }
            $script:CollectionName = $useCollection.CollectionName
            Write-Host "    An RD Session Collection already exists ('$($useCollection.CollectionName)') - skipping creation and using it instead."
        }
        else {
            New-RDSessionCollection -CollectionName $CollectionName -SessionHost $fqdn -ConnectionBroker $fqdn -CollectionDescription 'BeyondTrust Password Safe application session RemoteApps' -ErrorAction Stop | Out-Null
        }
    }

    # Publish each pbpsmon executable as a RemoteApp, only if it actually exists on disk,
    # and only if it isn't already published (safe to re-run).
    $remoteApps = @(
        @{ Alias = 'pbpslaunch';  DisplayName = 'PasswordSafe - pbpslaunch';  File = 'pbpslaunch.exe' }
        @{ Alias = 'ps_automate'; DisplayName = 'PasswordSafe - ps_automate'; File = 'ps_automate.exe' }
        @{ Alias = 'pbpsmon';     DisplayName = 'PasswordSafe - pbpsmon';     File = 'pbpsmon.exe' }
    )

    # Look across every existing collection (not just $CollectionName) so a pbpsmon
    # app already published elsewhere - by this script's previous run, or by an admin
    # manually - is left alone instead of being duplicated in $CollectionName.
    $allExistingApps = @()
    try {
        Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
        foreach ($col in (Get-RDSessionCollection -ErrorAction SilentlyContinue)) {
            $allExistingApps += @(Get-RDRemoteApp -CollectionName $col.CollectionName -ErrorAction SilentlyContinue)
        }
    } catch {}

    foreach ($app in $remoteApps) {
        $exePath = Join-Path $PbpsmonPath $app.File
        if (-not (Test-Path $exePath)) {
            Write-Host "`n(Skipping RemoteApp publish for $($app.File) - not found at $exePath)" -ForegroundColor DarkYellow
            continue
        }

        $matchElsewhere = $allExistingApps | Where-Object {
            $_.Alias -eq $app.Alias -or $_.FilePath -eq $exePath
        } | Select-Object -First 1

        if ($matchElsewhere) {
            Write-Host "`n(Skipping RemoteApp publish for $($app.Alias) - already published as '$($matchElsewhere.Alias)' in collection '$($matchElsewhere.CollectionName)', leaving it untouched)" -ForegroundColor DarkYellow
            continue
        }

        Invoke-Step -Name "Publish RemoteApp: $($app.DisplayName)" -Action {
            Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
            $existingApp = Get-RDRemoteApp -CollectionName $CollectionName -Alias $app.Alias -ErrorAction SilentlyContinue
            if ($existingApp) {
                Write-Host "    RemoteApp '$($app.Alias)' already published in '$CollectionName' - skipping."
            }
            else {
                New-RDRemoteApp -CollectionName $CollectionName -Alias $app.Alias -DisplayName $app.DisplayName -FilePath $exePath -CommandLineSetting Allow -ErrorAction Stop | Out-Null
            }
        }
    }
}
else {
    Write-Host "`n(Skipping RD Collection creation / RemoteApp publishing per -SkipRemoteAppPublish)" -ForegroundColor DarkYellow
}

# 2. Allow multiple concurrent sessions per user
Invoke-Step -Name 'Allow multiple concurrent RDS sessions per user (fSingleSessionPerUser=0)' -Action {
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fSingleSessionPerUser' -Value 0 -OffValues @(1)
    # Also set the GPO-equivalent policy key so it matches "Restrict... to a single session" = Disabled
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServer' -Name 'fSingleSessionPerUser' -Value 0 -OffValues @(1)
}

# 3. Session time limits
Invoke-Step -Name 'Set time limit for disconnected sessions' -Action {
    $ms = $DisconnectedSessionLimitMinutes * 60 * 1000
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxDisconnectionTime' -Value $ms
    # End session (log off) when time limit is reached, rather than leaving it disconnected indefinitely
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fResetBroken' -Value 1
}

if ($IdleSessionLimitMinutes -gt 0) {
    Invoke-Step -Name 'Set time limit for active but idle sessions' -Action {
        $ms = $IdleSessionLimitMinutes * 60 * 1000
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxIdleTime' -Value $ms
    }
}
else {
    Write-Host "`n(Skipping idle session time limit - IdleSessionLimitMinutes=0)" -ForegroundColor DarkYellow
}

if ($ActiveSessionLimitMinutes -gt 0) {
    Invoke-Step -Name 'Set time limit for active sessions' -Action {
        $ms = $ActiveSessionLimitMinutes * 60 * 1000
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxConnectionTime' -Value $ms
    }
}
else {
    Write-Host "`n(Skipping max active session time limit - ActiveSessionLimitMinutes=0)" -ForegroundColor DarkYellow
}

# 4. RemoteApp logoff delay
Invoke-Step -Name 'Set RemoteApp session logoff delay' -Action {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'RemoteAppLogoffTimeLimit' -Value $RemoteAppLogoffDelayMs
}

# 5. Max simultaneous connections
Invoke-Step -Name 'Set maximum number of RDS connections' -Action {
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'MaxInstanceCount' -Value $MaxConnections
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxInstanceCount' -Value $MaxConnections
}

# 6. Environment variables for pbpslaunch / ps_automate
Invoke-Step -Name 'Create Pbpslaunch system environment variable' -Action {
    $exe = Join-Path $PbpsmonPath 'pbpslaunch.exe'
    $existing = [Environment]::GetEnvironmentVariable('Pbpslaunch', 'Machine')
    if ($existing) {
        Write-Host "    Pbpslaunch already set to '$existing' - leaving as-is, NOT overwriting."
    }
    else {
        [Environment]::SetEnvironmentVariable('Pbpslaunch', $exe, 'Machine')
        Write-Host "    Pbpslaunch was not set - created, pointing at $exe."
    }
    if (-not (Test-Path $exe)) {
        Write-Host "    NOTE: $exe does not exist on disk yet - install pbpsmon/ESA before relying on this variable." -ForegroundColor DarkYellow
    }
}

Invoke-Step -Name 'Create PSAutomate system environment variable' -Action {
    $exe = Join-Path $PbpsmonPath 'ps_automate.exe'
    $existing = [Environment]::GetEnvironmentVariable('PSAutomate', 'Machine')
    if ($existing) {
        Write-Host "    PSAutomate already set to '$existing' - leaving as-is, NOT overwriting."
    }
    else {
        [Environment]::SetEnvironmentVariable('PSAutomate', $exe, 'Machine')
        Write-Host "    PSAutomate was not set - created, pointing at $exe."
    }
    if (-not (Test-Path $exe)) {
        Write-Host "    NOTE: $exe does not exist on disk yet - install pbpsmon/ESA before relying on this variable." -ForegroundColor DarkYellow
    }
}

# 7. Apply policy
Invoke-Step -Name 'Run gpupdate /force' -Action {
    $p = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "gpupdate exited with code $($p.ExitCode)" }
}

# Summary
Write-Host "`n===================== SUMMARY =====================" -ForegroundColor Magenta
$script:results | Format-Table -AutoSize
$failed = $script:results | Where-Object { $_.Status -eq 'FAILED' }
if ($failed) {
    Write-Host "$($failed.Count) step(s) failed - review the detail above and rerun manually if needed." -ForegroundColor Yellow
}
else {
    Write-Host 'All automated steps completed successfully.' -ForegroundColor Green
}

if ($script:customValues.Count -gt 0) {
    Write-Host "`n===== EXISTING CUSTOM VALUES LEFT UNTOUCHED (non-destructive) =====" -ForegroundColor Cyan
    Write-Host "These registry values were already set to something other than the default/off state, so this script did not overwrite them. Review and change manually if they should match Password Safe's requirements." -ForegroundColor Cyan
    $script:customValues | Format-Table -AutoSize
}

Write-Host "`n================ MANUAL FOLLOW-UP (not automated) ================" -ForegroundColor Magenta
Write-Host @'
1. RDS Licensing: activate the RD Licensing server and add the correct CALs
   (per-user or per-device) for this deployment. Licensing setup is outside
   BeyondTrust support scope - consult Microsoft.

2. RDS Collection / RemoteApp publishing: this script auto-creates the
   'CollectionName' session collection and publishes any of pbpslaunch.exe,
   ps_automate.exe, pbpsmon.exe it finds under PbpsmonPath, with command-line
   parameters allowed. If any were skipped above, it's because the .exe
   wasn't found on disk yet (install pbpsmon/ESA first, then re-run).

3. If this server sits behind a network load balancer in front of multiple
   RD Session Hosts, confirm TCP port 3389 (or your custom RDP port) is
   allowed through all firewalls, and be aware the RD Connection Broker may
   redirect sessions to a different host than the load balancer chose.
   BeyondTrust recommends pre-deployed ESA in load-balanced environments,
   or pointing Password Safe directly at a specific RDS host IP instead of
   the load balancer VIP.

4. If this is a multi-node RDS cluster, re-run this script (or manually
   replicate its registry settings) on every node - Group Policy / registry
   settings applied here only affect this local server.
'@ -ForegroundColor White

if ($script:touchedKeys.Count -gt 0) {
    $undoFile = Join-Path $BackupPath "Undo-$stamp.ps1"
    $undoLines = New-Object System.Collections.Generic.List[string]
    $undoLines.Add('# Auto-generated rollback script - restores registry keys touched by')
    $undoLines.Add("# Configure-RDS-PasswordSafe.ps1 run on $stamp. Run elevated.")
    $undoLines.Add('$ErrorActionPreference = "Continue"')
    foreach ($k in $script:touchedKeys) {
        if ($k.ExistedBefore) {
            $undoLines.Add("Write-Host 'Restoring $($k.RegPath) from backup...'")
            $undoLines.Add("reg.exe import `"$($k.BackupFile)`"")
        }
        else {
            $undoLines.Add("Write-Host 'Removing $($k.RegPath) (did not exist before this run)...'")
            $undoLines.Add("Remove-Item -Path '$($k.Path)' -Recurse -Force -ErrorAction SilentlyContinue")
        }
    }
    Set-Content -Path $undoFile -Value $undoLines -Encoding UTF8
    Write-Host "`nRollback script written to: $undoFile" -ForegroundColor Cyan
    Write-Host "Registry backups stored in: $BackupPath" -ForegroundColor Cyan
}

Write-Host "`nDone: $(Get-Date)" -ForegroundColor Magenta
try { Stop-Transcript | Out-Null } catch {}

if (-not $NoSelfCleanup) {
    $selfPath = $PSCommandPath
    if ($selfPath -and (Test-Path $selfPath)) {
        Write-Host "Ephemeral run: deleting this script ($selfPath). Backups/rollback/transcript remain in $BackupPath." -ForegroundColor DarkGray
        # Detached one-liner so the file can delete itself after this process exits and releases the handle.
        Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-Command',
            "Start-Sleep -Seconds 2; Remove-Item -LiteralPath `"$selfPath`" -Force -ErrorAction SilentlyContinue"
        ) | Out-Null
    }
}
else {
    Write-Host "(Skipping self-cleanup per -NoSelfCleanup)" -ForegroundColor DarkGray
}
