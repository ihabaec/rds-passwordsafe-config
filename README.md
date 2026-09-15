# RDS Password Safe Configuration Script

PowerShell script that configures a Windows Server (RD Connection Broker + RD Session Host + RD Licensing, typically all on one box) for BeyondTrust Password Safe RemoteApp / Application sessions, following the BeyondTrust KB checklist.

## What it does

1. Installs RDS roles (Connection Broker, Session Host, Licensing) if not already present
2. Creates the actual RDS session deployment (`New-RDSessionDeployment`) if one doesn't exist yet — installing the Windows features alone does not do this, and Server Manager's RDS Overview page will show "no deployment" until it's created
3. Creates a `PasswordSafe-<name>` RD Session Collection and publishes `pbpslaunch.exe`, `ps_automate.exe`, and `pbpsmon.exe` as RemoteApps (command-line parameters allowed) for whichever of those actually exist under `-PbpsmonPath`
4. Enables multiple concurrent sessions per user
5. Sets session time limits (disconnected / idle / active)
6. Sets the RemoteApp session logoff delay
7. Sets the max simultaneous RDS connection count
8. Creates the `Pbpslaunch` and `PSAutomate` machine environment variables used by Password Safe to launch RemoteApp sessions
9. Runs `gpupdate /force` to apply the changes
10. Prints manual follow-up items that are still out of scope for automation (RDS licensing/CALs activation, load balancer/firewall notes)

## Safety features

- Pre-flight checks (Server SKU, pending reboot, free disk space) before any change is made
- Registry keys are backed up to `.reg` files before being modified, with an auto-generated rollback script
- `-WhatIf` / `-Confirm` support to preview changes first
- Full transcript logging
- Self-deletes after running (ephemeral) unless `-NoSelfCleanup` is passed

## Usage

```powershell
# Dry run - see what would change without applying anything
.\Configure-RDS-PasswordSafe.ps1 -WhatIf

# Apply with defaults
.\Configure-RDS-PasswordSafe.ps1

# Apply and keep the script file afterward
.\Configure-RDS-PasswordSafe.ps1 -NoSelfCleanup
```

Must be run as Administrator. See the script's comment-based help (`Get-Help .\Configure-RDS-PasswordSafe.ps1 -Full`) for all parameters.

## Notes

Setup and licensing of Microsoft RDS itself is outside BeyondTrust support scope — consult Microsoft's RDS documentation for licensing requirements.
