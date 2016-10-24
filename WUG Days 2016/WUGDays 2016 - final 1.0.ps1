#Requires -Version 5.1.14393
#Requires -RunAsAdministrator
# Created by Ben Armstrong aka VirtualPCGuy
# VirtualPCGuy's Twitter: https://twitter.com/virtualpcguy
# Original sources are available at: https://github.com/Microsoft/Virtualization-Documentation
# Modified for RTM version by Kamil Roman aka KamilRT
# Feel free to contact me with any questions and suggestions at IT@KamilRT.net
# Version 1.0 for Windows Server 2016 RTM

# Parameters
$workingDir = "E:\WUGDays"
$BaseVHDPath = "$($workingDir)\BaseVHDs"
$VMPath = "$($workingDir)\VMs"
$Organization = "KamilRT.net"
$Owner = "Kamil Roman"
$Timezone = "Central Europe Standard Time"
$adminPassword = "tajneheslo1@"
$domainName = "WUGDays.KamilRT.net"
$domainAdminPassword = "tajneheslo1@"
$virtualSwitchName = "WUG Days Demo switch"
$subnet = "10.0.0."
$ErrorActionPreference = "Continue"


$localCred = New-Object -TypeName System.Management.Automation.PSCredential `
             -ArgumentList "Administrator", (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
$domainCred = New-Object -TypeName System.Management.Automation.PSCredential `
              -ArgumentList "$($domainName)\Administrator", (ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force)
$ServerISO = "X:\14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US.iso"

$WindowsKey = ""

### Sysprep unattend XML
$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <RegisteredOrganization>Organization</RegisteredOrganization>
            <RegisteredOwner>Owner</RegisteredOwner>
            <TimeZone>TZ</TimeZone>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>password</Value>
                    <PlainText>True</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>cs-CZ</InputLocale>
            <SystemLocale>cs-CZ</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>cs-CZ</UserLocale>
        </component>
    </settings>
</unattend>
"@

function waitForPSDirect([string]$VMName, $cred){
   Logger $VMName "Waiting for PowerShell Direct (using $($cred.username))"
   while ((icm -VMName $VMName -Credential $cred {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}}

function rebootVM([string]$VMName){logger $VMName "Rebooting"; stop-vm $VMName; start-vm $VMName}

# Helper function to make sure that needed folders are present
function checkPath
{
    param
    (
        [string] $path
    )
    if (!(Test-Path $path)) 
    {
        $null = md $path;
    }
}

function Logger {
    param
    (
        [string]$systemName,
        [string]$message
    )

    # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
    Write-Host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline;
    Write-Host " - [" -ForegroundColor White -NoNewline;
    Write-Host $systemName -ForegroundColor Yellow -NoNewline;
    Write-Host "]::$($message)" -ForegroundColor White;
}

# Helper function for no error file cleanup
function cleanupFile
{
    param
    (
        [string] $file
    )
    
    if (Test-Path $file) 
    {
        Remove-Item $file -Recurse > $null;
    }
}

function GetUnattendChunk 
{
    param
    (
        [string] $pass, 
        [string] $component, 
        [xml] $unattend
    ); 
    
    # Helper function that returns one component chunk from the Unattend XML data structure
    return $Unattend.unattend.settings | ? pass -eq $pass `
        | select -ExpandProperty component `
        | ? name -eq $component;
}

function makeUnattendFile 
{
    param
    (
        [string] $filePath
    ); 

    # Composes unattend file and writes it to the specified filepath
     
    # Reload template - clone is necessary as PowerShell thinks this is a "complex" object
    $unattend = $unattendSource.Clone();
     
    # Customize unattend XML
    GetUnattendChunk "specialize" "Microsoft-Windows-Shell-Setup" $unattend | %{$_.RegisteredOrganization = $Organization};
    GetUnattendChunk "specialize" "Microsoft-Windows-Shell-Setup" $unattend | %{$_.RegisteredOwner = $Owner};
    GetUnattendChunk "specialize" "Microsoft-Windows-Shell-Setup" $unattend | %{$_.TimeZone = $Timezone};
    GetUnattendChunk "oobeSystem" "Microsoft-Windows-Shell-Setup" $unattend | %{$_.UserAccounts.AdministratorPassword.Value = $adminPassword};
    #GetUnattendChunk "specialize" "Microsoft-Windows-Shell-Setup" $unattend | %{$_.ProductKey = $WindowsKey};

    # Write it out to disk
    cleanupFile $filePath; $Unattend.Save($filePath);
}

# Build base VHDs

Function BuildBaseImages {

   Mount-DiskImage $ServerISO
   $DVDDriveLetter = (Get-DiskImage $ServerISO | Get-Volume).DriveLetter
   Copy-Item "$($DVDDriveLetter):\NanoServer\NanoServerImageGenerator\Convert-WindowsImage.ps1" "$($workingDir)\Convert-WindowsImage.ps1" -Force
   Import-Module "$($DVDDriveLetter):\NanoServer\NanoServerImageGenerator\NanoServerImageGenerator.psm1" -Force
   Import-Module "$workingDir\Convert-WindowsImage.ps1" -Force

   makeUnattendFile "$($BaseVHDPath)\unattend.xml"

    if (!(Test-Path "$($BaseVHDPath)\NanoBase.vhdx")) 
    {
    New-NanoServerImage -MediaPath "$($DVDDriveLetter):\" -BasePath $BaseVHDPath -TargetPath "$($BaseVHDPath)\NanoBase.vhdx" -Edition Datacenter -DeploymentType Guest -Compute -Clustering -AdministratorPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
    }

    if (!(Test-Path "$($BaseVHDPath)\VMServerBaseCore.vhdx")) 
    {
        Convert-WindowsImage -SourcePath "$($DVDDriveLetter):\sources\install.wim" -VHDPath "$($BaseVHDPath)\VMServerBaseCore.vhdx" `
                     -SizeBytes 40GB -VHDFormat VHDX -UnattendPath "$($BaseVHDPath)\unattend.xml" `
                     -Edition "ServerDataCenterCore" -DiskLayout UEFI -MergeFolder "$($workingDir)\cBase"
    }

    if (!(Test-Path "$($BaseVHDPath)\VMServerBase.vhdx")) 
    {
        Convert-WindowsImage -SourcePath "$($DVDDriveLetter):\sources\install.wim" -VHDPath "$($BaseVHDPath)\VMServerBase.vhdx" `
                     -SizeBytes 40GB -VHDFormat VHDX -UnattendPath "$($BaseVHDPath)\unattend.xml" `
                     -Edition "ServerDataCenter" -DiskLayout UEFI
    }

    cleanupFile "$($BaseVHDPath)\unattend.xml"
    Dismount-DiskImage $ServerISO 
}

function PrepVM {

    param
    (
        [string] $VMName, 
        [string] $GuestOSName, 
        [switch] $FullServer
    ); 

   Logger $VMName "Removing old VM"
   Get-VM $VMName -ErrorAction SilentlyContinue | Stop-VM -TurnOff -Force -Passthru | Remove-VM -Force
   cleanupFile "$($VMPath)\$($GuestOSName).vhdx"

   # Make new VM
   logger $VMName "Creating new differencing disk"
   if ($FullServer) { New-VHD -Path "$($VMPath)\$($GuestOSName).vhdx" -ParentPath "$($BaseVHDPath)\VMServerBase.vhdx" -Differencing | Out-Null}
   else {New-VHD -Path "$($VMPath)\$($GuestOSName).vhdx" -ParentPath "$($BaseVHDPath)\VMServerBaseCore.vhdx" -Differencing | Out-Null}
   Logger $VMName "Creating virtual machine"
   New-VM -Name $VMName -MemoryStartupBytes 900MB -SwitchName $VirtualSwitchName `
          -VHDPath "$($VMPath)\$($GuestOSName).vhdx" -Generation 2  | Set-VM -ProcessorCount 2
   Logger $VMName "Starting virtual machine"
   Start-VM $VMName
   }

function CreateVM {

    param
    (
        [string] $VMName, 
        [string] $GuestOSName, 
        [string] $IPNumber = "0"
    ); 

   waitForPSDirect $VMName -cred $localCred

   # Set IP address & name
   icm -VMName $VMName -Credential $localCred {
      param($IPNumber, $GuestOSName,  $VMName, $domainName, $subnet)
      if ($IPNumber -ne "0") {
         Write-Output "[$($VMName)]:: Setting IP Address to $($subnet)$($IPNumber)"
         New-NetIPAddress -IPAddress "$($subnet)$($IPNumber)" -InterfaceAlias "Ethernet" -PrefixLength 16 | Out-Null
         Write-Output "[$($VMName)]:: Setting DNS Address"
         Get-DnsClientServerAddress | %{Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses "$($subnet)1"}}
      Write-Output "[$($VMName)]:: Renaming OS to `"$($GuestOSName)`""
      Rename-Computer $GuestOSName
      Write-Output "[$($VMName)]:: Configuring WSMAN Trusted hosts"
      Set-Item WSMan:\localhost\Client\TrustedHosts "*.$($domainName)" -Force
      Set-Item WSMan:\localhost\client\trustedhosts "$($subnet)*" -force -Concatenate
      Enable-WSManCredSSP -Role Client -DelegateComputer "*.$($domainName)" -Force
      } -ArgumentList $IPNumber, $GuestOSName, $VMName, $domainName, $subnet

      # Reboot
      rebootVM $VMName; waitForPSDirect $VMName -cred $localCred

}

Logger "Host" "Getting started..."

checkpath $BaseVHDPath
checkpath $VMPath

BuildBaseImages

if ((Get-VMSwitch | ? name -eq $virtualSwitchName) -eq $null)
{
New-VMSwitch -Name $virtualSwitchName -SwitchType Private
}

PrepVM "Domain Controller 1" "DC1"
PrepVM "Domain Controller 2" "DC2"
PrepVM "DHCP Server" "DHCP"
PrepVM "Management Console" "Management" -FullServer
PrepVM "Storage Node 1" "S2DNode1"
PrepVM "Storage Node 2" "S2DNode2"
PrepVM "Storage Node 3" "S2DNode3"
PrepVM "Storage Node 4" "S2DNode4"

$vmName = "Domain Controller 1"
$GuestOSName = "DC1"
$IPNumber = "1"

CreateVM $vmName $GuestOSName $IPNumber
      icm -VMName $VMName -Credential $localCred {
         param($VMName, $domainName, $domainAdminPassword)
             Write-Output "[$($VMName)]:: Installing AD"
             Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | out-null
             $ProgressPreference = "SilentlyContinue"
             Write-Output "[$($VMName)]:: Enabling Active Directory and promoting to domain controller"
             Install-ADDSForest -DomainName $domainName -InstallDNS -NoDNSonNetwork -NoRebootOnCompletion `
                                -SafeModeAdministratorPassword (ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force) -confirm:$false
             $ProgressPreference = "Continue"
         } -ArgumentList $VMName, $domainName, $domainAdminPassword

      # Reboot
      Logger $vmName "AD installed"
      rebootVM $VMName; 


$vmName = "DHCP Server"
$GuestOSName = "DHCP"
$IPNumber = "3"

CreateVM $vmName $GuestOSName $IPNumber

      icm -VMName $VMName -Credential $localCred {
         param($VMName, $domainCred, $domainName)
         Write-Output "[$($VMName)]:: Installing DHCP"
         Install-WindowsFeature DHCP -IncludeManagementTools | out-null
         Write-Output "[$($VMName)]:: Joining domain as `"$($env:computername)`""
         while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}
         do {Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue} until ($?)
         } -ArgumentList $VMName, $domainCred, $domainName

               # Reboot
      rebootVM $VMName
      waitForPSDirect $VMName -cred $domainCred

      icm -VMName $VMName -Credential $domainCred {
         param($VMName, $domainName, $subnet, $IPNumber)

         Write-Output "[$($VMName)]:: Waiting for name resolution"

         while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}

         Write-Output "[$($VMName)]:: Configuring DHCP Server"    
         Set-DhcpServerv4Binding -BindingState $true -InterfaceAlias Ethernet
         Add-DhcpServerv4Scope -Name "IPv4 Network" -StartRange "$($subnet)10" -EndRange "$($subnet)200" -SubnetMask 255.255.0.0
         Set-DhcpServerv4OptionValue -OptionId 6 -value "$($subnet)1"
         Add-DhcpServerInDC -DnsName "$($env:computername).$($domainName)"
         foreach($i in 1..99) {
         $mac = "00-b5-5d-fe-f6-" + ($i % 100).ToString("00")
         $ip = $subnet + "1" + ($i % 100).ToString("00")
         $desc = "Nano " + $i.ToString()
         $scopeID = $subnet + "0"
         Add-DhcpServerv4Reservation -IPAddress $ip -ClientId $mac -Description $desc -ScopeId $scopeID}
                            } -ArgumentList $VMName, $domainName, $subnet, $IPNumber

      # Reboot
      rebootVM $VMName

$vmName = "Domain Controller 2"
$GuestOSName = "DC2"
$IPNumber = "2"

CreateVM $vmName $GuestOSName $IPNumber

      icm -VMName $VMName -Credential $localCred {
         param($VMName, $domainCred, $domainName)
         Write-Output "[$($VMName)]:: Installing AD"
         Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | out-null
         Write-Output "[$($VMName)]:: Joining domain as `"$($env:computername)`""
         while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}
         do {Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue} until ($?)
         } -ArgumentList $VMName, $domainCred, $domainName

               # Reboot
      rebootVM $VMName; waitForPSDirect $VMName -cred $domainCred

      icm -VMName $VMName -Credential $domainCred {
         param($VMName, $domainName, $domainAdminPassword)

             Write-Output "[$($VMName)]:: Waiting for name resolution"
             while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}
             Write-Output "[$($VMName)]:: Enabling Active Directory and promoting to domain controller"
             $ProgressPreference = "SilentlyContinue"
             Install-ADDSDomainController -DomainName $domainName -InstallDNS -NoRebootOnCompletion `
                                         -SafeModeAdministratorPassword (ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force) -confirm:$false 
             $ProgressPreference = "Continue"
         } -ArgumentList $VMName, $domainName, $domainAdminPassword

      # Reboot
      rebootVM $VMName

$vmName = "Domain Controller 1"
$GuestOSName = "DC1"
$IPNumber = "1"

waitForPSDirect $VMName -cred $domainCred

icm -VMName $VMName -Credential $domainCred {
         param($VMName, $password)

         Write-Output "[$($VMName)]:: Creating user account for Kamil"
         do {start-sleep 5; New-ADUser `
            -Name "Kamil" `
            -SamAccountName  "Kamil" `
            -DisplayName "Kamil" `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $false  `
            -Enabled $true -ea 0} until ($?)
            Add-ADGroupMember "Domain Admins" "Kamil"} -ArgumentList $VMName, $domainAdminPassword

$vmName = "Management Console"
$GuestOSName = "Management"

CreateVM $vmName $GuestOSName

      icm -VMName $VMName -Credential $localCred {
         param($VMName, $domainCred, $domainName)
         Write-Output "[$($VMName)]:: Management tools"
         Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools, RSAT-DNS-Server | out-null
         Install-WindowsFeature RSAT-AD-Tools -IncludeAllSubfeature | out-null
         Write-Output "[$($VMName)]:: Joining domain as `"$($env:computername)`""
         while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}
         do {Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue} until ($?)
         } -ArgumentList $VMName, $domainCred, $domainName

      # Reboot
      rebootVM $VMName

function BuildStorageNode {
param($VMName, $GuestOSName)

CreateVM $vmName $GuestOSName

   cleanupFile "$($VMPath)\$($GuestOSName) - Data 1.vhdx"
   cleanupFile "$($VMPath)\$($GuestOSName) - Data 2.vhdx"

   Add-VMNetworkAdapter -VMName $VMName -SwitchName $VirtualSwitchName
   New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -Dynamic -SizeBytes 100GB
   Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx"
   New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx" -Dynamic -SizeBytes 100GB
   Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx"

      icm -VMName $VMName -Credential $localCred {
         param($VMName, $domainCred, $domainName)
         Write-Output "[$($VMName)]:: Installing Clustering"
         Install-WindowsFeature -Name File-Services, Failover-Clustering -IncludeManagementTools | out-null
         Write-Output "[$($VMName)]:: Joining domain as `"$($env:computername)`""
         while (!(Test-Connection -Computername $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) {sleep -seconds 1}
         do {Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue} until ($?)
         Get-NetFirewallRule | Enable-NetFirewallRule
         } -ArgumentList $VMName, $domainCred, $domainName


      # Reboot
      rebootVM $VMName
}

BuildStorageNode "Storage Node 1" "S2DNode1"
BuildStorageNode "Storage Node 2" "S2DNode2"
BuildStorageNode "Storage Node 3" "S2DNode3"
BuildStorageNode "Storage Node 4" "S2DNode4"

waitForPSDirect "Storage Node 4" -cred $domainCred

Logger "S2D Cluster" "Creating S2D Cluster"

icm -VMName "Management Console" -Credential $domainCred {
param ($domainName)
do {New-Cluster -Name S2DCluster -Node S2DNode1,S2DNode2,S2DNode3,S2DNode4 -NoStorage -Verbose} until ($?)
Write-Output "[Management console]:: Waiting for new S2Dcluster to come up" 
while (!(Test-Connection -Computername "S2DCluster.$($domainName)" -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
      {Clear-DnsClientCache; sleep -seconds 2}
Write-Output "[Management console]:: Adding Scale-Out file server cluster role to S2Dcluster"
Add-ClusterScaleoutFileServerRole -Name S2DFileServer -Cluster "S2DCluster.$($domainName)"
} -ArgumentList $domainName

logger "Storage Node 1" "Enabling Cluster Storage Spaces Direct"
icm -VMName "Storage Node 1" -Credential $domainCred {
param ($domainName)
Enable-ClusterStorageSpacesDirect -SkipEligibilityChecks -Confirm:$false -Verbose
Write-Output "[Storage Node 1]:: Creating new Storage pool"
New-StoragePool -StorageSubSystemName "S2DCluster.$($domainName)" -FriendlyName "S2DPool" -WriteCacheSizeDefault 0 -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault Mirror -PhysicalDisk (Get-StorageSubSystem  -Name "S2DCluster.$($domainName)" | Get-PhysicalDisk) -Verbose -ErrorAction Continue
Write-Output "[Storage Node 1]:: Creating new volume on Storage pool"
New-Volume -StoragePoolFriendlyName "S2D on S2DCluster" -FriendlyName "S2DDisk" -PhysicalDiskRedundancy 2 -FileSystem CSVFS_REFS -Size 200GB -Verbose
Write-Output "[Storage Node 1]:: Switching off file integrity for CSV volume for better performance for test environment"
Set-FileIntegrity "C:\ClusterStorage\Volume1" -Enable $false

Write-Output "[Storage Node 1]:: Creating new shares at SOFS"
         MD C:\ClusterStorage\Volume1\VHDX
         New-SmbShare -Name VHDX -Path C:\ClusterStorage\Volume1\VHDX -FullAccess "$($domainName)\administrator", "$($domainName)\Kamil", "$($domainName)\Management$"
         Set-SmbPathAcl -ShareName VHDX

         MD C:\ClusterStorage\Volume1\ClusQuorum
         New-SmbShare -Name ClusQuorum -Path C:\ClusterStorage\Volume1\ClusQuorum -FullAccess "$($domainName)\administrator", "$($domainName)\Kamil", "$($domainName)\Management$"
         Set-SmbPathAcl -ShareName ClusQuorum

         MD C:\ClusterStorage\Volume1\ClusData
         New-SmbShare -Name ClusData -Path C:\ClusterStorage\Volume1\ClusData -FullAccess "$($domainName)\administrator", "$($domainName)\Kamil", "$($domainName)\Management$"
         Set-SmbPathAcl -ShareName ClusData

} -ArgumentList $domainName


function PrepComputeNode {
param($VMName, $GuestOSName)

   Logger $VMName "Removing old VM"
   Get-VM $VMName -ErrorAction SilentlyContinue | Stop-VM -TurnOff -Force -Passthru | Remove-VM -Force
   cleanupFile "$($VMPath)\$($GuestOSName).vhdx"

   copy "$($BaseVHDPath)\NanoBase.vhdx" "$($VMPath)\$($GuestOSName).vhdx"

   # Make new VM
   Logger $VMName "Creating virtual machine"
   New-VM -Name $VMName -MemoryStartupBytes 2400MB -SwitchName $VirtualSwitchName `
          -VHDPath "$($VMPath)\$($GuestOSName).vhdx" -Generation 2
   Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
   Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $true
   Add-VMNetworkAdapter -VMName $VMName -SwitchName $VirtualSwitchName
   Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing on
   Logger $VMName "Starting virtual machine"
   do {Start-VM $VMName} until ($?)
}

function BuildComputeNode {
param($VMName, $GuestOSName)

   waitForPSDirect $VMName $localCred
    
   Logger $VMName "Creating standard virtual switch"
   icm -VMName $VMName -Credential $localCred {
      param($GuestOSName)
      Enable-WSManCredSSP -Role server -Force
      New-VMSwitch -Name "Virtual Switch" -NetAdapterName "Ethernet" -AllowManagementOS $true
      djoin /requestodj /loadfile "\\10.0.0.1\c$\$($GuestOSName).txt" /windowspath c:\windows /localos
      del "\\10.0.0.1\c$\$($GuestOSName).txt"
      Get-NetFirewallRule | Enable-NetFirewallRule

      } -ArgumentList $GuestOSName
      
      # Reboot
      rebootVM $VMName; 
}


PrepComputeNode "Hyper-V Node 1" "HVNode1"
PrepComputeNode "Hyper-V Node 2" "HVNode2"
PrepComputeNode "Hyper-V Node 3" "HVNode3"
PrepComputeNode "Hyper-V Node 4" "HVNode4"
PrepComputeNode "Hyper-V Node 5" "HVNode5"
PrepComputeNode "Hyper-V Node 6" "HVNode6"
PrepComputeNode "Hyper-V Node 7" "HVNode7"
PrepComputeNode "Hyper-V Node 8" "HVNode8"



icm -VMName "Management Console" -Credential $domainCred {
                    param($domainName)
                    djoin.exe /provision /domain $domainName /machine "HVNode1" /savefile \\10.0.0.1\c$\HVNode1.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode2" /savefile \\10.0.0.1\c$\HVNode2.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode3" /savefile \\10.0.0.1\c$\HVNode3.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode4" /savefile \\10.0.0.1\c$\HVNode4.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode5" /savefile \\10.0.0.1\c$\HVNode5.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode6" /savefile \\10.0.0.1\c$\HVNode6.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode7" /savefile \\10.0.0.1\c$\HVNode7.txt
                    djoin.exe /provision /domain $domainName /machine "HVNode8" /savefile \\10.0.0.1\c$\HVNode8.txt} -ArgumentList $domainName


BuildComputeNode "Hyper-V Node 1" "HVNode1"
BuildComputeNode "Hyper-V Node 2" "HVNode2"
BuildComputeNode "Hyper-V Node 3" "HVNode3"
BuildComputeNode "Hyper-V Node 4" "HVNode4"
BuildComputeNode "Hyper-V Node 5" "HVNode5"
BuildComputeNode "Hyper-V Node 6" "HVNode6"
BuildComputeNode "Hyper-V Node 7" "HVNode7"
BuildComputeNode "Hyper-V Node 8" "HVNode8"


waitForPSDirect "Hyper-V Node $ClusterNodesCount" -cred $domainCred

Logger "HVCluster" "Creating HVCluster"

icm -VMName "Management Console" -Credential $domainCred {
param ($domainName)
do {New-Cluster -Name HVCluster -Node HVNode1,HVNode2,HVNode3,HVNode4,HVNode5,HVNode6,HVNode7,HVNode8 -NoStorage} until ($?)
while (!(Test-Connection -Computername "S2DCluster.$($domainName)" -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
      {Clear-DnsClientCache | Out-Null; sleep -seconds 1}
} -ArgumentList $domainName

Logger "S2DCluster" "Assigning access for HVCluster nodes at SOFS shares"

icm -VMName "Storage Node 1" -Credential $domainCred {
param ($domainName)
Get-SmbShareAccess VHDX | Grant-SmbShareAccess -AccountName "$($domainName)\HVNode1$","$($domainName)\HVNode2$","$($domainName)\HVNode3$", `
                                             "$($domainName)\HVNode4$","$($domainName)\HVNode5$","$($domainName)\HVNode6$", `
                                             "$($domainName)\HVNode7$","$($domainName)\HVNode8$","$($domainName)\HVCluster$" `
                                             -AccessRight Full -Confirm:$false

Get-SmbShareAccess ClusQuorum | Grant-SmbShareAccess -AccountName "$($domainName)\HVNode1$","$($domainName)\HVNode2$","$($domainName)\HVNode3$", `
                                             "$($domainName)\HVNode4$","$($domainName)\HVNode5$","$($domainName)\HVNode6$", `
                                             "$($domainName)\HVNode7$","$($domainName)\HVNode8$","$($domainName)\HVCluster$" `
                                             -AccessRight Full -Confirm:$false

Get-SmbShareAccess ClusData | Grant-SmbShareAccess -AccountName "$($domainName)\HVNode1$","$($domainName)\HVNode2$","$($domainName)\HVNode3$", `
                                             "$($domainName)\HVNode4$","$($domainName)\HVNode5$","$($domainName)\HVNode6$", `
                                             "$($domainName)\HVNode7$","$($domainName)\HVNode8$","$($domainName)\HVCluster$" `
                                             -AccessRight Full -Confirm:$false

Set-SmbPathAcl -ShareName VHDX
Set-SmbPathAcl -ShareName ClusQuorum
Set-SmbPathAcl -ShareName ClusData
} -ArgumentList $domainName

Logger "HVCluster" "Setting Witness"

icm -VMName "Management Console" -Credential $domainCred {
param ($domainName)
Set-ClusterQuorum -Cluster HVCluster -NodeAndFileShareMajority "\\S2DFileServer.$($domainName)\ClusQuorum"
} -ArgumentList $domainName

Logger "HVCluster" "Preparing image file for cluster VMs"

cleanupFile "$($VMPath)\NanoHost - Diff.vhdx"
New-VHD -Path "$($VMPath)\NanoHost - Diff.vhdx" -ParentPath "$($BaseVHDPath)\NanoBase.vhdx" -Differencing | Out-Null

Add-VMHardDiskDrive -VMName "Hyper-V Node 1" -Path "$($VMPath)\NanoHost - Diff.vhdx"


icm -VMName "Hyper-V Node 1" -Credential $domainCred {while ((get-disk).Count -ne 2) {start-sleep 1}
                                                      New-VHD -path "\\s2dfileserver\vhdx\NanoBase.VHDX" -Dynamic -SourceDisk 1}



Logger "HVCluster" "Waiting for cluster to come up before adding VMs"

waitForPSDirect "Hyper-V Node 8" -cred $domainCred

Logger "HVCluster" "Creating VMs"



foreach ($i in 1..8) 
{

    icm -VMName "Hyper-V Node $($i)" -Credential $domainCred {
        param ($k, $domainName, $localCred)

        Set-VMHost -VirtualHardDiskPath "\\S2DFileServer.$($domainName)\VHDX" `
                    -VirtualMachinePath "\\S2DFileServer.$($domainName)\VHDX" 
        $j = $k - 1
            do {New-VHD -Path "\\s2dfileserver\vhdx\Nano Host $($j).VHDX" -ParentPath "\\s2dfileserver\vhdx\NanoBase.VHDX" -Differencing -ea 0| Out-Null} until ($?)
            do {New-VM -Name "Nano Host $($j)" -MemoryStartupBytes 768MB -SwitchName "Virtual Switch" -VHDPath "\\s2dfileserver\vhdx\Nano Host $($j).VHDX" -Generation 2 -ea 0} until ($?)
            Set-VM -Name "Nano Host $($j)" -ProcessorCount 2
            Get-VMNetworkAdapter -VMName "Nano Host $($j)" | Set-VMNetworkAdapter -MacAddressSpoofing on
            Start-VM "Nano Host $($j)"
                   
            New-VHD -Path "\\s2dfileserver\vhdx\Nano Host $($k).VHDX" -ParentPath "\\s2dfileserver\vhdx\NanoBase.VHDX" -Differencing | Out-Null
            do {New-VM -Name "Nano Host $($k)" -MemoryStartupBytes 768MB -SwitchName "Virtual Switch" -VHDPath "\\s2dfileserver\vhdx\Nano Host $($k).VHDX" -Generation 2 -ea 0} until ($?)
            Set-VM -Name "Nano Host $($k)" -ProcessorCount 2
            Get-VMNetworkAdapter -VMName "Nano Host $($k)" | Set-VMNetworkAdapter -MacAddressSpoofing on
            Start-VM "Nano Host $($k)"
                   
            while ((icm -VMName "Nano Host $($k)" -Credential $localCred {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}

        } -ArgumentList ($i*2), $domainName, $localCred


    Logger "HVCluster" "VMs for cluster Node $($i) created"


        icm -VMName "Management Console" -Credential $domainCred {
            param ($k, $HyperVNodeNumber) 
            $j = $k - 1
            Add-VMToCluster -Cluster HVCluster -VMName "Nano Host $($j)" -Verbose
            Add-VMToCluster -Cluster HVCluster -VMName "Nano Host $($k)" -Verbose
        } -ArgumentList ($i*2), $i

    Logger "HVCluster" "VMs for cluster Node $($i) added to cluster"
}


Logger "Done" "Done!"
