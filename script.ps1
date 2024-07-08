# The script is divided into four parts; each part must be enabled separately, otherwise some settings may take effect
# Only after rebooting the computer, and if you enable rebooting the computer, the script process will stop.

# First part of the script
# Change computer name
$NewComputerName = "ws1"
Rename-Computer -NewName $NewComputerName -Force -Restart


# Second part
# First look at the Ethernet Bridge configuration
$AdapterBridge = "Ethernet"
Get-NetAdapter -Name $AdapterBridge
Get-NetIPAddress -InterfaceAlias $AdapterBridge

# First preview of Ethernet Internal configuration before setup
$AdapterInternal = "Ethernet 2"
Get-NetAdapter -Name $AdapterInternal
Get-NetIPAddress -InterfaceAlias $AdapterInternal

# Obtain IP address and subnet for Ethernet 2
$InterfaceIndex = (Get-NetAdapter -Name "Ethernet 2").InterfaceIndex
$IPaddress = "192.168.100.1"
$SubnetMask = "255.255.255.248"

# Disabling DHCP
Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled

# Setting a static IP address and subnet
New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPaddress $IPaddress -PrefixLength 29 

# Second View of Ethernet Bridge Configuration
$AdapterBridge = "Ethernet"
Get-NetAdapter -Name $AdapterBridge
Get-NetIPAddress -InterfaceAlias $AdapterBridge

# Second viewing of Ethernet Internal configuration after setup
$AdapterInternal = "Ethernet 2"
Get-NetAdapter -Name $AdapterInternal
Get-NetIPAddress -InterfaceAlias $AdapterInternal

# Install DHCP and DNS
Install-WindowsFeature -Name DNS -IncludeManagementTools
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Configuring DHCP Settings
$Subnet = "192.168.100.0"
$SubnetMask = "255.255.255.248"
$StartRange = "192.168.100.2"
$EndRange = "192.168.100.5"
$Router = "192.168.100.1"
$DNSServer = "8.8.8.8", "8.8.4.4"

Add-DhcpServerV4Scope -Name "MyScope" -StartRange $StartRange -EndRange $EndRange -SubnetMask $SubnetMask -State Active
Set-DhcpServerv4OptionValue -OptionID 3 -Value $Router
Set-DhcpServerv4OptionValue -OptionID 6 -Value $DNSServer
Set-DhcpServerv4OptionValue -OptionID 51 -Value 86400

# Activating DHCP Services
Start-Service DHCPServer 
Set-Service DHCPServer -StartupType 'Automatic'

# Name server  DNS
$DnsServer = "ws1"

# Name zone DNS
$ForwardZoneName = "mysite.potak.loc"

# Connect to server DNS
$Session = New-PSSession -ComputerName $DnsServer
Enter-PSSession -Session $Session

# Creating a Forward View Zone
Add-DnsServerPrimaryZone -Name $ForwardZoneName

# Ending a connection session
Exit-PSSession
Remove-PSSession $Session

# Name server DNS
$DnsServer = "ws1"

# IP address and subnet to create a reverse lookup zone
$ReverseZoneNetwork = "192.168.100.0/29"

# Connect to server DNS
$Session = New-PSSession -ComputerName $DnsServer
Enter-PSSession -Session $Session

# Creating a Reverse Lookup Zone
Add-DnsServerPrimaryZone -NetworkID $ReverseZoneNetwork -ZoneFile "192.168.100.rev"

# Ending a connection session
Exit-PSSession
Remove-PSSession $Session

# Name server DNS
$DnsServer = "ws1"

# Name server DNS
$ForwardZoneName = "mysite.potak.loc"

# Associative array for storing records
$RecordMappings = @{
    "www" = "192.168.100.1"
    "web" = "192.168.100.1"
    "ws1" = "192.168.100.1"
}

# Connect to server DNS
$Session = New-PSSession -ComputerName $DnsServer
Enter-PSSession -Session $Session

# Adding Records to the Forward View Zone
foreach ($RecordName in $RecordMappings.Keys) {
    $IPAddress = $RecordMappings[$RecordName]
    Add-DnsServerResourceRecordA -ZoneName $ForwardZoneName -Name $RecordName -IPv4Address $IPAddress
}

# Ending a connection session
Exit-PSSession
Remove-PSSession $Session

# Enable Routing
Install-WindowsFeature -Name Routing -IncludeManagementTools

# Configure NAT (Network Address Translation) for Internet access
Install-Module -Name NatGateway -Force -AllowClobber
Import-Module NatGateway

# Get the interfaces (adapt as needed)
$InternalInterface = "Ethernet"
$ExternalInterface = "Ethernet 2"

# Create NAT rule
New-NatPortMapping -NatName "InternetNat" -Protocol TCP -ExternalIPAddress 0.0.0.0 -InternalIPAddress 0.0.0.0 -InternalPort 0 -ExternalPort 0 -InterfaceAlias $ExternalInterface

# Enable NAT on the external interface
Set-NetNatTransitionConfiguration -NATName "InternetNat" -IPv4AddressPortPool @( @{ StartPort = 1024; EndPort = 65535 } ) -InternalIPInterfaceAddressPrefix $InternalInterface

# Enable IP forwarding
Set-NetIPInterface -InterfaceAlias $InternalInterface -Forwarding Enabled

# Configure DNS (use your preferred DNS server addresses)
$DNSAddresses = "8.8.8.8", "8.8.4.4"
Set-DnsClientServerAddress -InterfaceAlias $InternalInterface -ServerAddresses $DNSAddresses

# Set static IP for external interface (replace with your actual external IP configuration)
$ExternalIP = "192.168.100.1"
$ExternalSubnet = "255.255.255.0"
$ExternalGateway = "192.168.100.1"

New-NetIPAddress -InterfaceAlias $ExternalInterface -IPAddress $ExternalIP -PrefixLength 24 -DefaultGateway $ExternalGateway
Set-DnsClientServerAddress -InterfaceAlias $ExternalInterface -ServerAddresses $DNSAddresses

# Restart network interfaces
Restart-NetAdapter -InterfaceAlias $InternalInterface, $ExternalInterface -Confirm:$false

# Install ISS
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Install PHP
Invoke-WebRequest -Uri https://aka.ms/webpi-5.1.1776 -OutFile WebPI.msi
Start-Process -Wait -FilePath .\WebPI.msi
& "$env:ProgramFiles\Microsoft\Web Platform Installer\WebpiCmd.exe" /Install /Products:PHP

# Install Mysql Server
Install-Module -Name MySQL -Force -AllowClobber
Install-Module -Name PowerShellGet -Force -AllowClobber
Import-Module MySQL
Install-MySQL -InstallationType Server -InstallAsService

# MySQL Server Installation Parameters
$mysqlInstallerPath = "C:\path\to\mysql-installer-community-8.0.26.0.msi"  
$mysqlRootPassword = "123456"

# MySQL connection parameters
$mysqlHost = "localhost"
$mysqlUser = "root"  
$mysqlPassword = "123456"  
# MySQL commands
$mysqlCommands = @(
    "CREATE DATABASE wordpress;",
    "CREATE USER 'wordpressuser'@'localhost' IDENTIFIED BY 'your_password';",
    "GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpressuser'@'localhost';",
    "FLUSH PRIVILEGES;",
    "EXIT;"
)

# Command construction in Mysql
# mysql: This is a command line tool for MySQL.
# -h $mysqlHost: Specifies the host of the MySQL server.
# -u $mysqlUser: Specifies the MySQL user.
# -p$mysqlPassword: Specifies the MySQL user password. The -p option without a space is used to indicate that the password follows immediately.
# -e: Allows you to execute a command or SQL statement directly from the command line.
# "$(($mysqlCommands -join ' ') -replace "n", '')"`: This part is a little tricky:
# $mysqlCommands -join ' ': Joins an array of MySQL commands into one space-separated string.
# -replace "n", '': Removes newlines ("n") from the string. This is useful for creating a one-line command.

$mysqlCommandString = "mysql -h $mysqlHost -u $mysqlUser -p$mysqlPassword -e `"$(($mysqlCommands -join ' ') -replace "`n", '')`""

# Run MySQL commands
Invoke-Expression -Command $mysqlCommandString

# Installing and exporting wordpress
Invoke-WebRequest -Uri "https://wordpress.org/latest.zip" -OutFile "C:\inetpub\wwwroot\wordpress.zip"
Expand-Archive -Path "C:\inetpub\wwwroot\wordpress.zip" -DestinationPath "C:\inetpub\wwwroot\"

# ISS configuration
New-IISSite -Name "WordPress" -PhysicalPath "C:\inetpub\wwwroot\wordpress" -BindingInformation "*:80:" -ApplicationPool "DefaultAppPool"


# Third part of the script
# Installing the Active Directory Domain itself
Install-WindowsFeature -Name Ad-Domain-Services -IncludeManagementTools 

# Setting a password for the Active Directory Domain administrator
$adminPassword = ConvertTo-SecureString -AsPlainText "R18663sdfghjklzxcvbnm" -Force

# Importing the ADDSDeployment module
Import-Module ADDSDeployment

# The command creates a new domain name, also a domain version for Windows Server 2019, sets DNS and sets a password for the administrator
Install-ADDSForest -DomainName "potak.loc" -InstallDns -SafeModeAdministratorPassword $adminPassword 

# Restarting the computer
Restart-Computer -Force


# Fourth part
# Import the Active Directory module
Import-Module ActiveDirectory

# Set the credentials for the new user
$Username = "NewUser"
$Password = ConvertTo-SecureString "Password123" -AsPlainText -Force

# Specify the user details
$FirstName = "darja"
$LastName = "darja"
$DisplayName = "$FirstName $LastName"
$UserPrincipalName = "$Username@potak.loc"
$EmailAddress = "$Username@potak.loc"

# Create the new user
New-ADUser -SamAccountName $Username -UserPrincipalName $UserPrincipalName -GivenName $FirstName -Surname $LastName -DisplayName $DisplayName -EmailAddress $EmailAddress -Enabled $true -AccountPassword $Password -PassThru

Write-Host "User $Username created successfully."
