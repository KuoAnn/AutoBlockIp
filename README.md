# AutoBlockIp
This Batch Will Auto block suspicious IP from windows event log.

:warning: You need to perform this as a system administrator

## Batch Logic
1. Get suspicious IP from windows security auditing event log (eventId=`4625`)
![image](https://user-images.githubusercontent.com/18626429/196039188-5c080dee-867c-4d37-89ca-0f578927be76.png)
  * Nearly 30 minutes 
  * Exclude retry {n} times
  * Exclude white list
2. Configure the firewall through the power shell
3. Log windows event

## Powershell script
``` sh
# 將特定 IP 加入到防火牆的規則內
function Add-IpAddressToFirewallRule{
    param (
        [ValidateNotNullOrEmpty()]
        [string]$RuleName,
        [ValidateNotNullOrEmpty()]
        [string]$Ip
    )

$all_ips = [string[]](Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallAddressFilter).RemoteAddress

if (!$all_ips.Contains($ip)){
    $all_ips += $ip
    Set-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $all_ips
    }

}

# 將特定 IP 從防火牆的規則內移出
function Remove-IpAddressToFirewallRule{
    param (
        [ValidateNotNullOrEmpty()]
        [string]$RuleName,
        [ValidateNotNullOrEmpty()]
        [string]$Ip
    )

$all_ips = [string[]](Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallAddressFilter).RemoteAddress

if ($all_ips.Contains($ip)){
    $all_ips = $all_ips | ? {$_ -ne $ip} 
    Set-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $all_ips
    }

}

#Add-IpAddressToFirewallRule -RuleName "Hacker" -Ip "139.205.71.104"

#Remove-IpAddressToFirewallRule -RuleName "Hacer" -Ip "161.162.163.164"
```

## Ref
> https://dotblogs.com.tw/jamesfu/2022/09/13/PowerShell_Block_IP_Address
