using System.Diagnostics;

namespace AutoBlockIP
{
    internal class Program
    {
        // Allowed number of try
        private static readonly int threshold = 3;
        private static readonly string[] whiteList = new string[] { "kuoann" };

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:驗證平台相容性", Justification = "<暫止>")]
        static void Main(string[] args)
        {
            try
            {
                var eventLog = new EventLog() { Log = "Security" };
                var entries =
                    from EventLogEntry e in eventLog.Entries
                    where e.InstanceId == 4625
                        && e.EntryType == EventLogEntryType.FailureAudit
                    //&& e.TimeGenerated > DateTime.Now.AddMinutes(-30)
                    select new
                    {
                        e.ReplacementStrings,
                    };

                if (entries.Count() > 0)
                {
                    var events = entries.ToList();
                    var suspiciousIps = new Dictionary<string, int>();

                    foreach (var d in events)
                    {
                        if (d.ReplacementStrings.Length >= 19)
                        {
                            var targetUserName = d.ReplacementStrings[5];
                            var ip = d.ReplacementStrings[19];

                            if (ValidateIPv4(ip) && !isWhiteList(targetUserName))
                            {
                                if (suspiciousIps.ContainsKey(ip))
                                {
                                    suspiciousIps[ip]++;
                                }
                                else
                                {
                                    suspiciousIps.Add(ip, 1);
                                }
                            }
                        }
                    }

                    var blockIps = suspiciousIps.Where(x => x.Value > threshold);
                    foreach (var d in blockIps)
                    {
                        Console.WriteLine($"{d.Key}...{d.Value}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            finally
            {
                Console.WriteLine("done");
            }

            Console.ReadKey();
        }

        private static bool ValidateIPv4(string ipString)
        {
            if (String.IsNullOrWhiteSpace(ipString))
            {
                return false;
            }

            string[] splitValues = ipString.Split('.');
            if (splitValues.Length != 4)
            {
                return false;
            }

            byte tempForParsing;

            return splitValues.All(r => byte.TryParse(r, out tempForParsing));
        }

        private static bool isWhiteList(string targetUserName) =>
            !string.IsNullOrWhiteSpace(targetUserName)
            && whiteList.Contains(targetUserName.Trim().ToLower());

        /// <summary>
        /// <code>
        /// #Add-IpAddressToFirewallRule -RuleName "Hacker" -Ip "139.205.71.104"
        /// #Remove-IpAddressToFirewallRule -RuleName "Hacer" -Ip "161.162.163.164"
        /// </code>
        /// </summary>
        /// <returns></returns>
        private static string getPowershellFunctionScripts() => @"
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
";

    }
}