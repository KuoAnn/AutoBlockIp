using System.Diagnostics;
using System.Management.Automation;
using Serilog;
using Serilog.Events;

namespace AutoBlockIP
{
    internal class Program
    {
        private static readonly int threshold = 3;
        private static readonly string[] whiteList = new string[] { "kuoann" };
        private static readonly string[] blackList = new string[] { "administrator", "admin", "guest" };
        private static readonly string firewallRuleName = "AutoBlockIP";

        private static readonly int trackMinutes = 10;

        private static void Main(string[] args)
        {
            Serilog.Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}]{Message}{NewLine}{Exception}")
                .WriteTo.Seq("http://localhost:1315", restrictedToMinimumLevel: LogEventLevel.Information, bufferBaseFilename: @"Logs\Seq-BlockIp")
                .CreateLogger();

            try
            {
                Log.SetPrefix("[BlockIP] ");
                Log.Warning("Start 🟢");

                var blockIps = GetBlockIps();
                if (blockIps.Count > 0)
                {
                    var blockedIps = GetBlockedIps();
                    var finalBlockIps = new HashSet<string>(blockedIps);
                    finalBlockIps.UnionWith(blockIps);
                    var newBlockIps = finalBlockIps.Except(blockedIps).ToList();

                    if (newBlockIps.Count > 0)
                    {
                        Log.Warning("Block {newBlockIps}", string.Join("\n", newBlockIps));
                        if (SetFirewall(finalBlockIps.ToArray()))
                        {
                            Log.Information($"SetFirewall...OK ({finalBlockIps.Count})\n>> {string.Join(',', finalBlockIps)}");
                        }
                        else
                        {
                            Log.Error($"SetFirewall...Fail ({finalBlockIps.Count})");
                        }
                    }
                    else
                    {
                        Log.Information("No New BlockIP");
                    }
                }
                else
                {
                    Log.Information("Can't Get BlockIP");
                }
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, ex.Message);
            }
            finally
            {
                Log.Warning("Stop 🔴");
                Serilog.Log.CloseAndFlush();
#if DEBUG
                Console.ReadKey();
#endif
            }
        }

        /// <summary>
        /// Get suspicious ips from event log
        /// </summary>
        private static List<string> GetBlockIps()
        {
            var attackIps = new List<string>();
            var eventLog = new EventLog("Security");
            var ips = new Dictionary<string, int>();

            foreach (EventLogEntry e in eventLog.Entries)
            {
                if (e.InstanceId == 4625 && e.EntryType == EventLogEntryType.FailureAudit && e.TimeGenerated > DateTime.Now.AddMinutes(-trackMinutes))
                {
                    if (e.ReplacementStrings.Length >= 19)
                    {
                        var targetUserName = e.ReplacementStrings[5];
                        var attackIp = e.ReplacementStrings[19];

                        if (ValidateIPv4(attackIp))
                        {
                            if (IsWhiteList(targetUserName))
                            {
                                continue;
                            }

                            // 更新 IP 攻擊次數
                            if (ips.ContainsKey(attackIp))
                            {
                                ips[attackIp]++;
                            }
                            else if (IsBlackList(targetUserName))
                            {
                                // 黑名單 -> 無視閾值
                                Log.Warning("Force Block {attackIp} [{targetUserName}]", attackIp, targetUserName);
                                ips.Add(attackIp, 666);
                            }
                            else
                            {
                                ips.Add(attackIp, 1);
                            }
                        }
                    }
                }
            }

            // 過濾超過閾值的攻擊 IP
            return ips.Where(x => x.Value > threshold).Select(x => x.Key).ToList();
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

        private static bool IsWhiteList(string userName) =>
            !string.IsNullOrWhiteSpace(userName) && whiteList.Contains(userName.Trim().ToLower());

        private static bool IsBlackList(string userName) =>
            string.IsNullOrWhiteSpace(userName) ||
            (!string.IsNullOrWhiteSpace(userName) && blackList.Contains(userName.Trim().ToLower()));

        /// <summary>
        /// Get Blocked ips from firewall
        /// </summary>
        private static List<string> GetBlockedIps()
        {
            var blockedIps = new List<string>();

            using (var ps = PowerShell.Create())
            {
                // 將 Set-ExecutionPolicy 的範圍設置為 Process 並強制執行，避免影響全域設定。
                ps.AddScript("Set-ExecutionPolicy RemoteSigned -Scope Process -Force");
                ps.AddScript("Import-Module NetSecurity");
                ps.AddScript($"[string[]](Get-NetFirewallRule -DisplayName '{firewallRuleName}' | Get-NetFirewallAddressFilter).RemoteAddress");

                var results = ps.Invoke<string>();
                if (ps.HadErrors)
                {
                    foreach (var error in ps.Streams.Error)
                    {
                        Log.Error($"Error: {error}");
                    }
                }
                else
                {
                    blockedIps.AddRange(results);
                }
            }

            return blockedIps;
        }

        /// <summary>
        /// Set Blocked ips into firewall
        /// </summary>
        private static bool SetFirewall(string[] blockIps)
        {
            using (var ps = PowerShell.Create())
            {
                var remoteAddresses = string.Join(",", blockIps.Select(ip => $"\"{ip}\""));
                var script = $@"
                    Set-ExecutionPolicy RemoteSigned -Scope Process -Force;
                    Import-Module NetSecurity;
                    Set-NetFirewallRule -DisplayName '{firewallRuleName}' -Direction Inbound -Action Block -RemoteAddress @({remoteAddresses})
                ";

                ps.AddScript(script);
                ps.Invoke();

                if (ps.HadErrors)
                {
                    foreach (var error in ps.Streams.Error)
                    {
                        Log.Error($"Error: {error}");
                    }
                    return false;
                }
            }
            return true;
        }
    }
}