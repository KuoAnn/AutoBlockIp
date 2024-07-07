using System.Diagnostics;
using System.Management.Automation;
using System.Reflection;
using System.Text;
using Serilog;
using AutoBlockIP;
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
            Serilog.Log.Logger = new Serilog.LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug, outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}]{Message}{NewLine}{Exception}")
                .WriteTo.Seq("http://localhost:1315", restrictedToMinimumLevel: LogEventLevel.Information, bufferBaseFilename: @"Logs\Seq-BlockIp")
                .CreateLogger();

            try
            {
                Log.SetPrefix("");
                Log.Warning("Start 🟢");
                var ips = GetAttackIps();

                if (ips.Any())
                {
                    var blockedIps = GetBlockedIps();
                    var unionBlockIps = blockedIps.Union(ips).OrderBy(x => x).ToList();
                    var newBlockIps = unionBlockIps.Except(blockedIps);
                    if (newBlockIps.Any())
                    {
                        Log.Warning("Find New Block IP [{newBlockIps}]", string.Join("\n", newBlockIps));
                        if (SetFirewall(unionBlockIps.ToArray()))
                        {
                            Log.Information($"SetFirewall...OK ({unionBlockIps.Count()})\n>> {string.Join(',', unionBlockIps)}");
                        }
                        else
                        {
                            Log.Error($"SetFirewall...Fail ({unionBlockIps.Count()})");
                        }
                    }
                    else
                    {
                        Log.Debug("No New Block IP");
                    }
                }
                else
                {
                    Log.Warning($"\nUnextract IP");
                }
            }
            catch (Exception ex)
            {
                Log.Fatal($"Excep: {ex.Message}", ex);
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
        private static List<string> GetAttackIps()
        {
            var attackIps = new List<string>();
            var eventLog = new EventLog() { Log = "Security" };
            var entries =
                from EventLogEntry e in eventLog.Entries
                where e.InstanceId == 4625
                    && e.EntryType == EventLogEntryType.FailureAudit
                    && e.TimeGenerated > DateTime.Now.AddMinutes(-trackMinutes)
                select new
                {
                    e.ReplacementStrings,
                };

            if (entries.Count() > 0)
            {
                var events = entries.ToList();
                var ips = new Dictionary<string, int>();

                foreach (var d in events)
                {
                    if (d.ReplacementStrings.Length >= 19)
                    {
                        var targetUserName = d.ReplacementStrings[5];
                        var attackIp = d.ReplacementStrings[19];

                        if (ValidateIPv4(attackIp))
                        {
                            if (IsWhiteList(targetUserName)) continue;

                            if (ips.ContainsKey(attackIp))
                            {
                                ips[attackIp]++;
                            }
                            else if (IsBlackList(targetUserName))
                            {
                                // BlackList is evil! -> Force to over threshold
                                Log.Warning("[{targetUserName}]({attackIp}) is in BlackList", targetUserName, attackIp);
                                ips.Add(attackIp, 666);
                            }
                            else
                            {
                                ips.Add(attackIp, 1);
                            }
                        }
                    }
                }

                attackIps = ips.Where(x => x.Value > threshold).Select(x => x.Key).ToList();

                Log.Warning("Find attackIPs {attackIpCount}/{ipCount}: [{attackIps}]", attackIps.Count(), ips.Count, string.Join(",", attackIps));
            }
            else
            {
                Log.Warning($"Event 4625 Not Found in \"{eventLog.LogDisplayName}\"");
            }

            return attackIps;
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

        private static bool IsWhiteList(string targetUserName) =>
            !string.IsNullOrWhiteSpace(targetUserName)
            && whiteList.Contains(targetUserName.Trim().ToLower());

        private static bool IsBlackList(string targetUserName) =>
            !string.IsNullOrWhiteSpace(targetUserName)
            && blackList.Contains(targetUserName.Trim().ToLower());

        /// <summary>
        /// Get Blocked ips from firewall
        /// </summary>
        private static List<string> GetBlockedIps()
        {
            var blockedIps = new List<string>();

            using (var ps = PowerShell.Create())
            {
                ps.AddScript("Set-ExecutionPolicy RemoteSigned");
                ps.AddScript("Import-Module NetSecurity");
                ps.AddScript($"[string[]](Get-NetFirewallRule -DisplayName '{firewallRuleName}' | Get-NetFirewallAddressFilter).RemoteAddress");

                foreach (string ip in ps.Invoke<string>())
                {
                    blockedIps.Add(ip);
                }

                PSDataCollection<ErrorRecord> errors = ps.Streams.Error;
                if (errors != null && errors.Count > 0)
                {
                    foreach (ErrorRecord err in errors)
                    {
                        Log.Error($"Error: {err}");
                    }
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
                var sb = new StringBuilder();
                sb.Append("\"");
                sb.Append(string.Join("\",\"", blockIps));
                sb.Append("\"");

                ps.AddScript("Set-ExecutionPolicy RemoteSigned");
                ps.AddScript("Import-Module NetSecurity");
                ps.AddScript($"Set-NetFirewallRule -DisplayName '{firewallRuleName}' -Direction Inbound -Action Block -RemoteAddress @({sb})");

                ps.Invoke();

                PSDataCollection<ErrorRecord> errors = ps.Streams.Error;
                if (errors != null && errors.Count > 0)
                {
                    foreach (ErrorRecord err in errors)
                    {
                        Log.Error($"Error: {err}");
                    }

                    return false;
                }
            }
            return true;
        }
    }
}