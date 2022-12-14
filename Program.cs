using System.Diagnostics;
using System.Management.Automation;
using System.Reflection;
using System.Text;

namespace AutoBlockIP
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:驗證平台相容性", Justification = "<暫止>")]
    internal class Program
    {
        private static readonly int threshold = 3;
        private static readonly string[] whiteList = new string[] { "kuoann" };
        private static readonly string[] blackList = new string[] { "administrator", "guest" };
        private static readonly string firewallRuleName = "AutoBlockIP";
        private static StringBuilder logMessage = new StringBuilder();

        private static void Main(string[] args)
        {
            try
            {
                var ips = GetSuspiciousIps();

                if (ips.Count() > 0)
                {
                    var blockedIps = GetBlockedIps();
                    var mergedIps = blockedIps.Union(ips);

                    var newBlockIps = mergedIps.Except(blockedIps);
                    mergedIps = mergedIps.OrderBy(x => x).ToList();

                    if (newBlockIps.Count() > 0)
                    {
                        Log($" >>> Add [{string.Join("\n", newBlockIps)}]");
                        if (SetBlockedIpsIntoFirewall(mergedIps.ToArray()))
                        {
                            Log("SetBlockedIpsIntoFirewall...OK");
                        }
                        else
                        {
                            Log("SetBlockedIpsIntoFirewall...Fail");
                        }
                    }
                    else
                    {
                        Log($"\nNo Updated IP...{ips.Count() / blockedIps.Count()}");
                    }
                }
                else
                {
                    Log($"\nNo Suspicious IP");
                }

            }
            catch (Exception ex)
            {
                Log("\nError >>> " + ex.ToString());
                Write2EventLog(ex.ToString(), EventLogEntryType.Error);
            }
            finally
            {
#if DEBUG
                Console.ReadKey();
#else
                Write2EventLog(logMessage.ToString(), EventLogEntryType.Warning);
#endif
            }
        }

        private static void Log(string msg)
        {
            logMessage.AppendLine(msg);
            Console.WriteLine(msg);
        }

        private static void Write2EventLog(string message, EventLogEntryType entryType = EventLogEntryType.Information)
        {
            var assemblyVersion = Assembly.GetEntryAssembly()?.GetName().Version;

            using (var eventLog = new EventLog("Application"))
            {
                eventLog.Source = "WebApp";
                eventLog.WriteEntry($"[{firewallRuleName}][v{assemblyVersion}] {message}", entryType);
            }
        }

        /// <summary>
        /// Get suspicious ips from event log
        /// </summary>
        private static List<string> GetSuspiciousIps()
        {
            var suspiciousIps = new List<string>();
            var eventLog = new EventLog() { Log = "Security" };
            var entries =
                from EventLogEntry e in eventLog.Entries
                where e.InstanceId == 4625
                    && e.EntryType == EventLogEntryType.FailureAudit
                    && e.TimeGenerated > DateTime.Now.AddMinutes(-15)
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
                        var ip = d.ReplacementStrings[19];

                        if (ValidateIPv4(ip) && (!IsWhiteList(targetUserName)))
                        {
                            if (ips.ContainsKey(ip))
                            {
                                ips[ip]++;
                            }
                            else
                            {
                                ips.Add(ip, 1);
                            }
                        }
                    }
                }

                suspiciousIps = ips.Where(x => IsBlackList(x.Key) || x.Value > threshold)
                    .Select(x => x.Key).ToList();

                Log($"[{string.Join(",", suspiciousIps)}]");
            }
            else
            {
                Log($"Event 4625 Not Found in \"{eventLog.LogDisplayName}\"");
            }

            return suspiciousIps;
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
                        Write2EventLog($"Error: {err}", EventLogEntryType.Error);
                    }
                }
            }

            return blockedIps;
        }

        /// <summary>
        /// Set Blocked ips into firewall
        /// </summary>
        private static bool SetBlockedIpsIntoFirewall(string[] ips)
        {
            using (var ps = PowerShell.Create())
            {
                var sb = new StringBuilder();
                sb.Append("\"");
                sb.Append(string.Join("\",\"", ips));
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
                        Write2EventLog($"Error: {err}", EventLogEntryType.Error);
                    }

                    return false;
                }
                else
                {
                    Log($"{string.Join("\n", ips)}");
                }
            }
            return true;
        }
    }
}