using System.Diagnostics;
using System.Management.Automation;
using System.Text;
using Microsoft.Extensions.Logging;

namespace AutoBlockIP
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:驗證平台相容性", Justification = "<暫止>")]
    internal class Program
    {
        private static readonly int threshold = 3;
        private static readonly string[] whiteList = new string[] { "kuoann" };
        private static readonly string firewallRuleName = "AutoBlockIP";
        private static StringBuilder logMessage = new StringBuilder();

        private static void Main(string[] args)
        {
            try
            {
                var suspiciousIps = GetSuspiciousIps();
                var blockedIps = GetBlockedIps();
                var mergedIps = blockedIps.Union(suspiciousIps);

                var newBlockIps = mergedIps.Except(blockedIps);
                mergedIps = mergedIps.OrderBy(x => x).ToList();

                if (newBlockIps.Count() > 0)
                {
                    Log($"NewBlockIps=\n{string.Join("\n", newBlockIps)}");
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
                    Log($"\nNo Updated IP...{suspiciousIps.Count() / blockedIps.Count()}");
                }
            }
            catch (Exception ex)
            {
                Log("Error >>> " + ex.ToString());
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
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "Application";
                eventLog.WriteEntry($"[{firewallRuleName}] {message}", entryType);
            }
        }

        /// <summary>
        /// Get suspicious ips from event log
        /// </summary>
        /// <returns></returns>
        private static List<string> GetSuspiciousIps()
        {
            Log("Get Suspicious Ip >>>\n");
            var suspiciousIps = new List<string>();
            var eventLog = new EventLog() { Log = "Security" };
            var entries =
                from EventLogEntry e in eventLog.Entries
                where e.InstanceId == 4625
                    && e.EntryType == EventLogEntryType.FailureAudit
                    && e.TimeGenerated > DateTime.Now.AddMinutes(-30)
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

                        if (ValidateIPv4(ip) && !IsWhiteList(targetUserName))
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

                suspiciousIps = ips.Where(x => x.Value > threshold).Select(x => x.Key).ToList();

                Log($"{string.Join(",", suspiciousIps)}");
            }
            else
            {
                Log($"No datas in event log \"{eventLog.LogDisplayName}\"");
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

        /// <summary>
        /// Get Blocked ips from firewall
        /// </summary>
        /// <returns></returns>
        private static List<string> GetBlockedIps()
        {
            Log("Get Blocked Ip >>>\n");
            var blockedIps = new List<string>();

            using (var ps = PowerShell.Create())
            {
                ps.AddScript("Set-ExecutionPolicy RemoteSigned");
                ps.AddScript("Import-Module NetSecurity");
                ps.AddScript($"[string[]](Get-NetFirewallRule -DisplayName '{firewallRuleName}' | Get-NetFirewallAddressFilter).RemoteAddress");

                foreach (string ip in ps.Invoke<string>())
                {
                    Log(ip);
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
        /// <returns></returns>
        private static bool SetBlockedIpsIntoFirewall(string[] ips)
        {
            Log($"Set {ips.Length} Blocked IP into Firewall >>>\n");
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
                    Program.Log($"{string.Join("\n", ips)}");
                }
            }
            return true;
        }
    }
}