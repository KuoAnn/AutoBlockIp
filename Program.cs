using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace AutoBlockIP
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:驗證平台相容性", Justification = "<暫止>")]
    internal class Program
    {
        private static readonly int threshold = 3;
        private static readonly string[] whiteList = new string[] { "kuoann" };
        private static readonly string firewallRuleName = "Block IP";

        static void Main(string[] args)
        {
            try
            {
                var suspiciousIps = GetSuspiciousIps();
                var blockedIps = GetBlockedIps();
                var mergedIps = blockedIps.Union(suspiciousIps);

                mergedIps = mergedIps.OrderBy(x => x).ToList();

                SetBlockedIpsIntoFirewall(mergedIps.ToArray());
            }
            catch (Exception ex)
            {
                Write2EventLog(ex.ToString(), EventLogEntryType.Error);
                Console.WriteLine(ex);
            }
            finally
            {
                Console.WriteLine("Done");
            }

            Console.ReadKey();
        }

        private static void Write2EventLog(string message, EventLogEntryType entryType = EventLogEntryType.Information)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "Application";
                eventLog.WriteEntry($"[BlockIP] {message}", entryType);
            }
        }

        /// <summary>
        /// Get suspicious ips from event log
        /// </summary>
        /// <returns></returns>
        private static List<string> GetSuspiciousIps()
        {
            Console.WriteLine("GetSuspiciousIps...");
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

                foreach (string result in suspiciousIps)
                {
                    Console.WriteLine(result);
                }

                Write2EventLog($"GetSuspiciousIps:\n{string.Join("\n", suspiciousIps)}", EventLogEntryType.Warning);
            }
            else
            {
                Write2EventLog($"No datas in event log \"{eventLog.LogDisplayName}\"", EventLogEntryType.Warning);
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
            Console.WriteLine("GetBlockedIps...");
            var blockedIps = new List<string>();

            using (var ps = PowerShell.Create())
            {
                ps.AddScript("Set-ExecutionPolicy RemoteSigned");
                ps.AddScript("Import-Module NetSecurity");
                ps.AddScript($"[string[]](Get-NetFirewallRule -DisplayName '{firewallRuleName}' | Get-NetFirewallAddressFilter).RemoteAddress");

                foreach (string ip in ps.Invoke<string>())
                {
                    Console.WriteLine(ip);
                    blockedIps.Add(ip);
                }

                Write2EventLog($"GetBlockedIps:\n{string.Join("\n", blockedIps)}", EventLogEntryType.Warning);

                PSDataCollection<ErrorRecord> errors = ps.Streams.Error;
                if (errors != null && errors.Count > 0)
                {
                    foreach (ErrorRecord err in errors)
                    {
                        Console.WriteLine($"Error: {err}");
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
            Console.WriteLine("SetBlockedIpsIntoFirewall...");
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
                        Console.WriteLine($"Error: {err}");
                        Write2EventLog($"Error: {err}", EventLogEntryType.Error);
                    }

                    return false;
                }
                else
                {
                    Write2EventLog($"SetBlockedIpsIntoFirewall\n{string.Join("\n", ips)}", EventLogEntryType.Warning);
                }
            }
            return true;
        }

    }
}