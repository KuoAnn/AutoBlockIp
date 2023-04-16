using System.Diagnostics;
using System.Management.Automation;
using System.Reflection;
using System.Text;
using Serilog.Events;
using Serilog;

namespace AutoBlockIP
{
	internal class Program
	{
		private static readonly int threshold = 3;
		private static readonly string[] whiteList = new string[] { "kuoann" };
		private static readonly string[] blackList = new string[] { "administrator", "guest" };
		private static readonly string firewallRuleName = "AutoBlockIP";
		private static StringBuilder logMessage = new StringBuilder();

		private static void Main(string[] args)
		{
			Log.Logger = new LoggerConfiguration()
				.MinimumLevel.Debug()
				.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug,
					outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}]{Message}{NewLine}{Exception}")
				.WriteTo.Seq("http://localhost:1315",
					restrictedToMinimumLevel: LogEventLevel.Information,
					bufferBaseFilename: @"C:\Logs\Seq")
				.CreateLogger();

			try
			{
				var ips = GetSuspiciousIps();
				if (ips.Count() > 0)
				{
					var blockedIps = GetBlockedIps();
					var unionBlockIps = blockedIps.Union(ips);

					var newBlockIps = unionBlockIps.Except(blockedIps);
					unionBlockIps = unionBlockIps.OrderBy(x => x).ToList();

					if (newBlockIps.Count() > 0)
					{
						AppendLog($" >> Add [{string.Join("\n", newBlockIps)}]");
						if (SetFirewall(unionBlockIps.ToArray()))
						{
							Log.Information($"SetFirewall...OK ({unionBlockIps.Count()})");
						}
						else
						{
							Log.Error($"SetFirewall...Fail ({unionBlockIps.Count()})");
						}
					}
				}
				else
				{
					AppendLog($"\nUnextract IP");
				}
			}
			catch (Exception ex)
			{
				AppendLog("\nError >> " + ex.ToString());
				Log.Fatal($"[AutoBlockIP] Excep: {ex.Message}", ex);
			}
			finally
			{
				if (!string.IsNullOrEmpty(logMessage.ToString().Trim()))
				{
					Log.Warning(logMessage.ToString());
				}
				else
				{
					Log.Debug("[AutoBlockIP] Done");
				}
#if DEBUG
				Console.ReadKey();
#endif
			}
		}

		private static void AppendLog(string msg)
		{
			logMessage.AppendLine(msg);
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
					&& e.TimeGenerated > DateTime.Now.AddMinutes(-10)
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

				AppendLog($"[{string.Join(",", suspiciousIps)}]");
			}
			else
			{
				AppendLog($"Event 4625 Not Found in \"{eventLog.LogDisplayName}\"");
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
						Log.Error($"[AutoBlockIP] Error: {err}");
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
						Log.Error($"[AutoBlockIP] Error: {err}");
					}

					return false;
				}
			}
			return true;
		}
	}
}