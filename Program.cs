using System.Diagnostics;
using System.Management.Automation;
using System.Reflection;
using System.Text;
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
			Log.Logger = new LoggerConfiguration()
				.MinimumLevel.Debug()
				.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug, outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}]{Message}{NewLine}{Exception}")
				.WriteTo.Seq("http://localhost:1315", restrictedToMinimumLevel: LogEventLevel.Information, bufferBaseFilename: @"Logs\Seq-BlockIp")
				.CreateLogger();
			var assemblyVersion = Assembly.GetEntryAssembly()?.GetName().Version;
			try
			{
				Log.Warning("[AutoBlockIP][{assemblyVersion}] START", assemblyVersion);
				var ips = GetSuspiciousIps();
				if (ips.Any())
				{
					var blockedIps = GetBlockedIps();
					var unionBlockIps = blockedIps.Union(ips).OrderBy(x => x).ToList();
					var newBlockIps = unionBlockIps.Except(blockedIps);
					if (newBlockIps.Any())
					{
						Log.Warning($"[AutoBlockIP] Find New Block IP [{string.Join("\n", newBlockIps)}]");
						if (SetFirewall(unionBlockIps.ToArray()))
						{
							Log.Information($"[AutoBlockIP] SetFirewall...OK ({unionBlockIps.Count()})\n>> {string.Join(',', unionBlockIps)}");
						}
						else
						{
							Log.Error($"[AutoBlockIP] SetFirewall...Fail ({unionBlockIps.Count()})");
						}
					}
					else
					{
						Log.Debug("[AutoBlockIP] No New Block IP");
					}
				}
				else
				{
					Log.Warning($"\nUnextract IP");
				}
			}
			catch (Exception ex)
			{
				Log.Fatal($"[AutoBlockIP] Excep: {ex.Message}", ex);
			}
			finally
			{
				Log.Warning("[AutoBlockIP][{assemblyVersion}] END", assemblyVersion);
				Log.CloseAndFlush();
#if DEBUG
				Console.ReadKey();
#endif
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

				suspiciousIps = ips.Where(x => IsBlackList(x.Key) || x.Value > threshold)
					.Select(x => x.Key).ToList();

				Log.Warning($"[AutoBlockIP] Find suspicious IP {suspiciousIps.Count()}/{ips.Count}: {string.Join("\n", suspiciousIps)}");
			}
			else
			{
				Log.Warning($"[AutoBlockIP] Event 4625 Not Found in \"{eventLog.LogDisplayName}\"");
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