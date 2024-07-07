using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutoBlockIP
{
    public class Log
    {
        private static string _prefix { get; set; } = "";

        public static void SetPrefix(string prefix)
        {
            _prefix = prefix;
        }

        public static void Verbose(string message)
        {
            Serilog.Log.Verbose($"{_prefix}{message}", "");
        }

        public static void Verbose(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Verbose($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Debug(string message)
        {
            Serilog.Log.Debug($"{_prefix}{message}", "");
        }

        public static void Debug(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Debug($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Information(string message)
        {
            Serilog.Log.Information($"{_prefix}{message}");
        }

        public static void Information(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Information($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Warning(string message)
        {
            Serilog.Log.Warning($"{_prefix}{message}");
        }

        public static void Warning(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Warning($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Error(string message)
        {
            Serilog.Log.Error($"❗ {_prefix}{message}");
        }

        public static void Error(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Error($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Fatal(string message)
        {
            Serilog.Log.Fatal($"‼️ {_prefix}{message}");
        }

        public static void Fatal(Exception ex)
        {
            Serilog.Log.Fatal(ex, $"‼️ {_prefix}{ex.Message}");
        }

        public static void Fatal(Exception ex, string message)
        {
            Serilog.Log.Fatal(ex, $"‼️ {_prefix}{message}");
        }

        public static void Fatal(string messageTemplate, params object[] propertyValues)
        {
            Serilog.Log.Fatal($"{_prefix}{messageTemplate}", propertyValues);
        }

        public static void Fatal<T>(Exception? exception, string messageTemplate, T propertyValue)
        {
            Serilog.Log.Fatal(exception, messageTemplate, propertyValue);
        }
    }
}
