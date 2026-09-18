using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Vantrel.Security.Core;
using Vantrel.Security.Infrastructure;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class WindowsSecurityCenterHealthTests
{
    [TestMethod]
    public void Adapter_queries_only_antivirus_and_maps_each_documented_state()
    {
        var expected = new[]
        {
            WindowsAntivirusHealth.Good,
            WindowsAntivirusHealth.NotMonitored,
            WindowsAntivirusHealth.Poor,
            WindowsAntivirusHealth.Snoozed
        };
        for (var raw = 0; raw < expected.Length; raw++)
        {
            var value = raw;
            var source = new WindowsSecurityCenterHealthSource(provider =>
            {
                Assert.AreEqual(0x4u, provider);
                return (0, value);
            }, NullLogger<WindowsSecurityCenterHealthSource>.Instance);
            Assert.AreEqual(expected[raw], source.CollectAntivirus());
        }
    }

    [TestMethod]
    public void Firewall_query_uses_only_fixed_flag_and_maps_each_documented_state()
    {
        var expected = new[]
        {
            WindowsFirewallHealth.Good,
            WindowsFirewallHealth.NotMonitored,
            WindowsFirewallHealth.Poor,
            WindowsFirewallHealth.Snoozed
        };
        for (var raw = 0; raw < expected.Length; raw++)
        {
            var value = raw;
            var source = new WindowsSecurityCenterHealthSource(provider =>
            {
                Assert.AreEqual(0x1u, provider);
                return (0, value);
            }, NullLogger<WindowsSecurityCenterHealthSource>.Instance);
            Assert.AreEqual(expected[raw], source.CollectFirewall());
        }
    }

    [TestMethod]
    public void Firewall_s_false_failures_and_unknown_values_are_unavailable()
    {
        var logger = new WarningLogger();
        var stopped = new WindowsSecurityCenterHealthSource(provider =>
        {
            Assert.AreEqual(0x1u, provider);
            return (1, 2);
        }, logger);
        Assert.IsNull(stopped.CollectFirewall(), "S_FALSE with POOR is not an observed Poor state.");
        Assert.IsNull(stopped.CollectFirewall());
        Assert.AreEqual(1, logger.Messages.Count, "Matching failures should be rate-limited.");
        StringAssert.Contains(logger.Messages[0], "firewall health unavailable: WscUnavailable");
        StringAssert.Contains(logger.Messages[0], "HRESULT=00000001");

        var denied = new WindowsSecurityCenterHealthSource(_ =>
            (unchecked((int)0x80070005), 0), logger);
        Assert.IsNull(denied.CollectFirewall());
        var unexpected = new WindowsSecurityCenterHealthSource(_ => (0, 99), logger);
        Assert.IsNull(unexpected.CollectFirewall());
        Assert.AreEqual(3, logger.Messages.Count);
        StringAssert.Contains(logger.Messages[2], "UnexpectedHealthValue");
    }

    [TestMethod]
    public void Firewall_exception_is_unavailable_without_logging_exception_message()
    {
        var logger = new WarningLogger();
        var source = new WindowsSecurityCenterHealthSource(
            _ => throw new InvalidOperationException("private machine detail"), logger);
        Assert.IsNull(source.CollectFirewall());
        Assert.AreEqual(1, logger.Messages.Count);
        StringAssert.Contains(logger.Messages[0], "System.InvalidOperationException");
        Assert.IsFalse(logger.Messages[0].Contains("private machine detail", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Alternating_category_failures_remain_rate_limited()
    {
        var logger = new WarningLogger();
        var source = new WindowsSecurityCenterHealthSource(_ => (1, 2), logger);
        Assert.IsNull(source.CollectAntivirus());
        Assert.IsNull(source.CollectFirewall());
        Assert.IsNull(source.CollectAntivirus());
        Assert.IsNull(source.CollectFirewall());
        Assert.AreEqual(2, logger.Messages.Count);
    }

    [TestMethod]
    public void S_false_api_failure_and_unknown_values_are_unavailable()
    {
        var logger = new WarningLogger();
        var stopped = new WindowsSecurityCenterHealthSource(_ => (1, 2), logger);
        Assert.IsNull(stopped.CollectAntivirus(), "S_FALSE with POOR is not an observed POOR state.");
        Assert.IsNull(stopped.CollectAntivirus());
        Assert.AreEqual(1, logger.Messages.Count, "Matching failures should be rate-limited.");
        StringAssert.Contains(logger.Messages[0], "WscUnavailable");
        StringAssert.Contains(logger.Messages[0], "HRESULT=00000001");

        var denied = new WindowsSecurityCenterHealthSource(_ =>
            (unchecked((int)0x80070005), 0), logger);
        Assert.IsNull(denied.CollectAntivirus());
        var unexpected = new WindowsSecurityCenterHealthSource(_ => (0, 99), logger);
        Assert.IsNull(unexpected.CollectAntivirus());
        Assert.AreEqual(3, logger.Messages.Count);
        StringAssert.Contains(logger.Messages[2], "UnexpectedHealthValue");
    }

    [TestMethod]
    public void Exception_is_unavailable_without_logging_exception_message()
    {
        var logger = new WarningLogger();
        var source = new WindowsSecurityCenterHealthSource(
            _ => throw new InvalidOperationException("private machine detail"), logger);
        Assert.IsNull(source.CollectAntivirus());
        Assert.AreEqual(1, logger.Messages.Count);
        StringAssert.Contains(logger.Messages[0], "System.InvalidOperationException");
        Assert.IsFalse(logger.Messages[0].Contains("private machine detail", StringComparison.Ordinal));
    }

    private sealed class WarningLogger : ILogger<WindowsSecurityCenterHealthSource>
    {
        public List<string> Messages { get; } = [];
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) Messages.Add(formatter(state, exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
