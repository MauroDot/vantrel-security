using System.Security.Principal;
using Vantrel.Security.Service;

namespace Vantrel.Security.OfflineUpdateTool;

/// <summary>Fixed tool entry. The internal constructor exists only for deterministic tests.</summary>
public sealed class OfflineUpdateToolEntry
{
    private readonly Func<bool> _isElevated;
    private readonly Func<CancellationToken, Task<OfflineUpdateInvocationResult>> _apply;

    public OfflineUpdateToolEntry() : this(IsAdministrator, token => new OfflineUpdateAdministrator().ApplyFixedStagedCandidateAsync(token)) { }
    internal OfflineUpdateToolEntry(Func<bool> isElevated, Func<CancellationToken, Task<OfflineUpdateInvocationResult>> apply)
    {
        _isElevated = isElevated ?? throw new ArgumentNullException(nameof(isElevated));
        _apply = apply ?? throw new ArgumentNullException(nameof(apply));
    }

    public async Task<int> RunAsync(string[] args, TextWriter error, TextWriter output, CancellationToken token)
    {
        if (args.Length != 0) { await error.WriteLineAsync("This fixed operation accepts no arguments."); return 1; }
        if (!_isElevated()) { await error.WriteLineAsync("Administrator elevation is required."); return 1; }
        try
        {
            var result = await _apply(token);
            await output.WriteLineAsync($"Fixed offline update transaction ended in {result}.");
            return result == OfflineUpdateInvocationResult.Completed ? 0 : 2;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { await error.WriteLineAsync("Fixed offline update transaction did not complete."); return 3; }
    }

    private static bool IsAdministrator() => OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
}
