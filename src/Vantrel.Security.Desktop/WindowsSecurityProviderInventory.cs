using System.Collections.Immutable;
using System.IO;
using System.Runtime.InteropServices;

namespace Vantrel.Security.Desktop;

internal enum WindowsSecurityProviderCategory { Antivirus, Firewall }
internal enum WindowsSecurityProviderProductState { On, Off, Snoozed, Expired, Unknown }
internal enum WindowsSecurityProviderCategoryState { Current, Empty, Partial, Incomplete, Unavailable }

internal sealed record WindowsSecurityProviderEntry(
    WindowsSecurityProviderCategory Category,
    string DisplayName,
    WindowsSecurityProviderProductState State);

internal sealed record WindowsSecurityProviderCategorySnapshot(
    WindowsSecurityProviderCategory Category,
    WindowsSecurityProviderCategoryState State,
    ImmutableArray<WindowsSecurityProviderEntry> Entries);

internal sealed record WindowsSecurityProviderInventorySnapshot(
    DateTimeOffset CollectedAtUtc,
    WindowsSecurityProviderCategorySnapshot Antivirus,
    WindowsSecurityProviderCategorySnapshot Firewall);

internal interface IWindowsSecurityProviderInventorySource
{
    WindowsSecurityProviderInventorySnapshot Collect();
}

internal sealed class WindowsSecurityProviderInventorySource : IWindowsSecurityProviderInventorySource
{
    internal const int MaximumProvidersPerCategory = 32;
    private readonly IWindowsSecurityProviderInventoryNativeReader _native;
    private readonly Func<DateTimeOffset> _clock;

    internal WindowsSecurityProviderInventorySource(IWindowsSecurityProviderInventoryNativeReader? native = null,
        Func<DateTimeOffset>? clock = null)
    {
        _native = native ?? new WindowsSecurityProviderInventoryNativeReader();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public WindowsSecurityProviderInventorySnapshot Collect() => new(
        _clock(),
        Validate(WindowsSecurityProviderCategory.Antivirus, ReadCategory(WindowsSecurityProviderCategory.Antivirus)),
        Validate(WindowsSecurityProviderCategory.Firewall, ReadCategory(WindowsSecurityProviderCategory.Firewall)));

    private WindowsSecurityProviderNativeCategoryResult ReadCategory(WindowsSecurityProviderCategory category)
    {
        try { return _native.Read(category); }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            return WindowsSecurityProviderNativeCategoryResult.Unavailable();
        }
    }

    private static WindowsSecurityProviderCategorySnapshot Validate(WindowsSecurityProviderCategory category,
        WindowsSecurityProviderNativeCategoryResult result)
    {
        if (!result.Available)
            return new(category, WindowsSecurityProviderCategoryState.Unavailable, []);

        var entries = ImmutableArray.CreateBuilder<WindowsSecurityProviderEntry>();
        var partial = result.Partial;
        foreach (var product in result.Products)
        {
            if (entries.Count == MaximumProvidersPerCategory)
            {
                partial = true;
                break;
            }
            if (!TryValidateName(product.DisplayName, out var name))
            {
                partial = true;
                continue;
            }
            var state = MapState(product.RawState, out var knownState);
            if (!knownState) partial = true;
            entries.Add(new WindowsSecurityProviderEntry(category, name, state));
        }

        var categoryState = result.Incomplete ? WindowsSecurityProviderCategoryState.Incomplete :
            partial ? WindowsSecurityProviderCategoryState.Partial :
            entries.Count == 0 ? WindowsSecurityProviderCategoryState.Empty : WindowsSecurityProviderCategoryState.Current;
        return new(category, categoryState, entries.ToImmutable());
    }

    private static bool TryValidateName(string? value, out string name)
    {
        name = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 160 || value.Any(char.IsControl) ||
            Path.IsPathFullyQualified(value) || value.StartsWith("\\\\", StringComparison.Ordinal)) return false;
        name = value;
        return true;
    }

    private static WindowsSecurityProviderProductState MapState(int value, out bool known) => value switch
    {
        0 => Set(WindowsSecurityProviderProductState.On, out known),
        1 => Set(WindowsSecurityProviderProductState.Off, out known),
        2 => Set(WindowsSecurityProviderProductState.Snoozed, out known),
        3 => Set(WindowsSecurityProviderProductState.Expired, out known),
        _ => Set(WindowsSecurityProviderProductState.Unknown, out known)
    };

    private static WindowsSecurityProviderProductState Set(WindowsSecurityProviderProductState state, out bool known)
    {
        known = state != WindowsSecurityProviderProductState.Unknown;
        return state;
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal sealed class ProtectionProviderInventorySession
{
    private readonly object _sync = new();
    private long _generation;
    private WindowsSecurityProviderInventorySnapshot? _snapshot;
    internal WindowsSecurityProviderInventorySnapshot? Snapshot
    {
        get { lock (_sync) return _snapshot; }
    }

    internal async Task<WindowsSecurityProviderInventorySnapshot?> OpenAsync(IWindowsSecurityProviderInventorySource source)
    {
        long generation;
        lock (_sync)
        {
            generation = ++_generation;
            _snapshot = null;
        }

        WindowsSecurityProviderInventorySnapshot snapshot;
        try
        {
            snapshot = await Task.Run(source.Collect).ConfigureAwait(false);
        }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            snapshot = UnavailableSnapshot();
        }

        lock (_sync)
        {
            if (generation != _generation) return null;
            _snapshot = snapshot;
            return snapshot;
        }
    }

    internal bool IsCurrent(WindowsSecurityProviderInventorySnapshot snapshot)
    {
        lock (_sync) return ReferenceEquals(_snapshot, snapshot);
    }

    internal void Clear()
    {
        lock (_sync)
        {
            ++_generation;
            _snapshot = null;
        }
    }

    private static WindowsSecurityProviderInventorySnapshot UnavailableSnapshot() => new(DateTimeOffset.UtcNow,
        new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Unavailable, []),
        new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Unavailable, []));

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal sealed record WindowsSecurityProviderNativeProduct(string? DisplayName, int RawState);
internal sealed record WindowsSecurityProviderNativeCategoryResult(
    bool Available,
    bool Partial,
    bool Incomplete,
    IReadOnlyList<WindowsSecurityProviderNativeProduct> Products)
{
    internal static WindowsSecurityProviderNativeCategoryResult Unavailable() => new(false, false, false, []);
}

internal interface IWindowsSecurityProviderInventoryNativeReader
{
    WindowsSecurityProviderNativeCategoryResult Read(WindowsSecurityProviderCategory category);
}

internal interface IWindowsSecurityProviderComFactory
{
    IWindowsSecurityProviderComList Create();
}

internal interface IWindowsSecurityProviderComList : IDisposable
{
    bool TryInitialize(WindowsSecurityProviderCategory category);
    bool TryGetCount(out int count);
    bool TryGetProduct(int index, out IWindowsSecurityProviderComProduct? product);
}

internal interface IWindowsSecurityProviderComProduct : IDisposable
{
    bool TryGetDisplayName(out string? name);
    bool TryGetState(out int state);
}

internal sealed class WindowsSecurityProviderInventoryNativeReader : IWindowsSecurityProviderInventoryNativeReader
{
    private readonly IWindowsSecurityProviderComFactory _factory;
    private readonly Func<bool> _isSupported;

    internal WindowsSecurityProviderInventoryNativeReader(IWindowsSecurityProviderComFactory? factory = null,
        Func<bool>? isSupported = null)
    {
        _factory = factory ?? new WindowsSecurityProviderComFactory();
        _isSupported = isSupported ?? (() => OperatingSystem.IsWindowsVersionAtLeast(6, 2));
    }

    public WindowsSecurityProviderNativeCategoryResult Read(WindowsSecurityProviderCategory category)
    {
        if (!_isSupported())
            return WindowsSecurityProviderNativeCategoryResult.Unavailable();
        try
        {
            using var list = _factory.Create();
            if (!list.TryInitialize(category) || !list.TryGetCount(out var count) || count < 0)
                return WindowsSecurityProviderNativeCategoryResult.Unavailable();

            var entries = new List<WindowsSecurityProviderNativeProduct>();
            var partial = false;
            var capped = count > WindowsSecurityProviderInventorySource.MaximumProvidersPerCategory;
            var limit = Math.Min(count, WindowsSecurityProviderInventorySource.MaximumProvidersPerCategory);
            for (var index = 0; index < limit; index++)
            {
                IWindowsSecurityProviderComProduct? product = null;
                try
                {
                    if (!list.TryGetProduct(index, out product) || product is null ||
                        !product.TryGetDisplayName(out var name) || !product.TryGetState(out var state))
                    {
                        partial = true;
                        continue;
                    }
                    entries.Add(new WindowsSecurityProviderNativeProduct(name, state));
                }
        catch (Exception error) when (IsRecoverableFailure(error)) { partial = true; }
                finally { product?.Dispose(); }
            }
            return new WindowsSecurityProviderNativeCategoryResult(true, partial, capped, entries);
        }
        catch (Exception error) when (IsRecoverableFailure(error))
        {
            return WindowsSecurityProviderNativeCategoryResult.Unavailable();
        }
    }

    private static bool IsRecoverableFailure(Exception error) => error is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;
}

internal sealed class WindowsSecurityProviderComFactory : IWindowsSecurityProviderComFactory
{
    public IWindowsSecurityProviderComList Create() => new WindowsSecurityProviderComList(
        (IWscProductListNative)new WscProductListComClass());
}

internal delegate int WindowsSecurityProviderGetItem(uint index, out object? product);

internal sealed class WindowsSecurityProviderComList : IWindowsSecurityProviderComList
{
    private IWscProductListNative? _native;
    private readonly WindowsSecurityProviderGetItem _getItem;
    private readonly Action<object> _release;

    internal WindowsSecurityProviderComList(IWscProductListNative native)
    {
        _native = native;
        _getItem = GetItem;
        _release = ReleaseNativeReference;
    }

    internal WindowsSecurityProviderComList(WindowsSecurityProviderGetItem getItem, Action<object> release)
    {
        _getItem = getItem;
        _release = release;
    }

    public bool TryInitialize(WindowsSecurityProviderCategory category) =>
        _native is not null && _native.Initialize(category == WindowsSecurityProviderCategory.Antivirus ? 0x4u : 0x1u) == 0;

    public bool TryGetCount(out int count)
    {
        count = 0;
        return _native is not null && _native.GetCount(out count) == 0;
    }

    public bool TryGetProduct(int index, out IWindowsSecurityProviderComProduct? product)
    {
        product = null;
        var result = _getItem(checked((uint)index), out var native);
        if (result != 0 || native is not IWscProductNative productNative)
        {
            if (native is not null) _release(native);
            return false;
        }

        try
        {
            product = new WindowsSecurityProviderComProduct(productNative);
            return true;
        }
        catch
        {
            _release(productNative);
            throw;
        }
    }

    public void Dispose()
    {
        var native = Interlocked.Exchange(ref _native, null);
        if (native is not null) _release(native);
    }

    private int GetItem(uint index, out object? product)
    {
        product = null;
        if (_native is null) return unchecked((int)0x80004005);
        var result = _native.GetItem(index, out var native);
        product = native;
        return result;
    }

    private static void ReleaseNativeReference(object value)
    {
        if (Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
    }
}

internal sealed class WindowsSecurityProviderComProduct(IWscProductNative native) : IWindowsSecurityProviderComProduct
{
    private IWscProductNative? _native = native;

    public bool TryGetDisplayName(out string? name)
    {
        name = null;
        return _native is not null && _native.GetProductName(out name) == 0;
    }

    public bool TryGetState(out int state)
    {
        state = default;
        return _native is not null && _native.GetProductState(out state) == 0;
    }

    public void Dispose()
    {
        var native = Interlocked.Exchange(ref _native, null);
        if (native is not null && Marshal.IsComObject(native)) Marshal.FinalReleaseComObject(native);
    }
}

[ComImport, Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWscProductListNative
{
    [PreserveSig] int Initialize(uint provider);
    [PreserveSig] int GetCount(out int count);
    [PreserveSig] int GetItem(uint index, [MarshalAs(UnmanagedType.Interface)] out IWscProductNative? product);
}

[ComImport, Guid("8C38232E-3A45-4A27-92B0-1A16A975F669"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWscProductNative
{
    [PreserveSig] int GetProductName([MarshalAs(UnmanagedType.BStr)] out string? name);
    [PreserveSig] int GetProductState(out int state);
}

[ComImport, Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A")]
internal class WscProductListComClass;
