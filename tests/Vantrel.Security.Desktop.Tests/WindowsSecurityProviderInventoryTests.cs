using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Vantrel.Security.Desktop;

namespace Vantrel.Security.Desktop.Tests;

[TestClass]
public sealed class WindowsSecurityProviderInventoryTests
{
    [TestMethod]
    public void Source_maps_current_antivirus_and_firewall_provider_names_and_states()
    {
        var now = DateTimeOffset.UtcNow;
        var source = new WindowsSecurityProviderInventorySource(new FakeNativeReader(
            Category(true, products: [new("Example AV", 0), new("Example AV backup", 2)]),
            Category(true, products: [new("Example Firewall", 3)])), () => now);

        var snapshot = source.Collect();

        Assert.AreEqual(now, snapshot.CollectedAtUtc);
        Assert.AreEqual(WindowsSecurityProviderCategoryState.Current, snapshot.Antivirus.State);
        Assert.AreEqual(WindowsSecurityProviderProductState.On, snapshot.Antivirus.Entries[0].State);
        Assert.AreEqual(WindowsSecurityProviderProductState.Snoozed, snapshot.Antivirus.Entries[1].State);
        Assert.AreEqual(WindowsSecurityProviderProductState.Expired, snapshot.Firewall.Entries[0].State);

        var off = new WindowsSecurityProviderInventorySource(new FakeNativeReader(
            Category(true, products: [new("Example AV", 1)]), Category(true))).Collect();
        Assert.AreEqual(WindowsSecurityProviderProductState.Off, off.Antivirus.Entries[0].State);
    }

    [TestMethod]
    public void Source_marks_empty_and_unavailable_categories_without_diagnostics()
    {
        var source = new WindowsSecurityProviderInventorySource(new FakeNativeReader(Category(true), WindowsSecurityProviderNativeCategoryResult.Unavailable()));

        var snapshot = source.Collect();

        Assert.AreEqual(WindowsSecurityProviderCategoryState.Empty, snapshot.Antivirus.State);
        Assert.AreEqual(WindowsSecurityProviderCategoryState.Unavailable, snapshot.Firewall.State);
        Assert.AreEqual(0, snapshot.Antivirus.Entries.Length);
        Assert.AreEqual(0, snapshot.Firewall.Entries.Length);
    }

    [TestMethod]
    public void Source_rejects_malformed_overlong_control_and_path_like_names_and_maps_unknown_state_to_partial()
    {
        var source = new WindowsSecurityProviderInventorySource(new FakeNativeReader(
            Category(true, products:
            [
                new(null, 0),
                new("bad\u0001name", 0),
                new(new string('x', 161), 0),
                new("C:\\provider.exe", 0),
                new("Valid Provider", 99)
            ]),
            Category(true)));

        var snapshot = source.Collect();

        Assert.AreEqual(WindowsSecurityProviderCategoryState.Partial, snapshot.Antivirus.State);
        Assert.AreEqual(1, snapshot.Antivirus.Entries.Length);
        Assert.AreEqual("Valid Provider", snapshot.Antivirus.Entries[0].DisplayName);
        Assert.AreEqual(WindowsSecurityProviderProductState.Unknown, snapshot.Antivirus.Entries[0].State);
    }

    [TestMethod]
    public void Source_preserves_only_the_first_32_entries_and_marks_native_cap_as_incomplete()
    {
        var providers = Enumerable.Range(0, WindowsSecurityProviderInventorySource.MaximumProvidersPerCategory)
            .Select(index => new WindowsSecurityProviderNativeProduct($"Provider {index}", 0)).ToArray();
        var source = new WindowsSecurityProviderInventorySource(new FakeNativeReader(
            new WindowsSecurityProviderNativeCategoryResult(true, false, true, providers), Category(true)));

        var snapshot = source.Collect();

        Assert.AreEqual(WindowsSecurityProviderCategoryState.Incomplete, snapshot.Antivirus.State);
        Assert.AreEqual(WindowsSecurityProviderInventorySource.MaximumProvidersPerCategory, snapshot.Antivirus.Entries.Length);
    }

    [TestMethod]
    public void Native_reader_releases_each_product_and_list_and_marks_item_failure_partial()
    {
        var first = new FakeComList([
            new FakeComProduct("Example AV", 0),
            new FakeComProduct("ignored", 0) { ItemAvailable = false }
        ]);
        var factory = new FakeComFactory(first);
        var reader = new WindowsSecurityProviderInventoryNativeReader(factory, () => true);

        var result = reader.Read(WindowsSecurityProviderCategory.Antivirus);

        Assert.IsTrue(first.Initialized);
        Assert.AreEqual(1, first.InitializeCalls);
        Assert.IsTrue(first.Disposed);
        Assert.IsTrue(first.Products[0].Disposed);
        Assert.IsTrue(result.Partial);
        Assert.AreEqual(1, result.Products.Count);
    }

    [TestMethod]
    public void Native_reader_uses_a_distinct_initialized_list_per_category_and_caps_at_32()
    {
        var antivirus = new FakeComList(Enumerable.Range(0, 33)
            .Select(index => new FakeComProduct($"Provider {index}", 0)).ToArray());
        var firewall = new FakeComList([]);
        var factory = new FakeComFactory(antivirus, firewall);
        var reader = new WindowsSecurityProviderInventoryNativeReader(factory, () => true);

        var antivirusResult = reader.Read(WindowsSecurityProviderCategory.Antivirus);
        var firewallResult = reader.Read(WindowsSecurityProviderCategory.Firewall);

        Assert.AreEqual(2, factory.CreateCalls);
        Assert.AreEqual(1, antivirus.InitializeCalls);
        Assert.AreEqual(1, firewall.InitializeCalls);
        Assert.IsTrue(antivirusResult.Incomplete);
        Assert.AreEqual(WindowsSecurityProviderInventorySource.MaximumProvidersPerCategory, antivirusResult.Products.Count);
        Assert.IsTrue(antivirus.Disposed);
        Assert.IsTrue(firewall.Disposed);
    }

    [TestMethod]
    public void Source_scopes_one_category_failure_without_exposing_its_diagnostic()
    {
        var source = new WindowsSecurityProviderInventorySource(new ThrowingNativeReader());

        var snapshot = source.Collect();
        var presentation = WindowsSecurityProviderInventoryPresentation.Create(snapshot, DateTimeOffset.UtcNow);

        Assert.AreEqual(WindowsSecurityProviderCategoryState.Unavailable, snapshot.Antivirus.State);
        Assert.AreEqual(WindowsSecurityProviderCategoryState.Current, snapshot.Firewall.State);
        Assert.AreEqual(WindowsSecurityProviderInventoryDisplayState.Partial, presentation.State);
        Assert.IsFalse(presentation.StateText.Contains("diagnostic", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(presentation.StateText.Contains("failure", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Unsupported_platform_does_not_create_a_com_list()
    {
        var factory = new FakeComFactory();
        var reader = new WindowsSecurityProviderInventoryNativeReader(factory, () => false);

        var result = reader.Read(WindowsSecurityProviderCategory.Firewall);

        Assert.IsFalse(result.Available);
        Assert.AreEqual(0, factory.CreateCalls);
    }

    [TestMethod]
    public void Get_item_nonzero_hresult_with_a_returned_reference_releases_it_once()
    {
        var rawProduct = new object();
        var releases = 0;
        using var list = new WindowsSecurityProviderComList(
            (uint _, out object? product) =>
            {
                product = rawProduct;
                return unchecked((int)0x80004005);
            },
            value =>
            {
                Assert.AreSame(rawProduct, value);
                releases++;
            });

        var available = list.TryGetProduct(0, out var product);

        Assert.IsFalse(available);
        Assert.IsNull(product);
        Assert.AreEqual(1, releases);
    }

    [TestMethod]
    public void Presentation_marks_visible_snapshot_stale_without_refreshing_and_rows_are_source_scoped()
    {
        var then = DateTimeOffset.UtcNow.AddMinutes(-3);
        var snapshot = new WindowsSecurityProviderInventorySnapshot(then,
            new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Current,
                [new(WindowsSecurityProviderCategory.Antivirus, "Example AV", WindowsSecurityProviderProductState.On)]),
            new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Empty, []));

        var presentation = WindowsSecurityProviderInventoryPresentation.Create(snapshot, DateTimeOffset.UtcNow);

        Assert.AreEqual(WindowsSecurityProviderInventoryDisplayState.Stale, presentation.State);
        Assert.IsTrue(presentation.StateText.Contains("not refreshed automatically", StringComparison.Ordinal));
        Assert.AreEqual("Windows-reported antivirus provider: Example AV — state reported by Windows: On.", presentation.EntryText[0]);
    }

    [TestMethod]
    public async Task Session_clears_active_view_inventory_when_protection_is_hidden_or_window_closes()
    {
        var source = new FakeInventorySource(new WindowsSecurityProviderInventorySnapshot(DateTimeOffset.UtcNow,
            new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Empty, []),
            new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Empty, [])));
        var session = new ProtectionProviderInventorySession();

        await session.OpenAsync(source);
        Assert.IsNotNull(session.Snapshot);
        Assert.AreEqual(1, source.Calls);
        session.Clear();

        Assert.IsNull(session.Snapshot);
    }

    [TestMethod]
    public async Task Protection_view_collection_is_asynchronous_and_late_results_cannot_repopulate_a_cleared_view()
    {
        var snapshots = new[]
        {
            new WindowsSecurityProviderInventorySnapshot(DateTimeOffset.UtcNow,
                new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Current,
                    [new(WindowsSecurityProviderCategory.Antivirus, "Example AV", WindowsSecurityProviderProductState.On)]),
                new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Empty, [])),
            new WindowsSecurityProviderInventorySnapshot(DateTimeOffset.UtcNow,
                new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Unavailable, []),
                new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Unavailable, [])),
            new WindowsSecurityProviderInventorySnapshot(DateTimeOffset.UtcNow,
                new(WindowsSecurityProviderCategory.Antivirus, WindowsSecurityProviderCategoryState.Partial,
                    [new(WindowsSecurityProviderCategory.Antivirus, "Partial AV", WindowsSecurityProviderProductState.Unknown)]),
                new(WindowsSecurityProviderCategory.Firewall, WindowsSecurityProviderCategoryState.Empty, []))
        };

        foreach (var snapshot in snapshots)
        {
            var source = new BlockingInventorySource();
            var session = new ProtectionProviderInventorySession();
            var stopwatch = Stopwatch.StartNew();
            var loading = session.OpenAsync(source);
            Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
            await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.IsFalse(loading.IsCompleted);

            session.Clear();
            source.Complete(snapshot);

            Assert.IsNull(await loading.WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.IsNull(session.Snapshot);
        }
    }

    [TestMethod]
    public void Presentation_uses_required_truthful_notice_without_a_composite_verdict()
    {
        var presentation = WindowsSecurityProviderInventoryPresentation.Initial();

        Assert.AreEqual("Windows-reported registered providers are shown for this interactive session. This inventory does not assess Vantrel active protection, malware, detection, provider effectiveness, or firewall configuration.", presentation.NoticeText);
        Assert.IsFalse(Regex.IsMatch(presentation.StateText, "\\b(Protected|Safe|Clean|Secure|Trusted)\\b", RegexOptions.IgnoreCase));
    }

    private static WindowsSecurityProviderNativeCategoryResult Category(bool available, bool partial = false,
        bool incomplete = false, IReadOnlyList<WindowsSecurityProviderNativeProduct>? products = null) =>
        new(available, partial, incomplete, products ?? []);

    private sealed class FakeNativeReader(WindowsSecurityProviderNativeCategoryResult antivirus,
        WindowsSecurityProviderNativeCategoryResult firewall) : IWindowsSecurityProviderInventoryNativeReader
    {
        public WindowsSecurityProviderNativeCategoryResult Read(WindowsSecurityProviderCategory category) =>
            category == WindowsSecurityProviderCategory.Antivirus ? antivirus : firewall;
    }

    private sealed class ThrowingNativeReader : IWindowsSecurityProviderInventoryNativeReader
    {
        public WindowsSecurityProviderNativeCategoryResult Read(WindowsSecurityProviderCategory category)
        {
            if (category == WindowsSecurityProviderCategory.Antivirus)
                throw new COMException("private diagnostic", unchecked((int)0x80004005));
            return Category(true, products: [new("Example Firewall", 0)]);
        }
    }

    private sealed class FakeInventorySource(WindowsSecurityProviderInventorySnapshot snapshot) : IWindowsSecurityProviderInventorySource
    {
        internal int Calls { get; private set; }
        public WindowsSecurityProviderInventorySnapshot Collect() { Calls++; return snapshot; }
    }

    private sealed class BlockingInventorySource : IWindowsSecurityProviderInventorySource
    {
        private readonly TaskCompletionSource<WindowsSecurityProviderInventorySnapshot> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public WindowsSecurityProviderInventorySnapshot Collect()
        {
            Entered.TrySetResult(true);
            return _completion.Task.GetAwaiter().GetResult();
        }
        internal void Complete(WindowsSecurityProviderInventorySnapshot snapshot) => _completion.TrySetResult(snapshot);
    }

    private sealed class FakeComFactory(params FakeComList[] lists) : IWindowsSecurityProviderComFactory
    {
        private readonly Queue<FakeComList> _lists = new(lists);
        internal int CreateCalls { get; private set; }
        public IWindowsSecurityProviderComList Create()
        {
            CreateCalls++;
            return _lists.Count == 0 ? throw new InvalidOperationException("no list configured") : _lists.Dequeue();
        }
    }

    private sealed class FakeComList(IReadOnlyList<FakeComProduct> products) : IWindowsSecurityProviderComList
    {
        internal IReadOnlyList<FakeComProduct> Products { get; } = products;
        internal bool Initialized { get; private set; }
        internal int InitializeCalls { get; private set; }
        internal bool Disposed { get; private set; }
        public bool TryInitialize(WindowsSecurityProviderCategory category) { Initialized = true; InitializeCalls++; return true; }
        public bool TryGetCount(out int count) { count = Products.Count; return true; }
        public bool TryGetProduct(int index, out IWindowsSecurityProviderComProduct? product)
        {
            product = Products[index].ItemAvailable ? Products[index] : null;
            return Products[index].ItemAvailable;
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class FakeComProduct(string name, int state) : IWindowsSecurityProviderComProduct
    {
        internal bool ItemAvailable { get; init; } = true;
        internal bool Disposed { get; private set; }
        public bool TryGetDisplayName(out string? value) { value = name; return true; }
        public bool TryGetState(out int value) { value = state; return true; }
        public void Dispose() => Disposed = true;
    }
}
