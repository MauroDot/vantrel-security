using System.Text;
using System.Text.Json.Nodes;

namespace Vantrel.Security.Ipc.Tests;

[TestClass]
public sealed class LocalServiceHarnessPublishContractTests
{
    private const string EventLogLibrary = "System.Diagnostics.EventLog/10.0.12";
    private const string ServiceControllerLibrary = "System.ServiceProcess.ServiceController/10.0.12";
    private const string SelectedTargetName = ".NETCoreApp,Version=v10.0/win-x64";
    private const string EventLogAsset = "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.dll";
    private const string MessageAsset = "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.Messages.dll";

    // The SDK 10.0.401 framework-dependent win-x64 output has these two runtimeconfig
    // forms: Release adds MetadataUpdater.IsSupported=false to the Debug properties.
    private const string RuntimeConfig = """
        {
          "runtimeOptions": {
            "tfm": "net10.0",
            "framework": {
              "name": "Microsoft.NETCore.App",
              "version": "10.0.0"
            },
            "configProperties": {
              "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization": false,
              "CSWINRT_USE_WINDOWS_UI_XAML_PROJECTIONS": false
            }
          }
        }
        """;

    // Keep the package identity and asset paths shaped like the actual locked publish.
    // These fixtures are semantic inputs only; no synthetic DLL bytes enter the payload.
    private const string Deps = """
        {
          "runtimeTarget": {
            "name": ".NETCoreApp,Version=v10.0/win-x64",
            "signature": ""
          },
          "compilationOptions": {},
          "targets": {
            ".NETCoreApp,Version=v10.0": {},
            ".NETCoreApp,Version=v10.0/win-x64": {
              "Kestermere.Security.LocalServiceAclHarness/0.1.0": {
                "dependencies": {
                  "System.ServiceProcess.ServiceController": "10.0.12"
                },
                "runtime": {
                  "Kestermere.Security.LocalServiceAclHarness.dll": {}
                }
              },
              "System.Diagnostics.EventLog/10.0.12": {
                "runtime": {
                  "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.Messages.dll": {
                    "assemblyVersion": "10.0.0.0",
                    "fileVersion": "0.0.0.0"
                  },
                  "runtimes/win/lib/net10.0/System.Diagnostics.EventLog.dll": {
                    "assemblyVersion": "10.0.0.0",
                    "fileVersion": "10.0.1226.42308"
                  }
                }
              },
              "System.ServiceProcess.ServiceController/10.0.12": {
                "dependencies": {
                  "System.Diagnostics.EventLog": "10.0.12"
                },
                "runtime": {
                  "runtimes/win/lib/net10.0/System.ServiceProcess.ServiceController.dll": {
                    "assemblyVersion": "10.0.0.12",
                    "fileVersion": "10.0.1226.42308"
                  }
                }
              }
            }
          },
          "libraries": {
            "Kestermere.Security.LocalServiceAclHarness/0.1.0": {
              "type": "project",
              "serviceable": false,
              "sha512": ""
            },
            "System.Diagnostics.EventLog/10.0.12": {
              "type": "package",
              "serviceable": true,
              "sha512": "sha512-sOZM+VyRj1pg/ItlHsvrSbjws6oGqZveTzTNBGZ9ziwRDyKsOF3ub6vhvOdxotCIqtlnyHAIwP5sLNvgiZC+pQ==",
              "path": "system.diagnostics.eventlog/10.0.12",
              "hashPath": "system.diagnostics.eventlog.10.0.12.nupkg.sha512"
            },
            "System.ServiceProcess.ServiceController/10.0.12": {
              "type": "package",
              "serviceable": true,
              "sha512": "sha512-sFV+RM/yPtshiCAEIuTm8Dt4F7VuKRbL50PnGC9nXHolk/jw+z3T8zx7axKTBC8mqtQU2ZmjsoPC9b1iwOilNQ==",
              "path": "system.serviceprocess.servicecontroller/10.0.12",
              "hashPath": "system.serviceprocess.servicecontroller.10.0.12.nupkg.sha512"
            }
          }
        }
        """;

    [TestMethod]
    public void Current_sdk_shaped_Debug_and_Release_manifests_are_accepted()
    {
        Validate(RuntimeConfig, Deps);

        var release = ParseRuntimeConfig();
        release["runtimeOptions"]!["configProperties"]!.AsObject()
            ["System.Reflection.Metadata.MetadataUpdater.IsSupported"] = false;
        Validate(release.ToJsonString(), Deps);
    }

    [DataTestMethod]
    [DataRow("Microsoft.WindowsDesktop.App")]
    [DataRow("Other.Framework")]
    public void Runtimeconfig_rejects_wrong_primary_framework(string framework)
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!["framework"]!["name"] = framework);
    }

    [DataTestMethod]
    [DataRow("9.0.0")]
    [DataRow("11.0.0")]
    public void Runtimeconfig_rejects_wrong_dotnet_major(string version)
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!["framework"]!["version"] = version);
    }

    [TestMethod]
    public void Runtimeconfig_rejects_wrong_target_framework()
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!["tfm"] = "net9.0");
    }

    [TestMethod]
    public void Runtimeconfig_rejects_missing_runtime_options()
    {
        RejectRuntimeConfig(config => config.Remove("runtimeOptions"));
    }

    [TestMethod]
    public void Runtimeconfig_rejects_missing_framework()
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!.AsObject().Remove("framework"));
    }

    [TestMethod]
    public void Runtimeconfig_rejects_malformed_json() => Reject("{", Deps);

    [TestMethod]
    public void Runtimeconfig_rejects_input_above_its_json_size_bound() =>
        Reject(new string(' ', 16 * 1024) + RuntimeConfig, Deps);

    [TestMethod]
    public void Runtimeconfig_rejects_duplicate_framework_declaration()
    {
        var duplicate = RuntimeConfig.Replace("\"framework\": {",
            "\"framework\": {\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"}, \"framework\": {",
            StringComparison.Ordinal);
        Assert.AreNotEqual(RuntimeConfig, duplicate);
        Reject(duplicate, Deps);
    }

    [TestMethod]
    public void Runtimeconfig_rejects_duplicate_framework_field()
    {
        var duplicate = RuntimeConfig.Replace("\"name\": \"Microsoft.NETCore.App\"",
            "\"name\": \"Microsoft.NETCore.App\", \"name\": \"Microsoft.NETCore.App\"",
            StringComparison.Ordinal);
        Assert.AreNotEqual(RuntimeConfig, duplicate);
        Reject(duplicate, Deps);
    }

    [TestMethod]
    public void Runtimeconfig_rejects_self_contained_framework_declaration()
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!.AsObject()["includedFrameworks"] =
            new JsonArray(new JsonObject
            {
                ["name"] = "Microsoft.NETCore.App",
                ["version"] = "10.0.0"
            }));
    }

    [TestMethod]
    public void Runtimeconfig_rejects_major_roll_forward()
    {
        RejectRuntimeConfig(config => config["runtimeOptions"]!.AsObject()["rollForward"] = "Major");
    }

    [TestMethod]
    public void Deps_rejects_extra_managed_runtime_asset()
    {
        RejectDeps(deps => RuntimeAssets(deps, EventLogLibrary)["runtimes/win/lib/net10.0/Extra.Managed.dll"] =
            new JsonObject());
    }

    [TestMethod]
    public void Deps_rejects_extra_native_asset()
    {
        RejectDeps(deps => SelectedLibrary(deps, EventLogLibrary)["native"] = new JsonObject
        {
            ["runtimes/win-x64/native/extra.dll"] = new JsonObject()
        });
    }

    [TestMethod]
    public void Deps_rejects_extra_resource_asset()
    {
        RejectDeps(deps => SelectedLibrary(deps, EventLogLibrary)["resources"] = new JsonObject
        {
            ["en-US/Extra.resources.dll"] = new JsonObject { ["locale"] = "en-US" }
        });
    }

    [TestMethod]
    public void Deps_rejects_extra_runtime_target_asset()
    {
        RejectDeps(deps => SelectedLibrary(deps, EventLogLibrary)["runtimeTargets"] = new JsonObject
        {
            ["runtimes/win-x64/native/extra.dll"] = new JsonObject
            {
                ["rid"] = "win-x64",
                ["assetType"] = "native"
            }
        });
    }

    [TestMethod]
    public void Deps_rejects_missing_expected_runtime_asset()
    {
        RejectDeps(deps => RuntimeAssets(deps, EventLogLibrary).Remove(MessageAsset));
    }

    [TestMethod]
    public void Deps_rejects_duplicate_runtime_asset_property()
    {
        const string asset = "\"Kestermere.Security.LocalServiceAclHarness.dll\": {}";
        var duplicate = Deps.Replace(asset, asset + ", " + asset, StringComparison.Ordinal);
        Assert.AreNotEqual(Deps, duplicate);
        Reject(RuntimeConfig, duplicate);
    }

    [TestMethod]
    public void Deps_rejects_same_asset_path_declared_by_two_libraries()
    {
        RejectDeps(deps => RuntimeAssets(deps, ServiceControllerLibrary)[EventLogAsset] = new JsonObject());
    }

    [TestMethod]
    public void Deps_rejects_two_paths_collapsing_to_one_payload_basename()
    {
        RejectDeps(deps => RuntimeAssets(deps, EventLogLibrary)
            ["runtimes/win-x64/lib/net10.0/System.Diagnostics.EventLog.dll"] = new JsonObject());
    }

    [TestMethod]
    public void Deps_rejects_wrong_runtime_identifier()
    {
        RejectDeps(deps => deps["runtimeTarget"]!["name"] = ".NETCoreApp,Version=v10.0/linux-x64");
    }

    [TestMethod]
    public void Deps_rejects_wrong_framework_target()
    {
        RejectDeps(deps => deps["runtimeTarget"]!["name"] = ".NETCoreApp,Version=v9.0/win-x64");
    }

    [TestMethod]
    public void Deps_rejects_alternate_selected_target()
    {
        RejectDeps(deps => deps["targets"]!.AsObject()[".NETCoreApp,Version=v10.0/linux-x64"] =
            new JsonObject());
    }

    [DataTestMethod]
    [DataRow("../System.Diagnostics.EventLog.dll")]
    [DataRow("/System.Diagnostics.EventLog.dll")]
    [DataRow("C:/System.Diagnostics.EventLog.dll")]
    [DataRow("runtimes\\win\\lib\\net10.0\\System.Diagnostics.EventLog.dll")]
    [DataRow("runtimes/win/../lib/net10.0/System.Diagnostics.EventLog.dll")]
    [DataRow("runtimes//win/lib/net10.0/System.Diagnostics.EventLog.dll")]
    public void Deps_rejects_unsafe_asset_paths(string path)
    {
        RejectDeps(deps =>
        {
            var assets = RuntimeAssets(deps, EventLogLibrary);
            assets.Remove(EventLogAsset);
            assets[path] = new JsonObject();
        });
    }

    [TestMethod]
    public void Deps_rejects_malformed_json() => Reject(RuntimeConfig, "{");

    [TestMethod]
    public void Deps_rejects_input_above_its_json_size_bound() =>
        Reject(RuntimeConfig, new string(' ', 1024 * 1024) + Deps);

    private static JsonObject ParseRuntimeConfig() => JsonNode.Parse(RuntimeConfig)!.AsObject();
    private static JsonObject ParseDeps() => JsonNode.Parse(Deps)!.AsObject();

    private static JsonObject SelectedLibrary(JsonObject deps, string name) =>
        deps["targets"]![SelectedTargetName]![name]!.AsObject();

    private static JsonObject RuntimeAssets(JsonObject deps, string library) =>
        SelectedLibrary(deps, library)["runtime"]!.AsObject();

    private static void RejectRuntimeConfig(Action<JsonObject> change)
    {
        var config = ParseRuntimeConfig();
        change(config);
        Reject(config.ToJsonString(), Deps);
    }

    private static void RejectDeps(Action<JsonObject> change)
    {
        var deps = ParseDeps();
        change(deps);
        Reject(RuntimeConfig, deps.ToJsonString());
    }

    private static void Validate(string runtimeConfig, string deps) =>
        LocalServiceHarnessPublishContract.Validate(
            Encoding.UTF8.GetBytes(runtimeConfig), Encoding.UTF8.GetBytes(deps));

    private static void Reject(string runtimeConfig, string deps) =>
        Assert.ThrowsException<IOException>(() => Validate(runtimeConfig, deps));
}
