namespace Vantrel.Security.ReleaseLayoutTool;

/// <summary>The independent, ordered v2 Service signing authority.</summary>
internal static class ServiceReleaseV2PeContract
{
    internal static IReadOnlyList<ReleaseSigningArtifact> VantrelOwnedPeArtifacts { get; } =
        Array.AsReadOnly(new ReleaseSigningArtifact[]
        {
            new("service/Vantrel.Security.Service.exe"),
            new("service/Vantrel.Security.Service.dll"),
            new("service/Vantrel.Security.Infrastructure.dll"),
            new("service/Vantrel.Security.Core.dll")
        });
}
