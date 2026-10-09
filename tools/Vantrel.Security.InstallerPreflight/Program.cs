using Vantrel.Security.InstallerPreflight;

try
{
    if (args.Length == 7 && args[0] == "create-plan" && args[1] == "--output-root" && args[3] == "--msi-product-version" && args[5] == "--plan-output")
        new InstallerInputValidator().CreateAndWritePlan(args[2], args[4], args[6]);
    else if (args.Length == 7 && args[0] == "emit-wix" && args[1] == "--output-root" && args[3] == "--installer-plan" && args[5] == "--wix-output")
        WixFirstInstallAuthoring.ValidateAndWrite(args[2], args[4], args[6]);
    else if (args.Length == 17 && args[0] == "write-sandbox-input" && args[1] == "--installer-plan" && args[3] == "--msi" && args[5] == "--output" &&
             args[7] == "--source-commit" && args[9] == "--release-version" && args[11] == "--release-sequence" && args[13] == "--published-at-utc" && args[15] == "--msi-product-version")
        SandboxValidationInputCodec.CreateAndWrite(args[2], args[4], args[6], args[8], args[10], args[12], args[14], args[16]);
    else if (args.Length > 0 && args[0] == "sign-msi-distribution")
        MsiDistributionCommand.ExecuteProduction(args);
    else
        throw new ArgumentException();
}
catch
{
    Console.Error.WriteLine("Installer input validation failed.");
    Environment.ExitCode = 1;
}
