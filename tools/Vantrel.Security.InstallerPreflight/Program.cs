using Vantrel.Security.InstallerPreflight;

try
{
    if (args.Length == 7 && args[0] == "create-plan" && args[1] == "--output-root" && args[3] == "--msi-product-version" && args[5] == "--plan-output")
        new InstallerInputValidator().CreateAndWritePlan(args[2], args[4], args[6]);
    else if (args.Length == 7 && args[0] == "emit-wix" && args[1] == "--output-root" && args[3] == "--installer-plan" && args[5] == "--wix-output")
        WixFirstInstallAuthoring.ValidateAndWrite(args[2], args[4], args[6]);
    else
        throw new ArgumentException();
}
catch
{
    Console.Error.WriteLine("Installer input validation failed.");
    Environment.ExitCode = 1;
}
