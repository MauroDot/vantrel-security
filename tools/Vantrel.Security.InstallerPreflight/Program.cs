using Vantrel.Security.InstallerPreflight;

try
{
    if (args.Length != 7 || args[0] != "create-plan" || args[1] != "--output-root" || args[3] != "--msi-product-version" || args[5] != "--plan-output")
        throw new ArgumentException();
    new InstallerInputValidator().CreateAndWritePlan(args[2], args[4], args[6]);
}
catch
{
    Console.Error.WriteLine("Installer input validation failed.");
    Environment.ExitCode = 1;
}
