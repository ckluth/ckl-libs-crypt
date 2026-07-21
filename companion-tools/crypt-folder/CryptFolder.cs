#:package CKL.Libs.Crypt@3.0.0
#:property JsonSerializerIsReflectionEnabledByDefault=true

// Companion script for CKL.Libs.Crypt — encrypts or decrypts a whole folder.
// Run directly with the .NET 10 SDK: dotnet run CryptFolder.cs -- <encrypt|decrypt> <source> <target>
// The password is never passed as an argument; it is read from the keyboard in plaintext.

using CKL.Libs.Crypt;

if (args.Length < 3)
{
    Console.Error.WriteLine("Usage: dotnet run CryptFolder.cs -- <encrypt|decrypt> <source> <target>");
    return 1;
}

var mode = args[0].Trim().ToLowerInvariant();
var source = args[1];
var target = args[2];

if (mode != "encrypt" && mode != "decrypt")
{
    Console.Error.WriteLine("Mode must be 'encrypt' or 'decrypt'.");
    return 1;
}

if (mode == "encrypt" && !Directory.Exists(source))
{
    Console.Error.WriteLine($"Source folder not found: {source}");
    return 1;
}

if (mode == "decrypt" && !File.Exists(source))
{
    Console.Error.WriteLine($"Source file not found: {source}");
    return 1;
}

string password;
while (true)
{
    password = ReadPassword("Password: ");
    if (string.IsNullOrEmpty(password))
    {
        Console.Error.WriteLine("Password must not be empty.");
        return 1;
    }

    if (mode != "encrypt")
    {
        break;
    }

    // A typo here is only discovered later, possibly after the source is gone — confirm it now.
    var confirmation = ReadPassword("Confirm password: ");
    if (password == confirmation)
    {
        break;
    }

    Console.WriteLine("Passwords did not match — please try again.");
}

Console.WriteLine(mode == "encrypt"
    ? $"Encrypting '{source}' -> '{target}' ..."
    : $"Decrypting '{source}' -> '{target}' ...");

var result = mode == "encrypt"
    ? CryptoService.EncryptFolder(source, target, password)
    : CryptoService.DecryptFolder(source, target, password);

if (!result.Succeeded)
{
    Console.Error.WriteLine(result.ErrorMessage);
    Console.Error.WriteLine(result.CallStackAsString);
    return 1;
}

Console.WriteLine("Done.");
return 0;

static string ReadPassword(string prompt)
{
    Console.Write(prompt);
    return Console.ReadLine() ?? string.Empty;
}
