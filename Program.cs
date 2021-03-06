using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace KerberosLoopback;

public class Program
{
    [DllImport("libc", CharSet = CharSet.Ansi)]
    private static extern int setenv(string name, string value, bool overwrite);

    public static async Task Main()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddSimpleConsole(opt => opt.IncludeScopes = true)
                .AddFilter<ConsoleLoggerProvider>(level => level >= LogLevel.Trace);
        });

        var options = new ListenerOptions
        {
            Log = loggerFactory,
            DefaultRealm = "linux.contoso.com".ToUpper(),
            IsDebug = true,
            RealmLocator = realm => new FakeRealmService(realm)
        };

        // Start the KDC server
        var kdcListener = new FakeKdcServer(options);
        var endpoint = await kdcListener.Start();

        Console.WriteLine("KDC listening at " + endpoint);

        // Generate krb5.conf
        string krb5Path = Path.Combine(Environment.CurrentDirectory, "krb5.conf");
        if (OperatingSystem.IsLinux())
        {
            File.WriteAllText(krb5Path, $"[realms]\n{options.DefaultRealm} = {{\n  master_kdc = {endpoint}\n  kdc = {endpoint}\n}}\n");
        }
        else
        {
            File.WriteAllText(krb5Path, $"[realms]\n{options.DefaultRealm} = {{\n  kdc = tcp/{endpoint}\n}}\n");
        }

        // Generate keytab file
        string keytabPath = Path.Combine(Environment.CurrentDirectory, "krb5.keytab");
        var keyTable = new KeyTable();

        var etypes = options.Configuration.Defaults.DefaultTgsEncTypes;
        byte[] passwordBytes = FakeKerberosPrincipal.FakePassword;

        foreach (var etype in etypes.Where(CryptoService.SupportsEType))
        {
            var kerbKey = new KerberosKey(
                password: passwordBytes,
                etype: etype,
                principal: new PrincipalName(
                    PrincipalNameType.NT_PRINCIPAL,
                    options.DefaultRealm,
                    new [] { $"HTTP/linux.contoso.com" }),
                saltType: SaltType.ActiveDirectoryUser
            );

            keyTable.Entries.Add(new KeyEntry(kerbKey));
        }

        using (var fs = new FileStream(keytabPath, FileMode.Create))
        using (var writer = new BinaryWriter(fs))
        {
            keyTable.Write(writer);
            writer.Flush();
        }

        // Set environment variables for GSSAPI
        _ = setenv("KRB5_CONFIG", krb5Path, true);
        _ = setenv("KRB5_KTNAME", keytabPath, true);

        // Do a loopback authentication
        NegotiateAuthenticationClientOptions clientOptions = new()
        {
            Credential = new NetworkCredential("user", "P@ssw0rd!", options.DefaultRealm),
            TargetName = $"HTTP/linux.contoso.com"
        };
        NegotiateAuthenticationServerOptions serverOptions = new() { };
        NegotiateAuthentication clientNegotiateAuthentication = new(clientOptions);
        NegotiateAuthentication serverNegotiateAuthentication = new(serverOptions);

        byte[]? serverBlob = null;
        byte[]? clientBlob = null;
        bool shouldContinue = true;
        do
        {
            clientBlob = clientNegotiateAuthentication.GetOutgoingBlob(serverBlob, out NegotiateAuthenticationStatusCode statusCode);
            shouldContinue = statusCode == NegotiateAuthenticationStatusCode.ContinueNeeded;
            Console.WriteLine("client status: " + statusCode);
            Console.WriteLine("client blob: " + (clientBlob == null ? "null" : Convert.ToHexString(clientBlob)));
            if (clientBlob != null)
            {
                Console.WriteLine("client -> server ");
                serverBlob = serverNegotiateAuthentication.GetOutgoingBlob(clientBlob, out statusCode);
                Console.WriteLine("client -> server 2");
                Console.WriteLine("server status: " + statusCode);
                Console.WriteLine("server blob: " + (serverBlob == null ? "null" : Convert.ToHexString(serverBlob)));
            }
        }
        while (serverBlob != null && shouldContinue);

        kdcListener.Stop();

        File.Delete(krb5Path);
        File.Delete(keytabPath);
    }
}