# LettuceEncrypt 🥬 for ASP.NET Core

[![Build Status][azdo-badge]][azdo-url] [![Nuget][nuget-badge]][nuget-url]

[azdo-badge]: https://dev.azure.com/natemcmaster/github/_apis/build/status/LettuceEncrypt?branchName=master
[azdo-url]: https://dev.azure.com/natemcmaster/github/_build/latest?definitionId=10&branchName=master
[nuget-badge]: https://img.shields.io/nuget/v/LettuceEncrypt?color=blue
[nuget-url]: https://nuget.org/packages/LettuceEncrypt
[ACME]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
[Let's Encrypt]: https://letsencrypt.org/

LettuceEncrypt 🥬 provides API for ASP.NET Core projects to integrate with a certificate authority (CA), such as
[Let's Encrypt], for free, automatic HTTPS (SSL/TLS) certificate generation using the [ACME] protocol.

When enabled, your web server will **automatically** generate an HTTPS certificate during start up. It then configures Kestrel to use this certificate for all HTTPS traffic. See [usage instructions below](#usage) to get started.

Created and developed by [@natemcmaster](https://github.com/natemcmaster) with ❤️from Seattle ☕️.
This project was formerly known as "LetsEncrypt", but has been renamed for
trademark reasons. This project is **not an official
offering** from Let's Encrypt® or ISRG™.

Special thanks to my sponsors!

* [@bordenit](https://github.com/bordenit)

This project is 100% organic and best served cold with ranch and carrots.

## Will this work for me?

That depends on [which kind of web server you are using](#web-server-scenarios). This library only works with [Kestrel](https://docs.microsoft.com/aspnet/core/fundamentals/servers/kestrel), which is the default server configuration for ASP.NET Core projects. Other servers, such as IIS and HTTP.sys, are not supported. Furthermore, this only works when Kestrel is the edge server.

Not sure? [Read "Web Server Scenarios" below for more details.](#web-server-scenarios)

Using :cloud: Azure App Services (aka WebApps)? This library isn't for you, but you can still get free HTTPS certificates. See ["Securing An Azure App Service with Let's Encrypt"](https://www.hanselman.com/blog/SecuringAnAzureAppServiceWebsiteUnderSSLInMinutesWithLettuceEncrypt.aspx) by Scott Hanselman for more details.

## Usage

Install this package into your project using NuGet ([see details here][nuget-url]).

The primary API usage is to call `IServiceCollection.AddLettuceEncrypt` in the `Startup` class `ConfigureServices` method.

```csharp
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLettuceEncrypt();
    }
}
```

A few required options should be set, typically via the appsettings.json file.

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        // Set this to automatically accept the terms of service of your certificate authority.
        // If you don't set this in config, you will need to press "y" whenever the application starts
        "AcceptTermsOfService": true,

        // You must at least one domain name
        "DomainNames": [ "example.com", "www.example.com" ],

        // You must specify an email address to register with the certificate authority
        "EmailAddress": "it-admin@example.com"
    }
}
```

## Additional options

Certificates are stored to the machine's X.509 store by default. Certificates can be stored in additional
locations by using extension methods after calling `AddLettuceEncrypt()` in the `Startup` class.

Multiple storage locations can be configured.

### Save generated certificates and account information to a directory

```c#
using LettuceEncrypt;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistDataToDirectory(new DirectoryInfo("C:/data/LettuceEncrypt/"), "Password123");
}
```

### Save generated certificates to Azure Key Vault

Install [LettuceEncrypt.Azure](https://nuget.org/packages/LettuceEncrypt.Azure).

```c#
using LettuceEncrypt;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistCertificatesToAzureKeyVault(o =>
        {
            o.AzureKeyVaultEndpoint = "https://[url].vault.azure.net/";
        });
}
```


## Testing in development

See the [developer docs](./test/Integration/) for details on how to test in a non-production environment.

## Web Server Scenarios

I recommend also reading [Microsoft's official documentation on hosting and deploying ASP.NET Core](https://docs.microsoft.com/aspnet/core/host-and-deploy/).

### ASP.NET Core with Kestrel

:white_check_mark: supported

![Diagram of Kestrel on the edge with Kestrel](https://i.imgur.com/vhQTgUe.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to the internet. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with IIS

:x: NOT supported

![Diagram of Kestrel on the edge with IIS](https://i.imgur.com/PmrcLkN.png)

In this scenario, ASP.NET Core is hosted by IIS and that web server exposes its ports directly to the internet. IIS does not support dynamically configuring HTTPS certificates, so this library cannot support this scenario, but you can still configure cert automation using a different tool. See ["Using Let's Encrypt with IIS On Windows"](https://weblog.west-wind.com/posts/2016/feb/22/using-lets-encrypt-with-iis-on-windows) for details.

Azure App Service uses this for ASP.NET Core 2.2 and newer, which is why this library cannot support that scenario.. Older versions of ASP.NET Core on Azure App Service run with IIS as the reverse proxy (see below), which is also an unsupported scenario.


### ASP.NET Core with Kestrel Behind a TCP Load Balancer (aka SSL pass-thru)

:white_check_mark: supported

![Diagram of TCP Load Balancer](https://i.imgur.com/txqLTv5.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to a local network. A TCP load balancer such as nginx forwards traffic without decrypting it to the host running Kestrel. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with Kestrel Behind a Reverse Proxy

:x: NOT supported

![Diagram of reverse proxy](https://i.imgur.com/LA4jms7.png)

In this scenario, HTTPS traffic is decrypted by a different web server that is beyond the control of ASP.NET Core. This library cannot support this scenario because HTTPS certificates must be configured by the reverse proxy server.

This is commonly done by web hosting providers. For example, :cloud: Azure App Services (aka WebApps) often runs older versions of ASP.NET Core in a reverse proxy.

If you are running the reverse proxy, you can still get free HTTPS certificates, but you'll need to use a different method. [Try Googling this](https://www.google.com/search?q=let%27s%20encrypt%20nginx).
