// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using McMaster.AspNetCore.LetsEncrypt.Internal.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Helper methods for configuring https://letsencrypt.org/.
    /// </summary>
    public static class LetsEncryptServiceCollectionExtensions
    {
        /// <summary>
        /// Use Let's Encrypt (<see href="https://letsencrypt.org/">https://letsencrypt.org/</see>) to automatically
        /// generate HTTPS certificates for this server.
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public static ILetsEncryptServiceBuilder AddLetsEncrypt(this IServiceCollection services)
            => services.AddLetsEncrypt(_ => { });

        /// <summary>
        /// Use Let's Encrypt (<see href="https://letsencrypt.org/">https://letsencrypt.org/</see>) to automatically
        /// generate HTTPS certificates for this server.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configure">A callback to configure options.</param>
        /// <returns></returns>
        public static ILetsEncryptServiceBuilder AddLetsEncrypt(this IServiceCollection services, Action<LetsEncryptOptions> configure)
        {
            services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>();

            services.AddSingleton<CertificateSelector>()
                .AddSingleton<IConsole>(PhysicalConsole.Singleton)
                .AddSingleton<IClock, SystemClock>()
                .AddSingleton<TermsOfServiceChecker>()
                .AddSingleton<IHostedService, StartupCertificateLoader>()
                .AddSingleton<ICertificateSource, DeveloperCertLoader>()
                .AddSingleton<IHostedService, AcmeCertificateLoader>()
                .AddSingleton<IHttpChallengeResponseStore, InMemoryHttpChallengeResponseStore>()
                .AddSingleton<X509CertStore>()
                .AddSingleton<ICertificateSource>(x => x.GetRequiredService<X509CertStore>())
                .AddSingleton<ICertificateRepository>(x => x.GetRequiredService<X509CertStore>())
                .AddSingleton<HttpChallengeResponseMiddleware>()
                .AddSingleton<TlsAlpnChallengeResponder>()
                .AddSingleton<IStartupFilter, HttpChallengeStartupFilter>();

            services.AddSingleton<IConfigureOptions<LetsEncryptOptions>>(services =>
            {
                var config = services.GetService<IConfiguration?>();
                return new ConfigureOptions<LetsEncryptOptions>(options => config?.Bind("LetsEncrypt", options));
            });

            services.Configure(configure);

            return new LetsEncryptServiceBuilder(services);
        }
    }
}
