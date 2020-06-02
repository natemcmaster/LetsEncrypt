// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using LettuceEncrypt.Internal.IO;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    /// <summary>
    /// Loads certificates for all configured hostnames
    /// </summary>
    internal class AcmeCertificateLoader : BackgroundService
    {
        private readonly AcmeCertificateCreatorFactory _certificateCreatorFactory;
        private readonly CertificateSelector _selector;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger _logger;

        private readonly IServer _server;
        private readonly IConfiguration _config;
        private readonly IEnumerable<ICertificateRepository> _certificateRepositories;
        private readonly IClock _clock;
        private const string ErrorMessage = "Failed to create certificate";

        public AcmeCertificateLoader(
            AcmeCertificateCreatorFactory certificateCreatorFactory,
            CertificateSelector selector,
            IOptions<LettuceEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IServer server,
            IConfiguration config,
            IEnumerable<ICertificateRepository> certificateRepositories,
            IClock clock)
        {
            _certificateCreatorFactory = certificateCreatorFactory;
            _selector = selector;
            _options = options;
            _logger = logger;
            _server = server;
            _config = config;
            _certificateRepositories = certificateRepositories;
            _clock = clock;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!(_server is KestrelServer))
            {
                var serverType = _server.GetType().FullName;
                _logger.LogWarning(
                    "LettuceEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.",
                    serverType);
                return;
            }

            if (_config.GetValue<bool>("UseIISIntegration"))
            {
                _logger.LogWarning(
                    "LettuceEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding." +
                    "Skipping certificate provisioning.");
                return;
            }

            // load certificates in the background

            if (!LettuceEncryptDomainNamesWereConfigured())
            {
                _logger.LogInformation("No domain names were configured");
                return;
            }

            await Task.Run(async () =>
            {
                try
                {
                    await LoadCerts(stoppingToken);
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, ErrorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, ErrorMessage);
                }

                await MonitorRenewal(stoppingToken);
            }, stoppingToken);
        }

        private bool LettuceEncryptDomainNamesWereConfigured()
        {
            return _options.Value.DomainNames
                .Any(w => !string.Equals("localhost", w, StringComparison.OrdinalIgnoreCase));
        }

        private async Task LoadCerts(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var domainNames = _options.Value.DomainNames;
            var hasCertForAllDomains = domainNames.All(_selector.HasCertForDomain);
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for {domainNames} already found.", domainNames);
                return;
            }

            await CreateCertificateAsync(domainNames, cancellationToken);
        }

        private async Task CreateCertificateAsync(string[] domainNames, CancellationToken cancellationToken)
        {
            var factory = _certificateCreatorFactory.Create();

            var account = await factory.GetOrCreateAccountAsync(cancellationToken);
            _logger.LogInformation("Using account {accountId}", account.Id);

            try
            {
                _logger.LogInformation("Creating certificate for {hostname}",
                    string.Join(",", domainNames));

                var cert = await factory.CreateCertificateAsync(cancellationToken);

                _logger.LogInformation("Created certificate {subjectName} ({thumbprint})",
                    cert.Subject,
                    cert.Thumbprint);

                await SaveCertificateAsync(cert, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", domainNames);
                throw;
            }
        }

        private async Task SaveCertificateAsync(X509Certificate2 cert, CancellationToken cancellationToken)
        {
            _selector.Add(cert);

            var saveTasks = new List<Task>
            {
                Task.Delay(TimeSpan.FromMinutes(5), cancellationToken)
            };

            var errors = new List<Exception>();
            foreach (var repo in _certificateRepositories)
            {
                try
                {
                    saveTasks.Add(repo.SaveAsync(cert, cancellationToken));
                }
                catch (Exception ex)
                {
                    // synchronous saves may fail immediately
                    errors.Add(ex);
                }
            }

            await Task.WhenAll(saveTasks);

            if (errors.Count > 0)
            {
                throw new AggregateException("Failed to save cert to repositories", errors);
            }
        }

        private async Task MonitorRenewal(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var checkPeriod = _options.Value.RenewalCheckPeriod;
                var daysInAdvance = _options.Value.RenewDaysInAdvance;
                if (!checkPeriod.HasValue || !daysInAdvance.HasValue)
                {
                    _logger.LogInformation("Automatic certificate renewal is not configured. Stopping {service}",
                        nameof(AcmeCertificateLoader));
                    return;
                }

                await Task.Delay(checkPeriod.Value, cancellationToken);

                try
                {
                    var domainNames = _options.Value.DomainNames;
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug("Checking certificates' renewals for {hostname}",
                            string.Join(", ", domainNames));
                    }

                    foreach (var domainName in domainNames)
                    {
                        if (!_selector.TryGet(domainName, out var cert)
                            || cert == null
                            || cert.NotAfter <= _clock.Now.DateTime + daysInAdvance.Value)
                        {
                            await CreateCertificateAsync(domainNames, cancellationToken);
                            break;
                        }
                    }
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, ErrorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, ErrorMessage);
                }
            }
        }
    }
}
