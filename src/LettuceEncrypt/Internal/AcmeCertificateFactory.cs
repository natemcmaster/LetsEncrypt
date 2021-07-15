// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace LettuceEncrypt.Internal
{
    internal class AcmeCertificateFactory
    {
        private readonly AcmeClientFactory _acmeClientFactory;
        private readonly TermsOfServiceChecker _tosChecker;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly IAccountStore _accountRepository;
        private readonly ILogger _logger;
        private readonly IHostApplicationLifetime _appLifetime;
        private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;
        private readonly IEnumerable<IAdditionalIssuersSource> _additionalIssuersSources;
        private readonly TaskCompletionSource<object?> _appStarted = new();
        private AcmeClient? _client;
        private IKey? _acmeAccountKey;

        public AcmeCertificateFactory(
            AcmeClientFactory acmeClientFactory,
            TermsOfServiceChecker tosChecker,
            IOptions<LettuceEncryptOptions> options,
            IHttpChallengeResponseStore challengeStore,
            ILogger<AcmeCertificateFactory> logger,
            IHostApplicationLifetime appLifetime,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder,
            ICertificateAuthorityConfiguration certificateAuthority,
            IEnumerable<IAdditionalIssuersSource> additionalIssuersSources,
            IAccountStore? accountRepository = null)
        {
            _acmeClientFactory = acmeClientFactory;
            _tosChecker = tosChecker;
            _options = options;
            _challengeStore = challengeStore;
            _logger = logger;
            _appLifetime = appLifetime;
            _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;

            appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
            if (appLifetime.ApplicationStarted.IsCancellationRequested)
            {
                _appStarted.TrySetResult(null);
            }

            _additionalIssuersSources = additionalIssuersSources;
            _accountRepository = accountRepository ?? new FileSystemAccountStore(logger, certificateAuthority);
        }

        public async Task<AccountModel> GetOrCreateAccountAsync(CancellationToken cancellationToken)
        {
            var account = await _accountRepository.GetAccountAsync(cancellationToken);

            _acmeAccountKey = account != null
                ? KeyFactory.FromDer(account.PrivateKey)
                : KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);

            _client = _acmeClientFactory.Create(_acmeAccountKey);

            if (account != null && await ExistingAccountIsValidAsync())
            {
                return account;
            }

            return await CreateAccount(cancellationToken);
        }

        private async Task<AccountModel> CreateAccount(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null || _acmeAccountKey == null)
            {
                throw new InvalidOperationException();
            }

            var tosUri = await _client.GetTermsOfServiceAsync();

            _tosChecker.EnsureTermsAreAccepted(tosUri);

            var options = _options.Value;
            _logger.LogInformation("Creating new account for {email}", options.EmailAddress);
            var accountId = await _client.CreateAccountAsync(options.EmailAddress);

            var accountModel = new AccountModel
            {
                Id = accountId,
                EmailAddresses = new[] { options.EmailAddress },
                PrivateKey = _acmeAccountKey.ToDer(),
            };

            await _accountRepository.SaveAccountAsync(accountModel, cancellationToken);

            return accountModel;
        }

        private async Task<bool> ExistingAccountIsValidAsync()
        {
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            // double checks the account is still valid
            Account existingAccount;
            try
            {
                existingAccount = await _client.GetAccountAsync();
            }
            catch (AcmeRequestException exception)
            {
                _logger.LogWarning(
                    "An account key was found, but could not be matched to a valid account. Validation error: {acmeError}",
                    exception.Error);
                return false;
            }

            if (existingAccount.Status != AccountStatus.Valid)
            {
                _logger.LogWarning(
                    "An account key was found, but the account is no longer valid. Account status: {status}." +
                    "A new account will be registered.",
                    existingAccount.Status);
                return false;
            }

            _logger.LogInformation("Using existing account for {contact}", existingAccount.Contact);

            if (existingAccount.TermsOfServiceAgreed != true)
            {
                var tosUri = await _client.GetTermsOfServiceAsync();
                _tosChecker.EnsureTermsAreAccepted(tosUri);
                await _client.AgreeToTermsOfServiceAsync();
            }

            return true;
        }

        public async Task<X509Certificate2> CreateCertificateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            IOrderContext? orderContext = null;
            var orders = await _client.GetOrdersAsync();
            if (orders.Any())
            {
                var expectedDomains = new HashSet<string>(_options.Value.DomainNames);
                foreach (var order in orders)
                {
                    var orderDetails = await _client.GetOrderDetailsAsync(order);
                    if (orderDetails.Status != OrderStatus.Pending)
                    {
                        continue;
                    }

                    var orderDomains = orderDetails
                        .Identifiers
                        .Where(i => i.Type == IdentifierType.Dns)
                        .Select(s => s.Value);

                    if (expectedDomains.SetEquals(orderDomains))
                    {
                        _logger.LogDebug("Found an existing order for a certificate");
                        orderContext = order;
                        break;
                    }
                }
            }

            if (orderContext == null)
            {
                _logger.LogDebug("Creating new order for a certificate");
                orderContext = await _client.CreateOrderAsync(_options.Value.DomainNames);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var authorizations = await _client.GetOrderAuthorizations(orderContext);

            cancellationToken.ThrowIfCancellationRequested();
            await Task.WhenAll(BeginValidateAllAuthorizations(authorizations, cancellationToken));

            cancellationToken.ThrowIfCancellationRequested();
            return await CompleteCertificateRequestAsync(orderContext, cancellationToken);
        }

        private IEnumerable<Task> BeginValidateAllAuthorizations(IEnumerable<IAuthorizationContext> authorizations,
            CancellationToken cancellationToken)
        {
            foreach (var authorization in authorizations)
            {
                yield return ValidateDomainOwnershipAsync(authorization, cancellationToken);
            }
        }

        private async Task ValidateDomainOwnershipAsync(IAuthorizationContext authorizationContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            var authorization = await _client.GetAuthorizationAsync(authorizationContext);
            var domainName = authorization.Identifier.Value;

            if (authorization.Status == AuthorizationStatus.Valid)
            {
                // Short circuit if authorization is already complete
                return;
            }

            _logger.LogDebug("Requesting authorization to create certificate for {domainName}", domainName);

            cancellationToken.ThrowIfCancellationRequested();

            var validators = new List<DomainOwnershipValidator>();

            if (_tlsAlpnChallengeResponder.IsEnabled)
            {
                validators.Add(new TlsAlpn01DomainValidator(
                    _tlsAlpnChallengeResponder, _appLifetime, _client, _logger, domainName));
            }

            if (_options.Value.AllowedChallengeTypes.HasFlag(ChallengeType.Http01))
            {
                validators.Add(new Http01DomainValidator(
                    _challengeStore, _appLifetime, _client, _logger, domainName));
            }

            if (validators.Count == 0)
            {
                var challengeTypes = string.Join(", ", Enum.GetNames(typeof(ChallengeType)));
                throw new InvalidOperationException(
                    "Could not find a method for validating domain ownership. " +
                    "Ensure at least one kind of these challenge types is configured: " + challengeTypes);
            }

            foreach (var validator in validators)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await validator.ValidateOwnershipAsync(authorizationContext, cancellationToken);
                    // The method above raises if validation fails. If no exception occurs, we assume validation completed successfully.
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Validation with {validatorType} failed with error: {error}", validator.GetType().Name, ex.Message);
                }
            }

            throw new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
        }

        private async Task<X509Certificate2> CompleteCertificateRequestAsync(IOrderContext order,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            var commonName = _options.Value.DomainNames[0];
            _logger.LogDebug("Creating cert for {commonName}", commonName);

            var csrInfo = new CsrInfo
            {
                CommonName = commonName,
            };
            var privateKey = KeyFactory.NewKey((Certes.KeyAlgorithm)_options.Value.KeyAlgorithm);
            var acmeCert = await _client.GetCertificateAsync(csrInfo, privateKey, order);

            _logger.LogAcmeAction("NewCertificate");

            var pfxBuilder = acmeCert.ToPfx(privateKey);


            foreach (var additionalIssuersSource in _additionalIssuersSources)
            {
                var additionalIssuers = await additionalIssuersSource.GetAdditionalIssuersAsync(cancellationToken);
                foreach (var cert in additionalIssuers)
                {
                    pfxBuilder.AddIssuer(cert.RawData);
                }
            }

            var pfx = pfxBuilder.Build("HTTPS Cert - " + _options.Value.DomainNames, string.Empty);
            return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
        }
    }
}
