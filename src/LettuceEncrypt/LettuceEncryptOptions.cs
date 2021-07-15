// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Acme;

namespace LettuceEncrypt
{
    /// <summary>
    /// Options for configuring an ACME server to automatically generate HTTPS certificates.
    /// </summary>
    public class LettuceEncryptOptions
    {
        private string[] _domainNames = Array.Empty<string>();
        private bool? _useStagingServer;

        /// <summary>
        /// The domain names for which to generate certificates.
        /// </summary>
        public string[] DomainNames
        {
            get => _domainNames;
            set => _domainNames = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Indicate that you agree with ACME server's terms of service.
        /// </summary>
        public bool AcceptTermsOfService { get; set; }

        /// <summary>
        /// The email address used to register with the certificate authority.
        /// </summary>
        public string EmailAddress { get; set; } = string.Empty;

        /// <summary>
        /// Use Let's Encrypt staging server.
        /// <para>
        /// This is recommended during development of the application and is automatically enabled
        /// if the hosting environment name is 'Development'.
        /// </para>
        /// </summary>
        public bool UseStagingServer
        {
            get => _useStagingServer ?? false;
            set => _useStagingServer = value;
        }

        internal bool UseStagingServerExplicitlySet => _useStagingServer.HasValue;

        /// <summary>
        /// A certificate to use if a certifcates cannot be created automatically.
        /// <para>
        /// This can be null if there is not fallback certificate.
        /// </para>
        /// </summary>
        public X509Certificate2? FallbackCertificate { get; set; }

        /// <summary>
        /// How long before certificate expiration will be renewal attempted.
        /// Set to <c>null</c> to disable automatic renewal.
        /// </summary>
        public TimeSpan? RenewDaysInAdvance { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// How often will be certificates checked for renewal
        /// </summary>
        public TimeSpan? RenewalCheckPeriod { get; set; } = TimeSpan.FromDays(1);

        /// <summary>
        /// The asymmetric algorithm used for generating a private key for certificates: RS256, ES256, ES384, ES512
        /// </summary>
        public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.ES256;

        /// <summary>
        /// Specifies which kinds of ACME challenges LettuceEncrypt can use to verify domain ownership.
        /// Defaults to <see cref="ChallengeType.Any"/>.
        /// </summary>
        public ChallengeType AllowedChallengeTypes { get; set; } = ChallengeType.Any;

    }
}
