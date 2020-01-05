﻿// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class CertificateSelector
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certs = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

        private readonly IOptions<LetsEncryptOptions> _options;

        public CertificateSelector(IOptions<LetsEncryptOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public ICollection<string> SupportedDomains => _certs.Keys;

        public virtual void Add(X509Certificate2 certificate)
        {
            var commonName = certificate.GetNameInfo(X509NameType.SimpleName, false);
            AddWithDomainName(commonName, certificate);

            foreach (var subjectAltName in X509CertificateHelpers.GetDnsFromExtensions(certificate))
            {
                AddWithDomainName(subjectAltName, certificate);
            }
        }

        private void AddWithDomainName(string domainName, X509Certificate2 certificate)
        {
            _certs.AddOrUpdate(domainName, certificate, (_, __) => certificate);
        }

        public X509Certificate2? Select(ConnectionContext features, string? domainName)
        {
            if (domainName == null || !_certs.TryGetValue(domainName, out var retVal))
            {
                return _options.Value.FallbackCertificate;
            }

            return retVal;
        }
    }
}
