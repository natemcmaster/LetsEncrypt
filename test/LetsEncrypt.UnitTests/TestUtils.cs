﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LetsEncrypt.UnitTests
{
    public class TestUtils
    {
        public static X509Certificate2 CreateTestCert(string commonName, DateTimeOffset? expires = null)
            => CreateTestCert(new[] { commonName }, expires);

        public static X509Certificate2 CreateTestCert(string[] domainNames, DateTimeOffset? expires = null)
        {
            expires ??= DateTimeOffset.Now.AddMinutes(10);
            var key = RSA.Create(2048);
            var csr = new CertificateRequest(
                "CN=" + domainNames[0],
                key,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);

            if (domainNames.Length > 1)
            {
                var sanBuilder = new SubjectAlternativeNameBuilder();
                foreach (var san in domainNames.Skip(1))
                {
                    sanBuilder.AddDnsName(san);
                }

                csr.CertificateExtensions.Add(sanBuilder.Build());
            }

            var cert = csr.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-1), expires.Value);
            // https://github.com/dotnet/runtime/issues/29144
            return new X509Certificate2(cert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }
    }
}
