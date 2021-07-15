// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines a source for certificates that will be accepted as issuers for generated certificates.
    /// </summary>
    public interface IAdditionalIssuersSource
    {

        /// <summary>
        /// Gets available a collection of certificates that will be accepted as issuers for generated certificates.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A collection of certificates</returns>
        Task<IEnumerable<X509Certificate2>> GetAdditionalIssuersAsync(CancellationToken cancellationToken);
    }
}
