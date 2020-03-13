﻿// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Extensions for configuring certificate persistence
    /// </summary>
    public static class FileSystemStorageExtensions
    {
        /// <summary>
        /// Save Let's Encrypt data to a directory.
        /// Certificates are stored in the .pfx (PKCS #12) format in a subdirectory of <paramref name="directory"/>.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="directory">The root directory for storing information. Information may be stored in subdirectories.</param>
        /// <param name="pfxPassword">Set to null or empty for passwordless .pfx files.</param>
        /// <returns></returns>
        public static ILetsEncryptServiceBuilder PersistDataToDirectory(
            this ILetsEncryptServiceBuilder builder,
            DirectoryInfo directory,
            string? pfxPassword)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (directory is null)
            {
                throw new ArgumentNullException(nameof(directory));
            }

            var otherFileSystemRepoServices = builder
                .Services
                .Where(d => d.ServiceType == typeof(ICertificateRepository)
                && d.ImplementationInstance != null
                && d.ImplementationInstance.GetType() == typeof(FileSystemCertificateRepository));

            foreach (var serviceDescriptor in otherFileSystemRepoServices)
            {
                var otherRepo = (FileSystemCertificateRepository)serviceDescriptor.ImplementationInstance;
                if (otherRepo.RootDir.Equals(directory))
                {
                    if (otherRepo.PfxPassword != pfxPassword)
                    {
                        throw new ArgumentException($"Another file system repo has been configured for {directory}, but with a different password.");
                    }
                    return builder;
                }
            }

            var implementationInstance = new FileSystemCertificateRepository(directory, pfxPassword);
            builder.Services
                .AddSingleton<ICertificateRepository>(implementationInstance)
                .AddSingleton<ICertificateSource>(implementationInstance);
            return builder;
        }
    }
}
