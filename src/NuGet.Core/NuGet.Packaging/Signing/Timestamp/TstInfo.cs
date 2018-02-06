// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NuGet.Packaging.Signing.DerEncoding;

namespace NuGet.Packaging.Signing
{
    /*
        From RFC 3161 (https://tools.ietf.org/html/rfc3161):

            TSTInfo ::= SEQUENCE  {
               version                      INTEGER  { v1(1) },
               policy                       TSAPolicyId,
               messageImprint               MessageImprint,
                 -- MUST have the same value as the similar field in
                 -- TimeStampReq
               serialNumber                 INTEGER,
                -- Time-Stamping users MUST be ready to accommodate integers
                -- up to 160 bits.
               genTime                      GeneralizedTime,
               accuracy                     Accuracy                 OPTIONAL,
               ordering                     BOOLEAN             DEFAULT FALSE,
               nonce                        INTEGER                  OPTIONAL,
                 -- MUST be present if the similar field was present
                 -- in TimeStampReq.  In that case it MUST have the same value.
               tsa                          [0] GeneralName          OPTIONAL,
               extensions                   [1] IMPLICIT Extensions   OPTIONAL  }

            TSAPolicyId ::= OBJECT IDENTIFIER
    */
    /// <remarks>This is public only to facilitate testing.</remarks>
    public sealed class TstInfo
    {
        public int Version { get; }
        public Oid Policy { get; }
        public MessageImprint MessageImprint { get; }
        public byte[] SerialNumber { get; }
        public DateTimeOffset GenTime { get; }
        public Accuracy Accuracy { get; }
        public bool Ordering { get; }
        public byte[] Nonce { get; } // big endian!
        public byte[] Tsa { get; }
        public X509ExtensionCollection Extensions { get; }

        private TstInfo(
            int version,
            Oid policy,
            MessageImprint messageImprint,
            byte[] serialNumber,
            DateTimeOffset genTime,
            Accuracy accuracy,
            bool ordering,
            byte[] nonce,
            byte[] tsa,
            X509ExtensionCollection extensions)
        {
            Version = version;
            Policy = policy;
            MessageImprint = messageImprint;
            SerialNumber = serialNumber;
            GenTime = genTime;
            Accuracy = accuracy;
            Ordering = ordering;
            Nonce = nonce;
            Tsa = tsa;
            Extensions = extensions;
        }

        public static TstInfo Read(byte[] bytes)
        {
            return Read(new DerSequenceReader(bytes));
        }

        internal static TstInfo Read(DerSequenceReader reader)
        {
            var version = reader.ReadInteger();
            var policy = reader.ReadOid();
            var messageImprint = MessageImprint.Read(reader);
            var serialNumber = reader.ReadIntegerBytes();

            if (serialNumber == null || serialNumber.Length == 0)
            {
                throw new CryptographicException(Strings.InvalidAsn1);
            }

            var genTime = reader.ReadGeneralizedTime();

            Accuracy accuracy = null;

            if (reader.HasTag(DerSequenceReader.ConstructedSequence))
            {
                accuracy = Accuracy.Read(reader);
            }

            var ordering = false;

            if (reader.HasTag(DerSequenceReader.DerTag.Boolean))
            {
                ordering = reader.ReadBoolean();
            }

            byte[] nonce = null;

            if (reader.HasTag(DerSequenceReader.DerTag.Integer))
            {
                nonce = reader.ReadIntegerBytes();
            }

            byte[] tsa = null;

            if (reader.HasData && reader.HasTag(DerSequenceReader.ContextSpecificConstructedTag0))
            {
                tsa = reader.ReadValue((DerSequenceReader.DerTag)DerSequenceReader.ContextSpecificConstructedTag0);
            }

            X509ExtensionCollection extensions = null;

            if (reader.HasData && reader.HasTag(DerSequenceReader.ContextSpecificConstructedTag1))
            {
                extensions = new X509ExtensionCollection();

                var rawExtensions = Signing.Extensions.Read(reader);

                foreach (var rawExtension in rawExtensions.ExtensionsList)
                {
                    extensions.Add(
                        new X509Extension(
                            rawExtension.Id,
                            rawExtension.Value,
                            rawExtension.Critical));
                }

                if (extensions.Count == 0)
                {
                    throw new CryptographicException(Strings.InvalidAsn1);
                }
            }

            if (reader.HasData)
            {
                throw new CryptographicException(Strings.InvalidAsn1);
            }

            return new TstInfo(
                version,
                policy,
                messageImprint,
                serialNumber,
                genTime.ToUniversalTime(),
                accuracy,
                ordering,
                nonce,
                tsa,
                extensions);
        }
    }
}