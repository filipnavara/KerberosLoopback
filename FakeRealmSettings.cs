// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Kerberos.NET.Server;

namespace KerberosLoopback;

class FakeRealmSettings : IRealmSettings
{
    private readonly KerberosCompatibilityFlags compatibilityFlags;

    public FakeRealmSettings(KerberosCompatibilityFlags compatibilityFlags)
    {
        this.compatibilityFlags = compatibilityFlags;
    }

    public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

    public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

    public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);

    public KerberosCompatibilityFlags Compatibility => this.compatibilityFlags;
}
