using Kerberos.NET.Entities;
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Kerberos.NET.Server;

namespace KerberosLoopback;

class FakeTrustedRealms : ITrustedRealmService
{
    private readonly string currentRealm;

    public FakeTrustedRealms(string name)
    {
        this.currentRealm = name;
    }

    public IRealmReferral? ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context)
    {
        if (!tgsReq.Body.SName.FullyQualifiedName.EndsWith(this.currentRealm, StringComparison.InvariantCultureIgnoreCase) &&
            !tgsReq.Body.SName.FullyQualifiedName.Contains("not.found"))
        {
            return new FakeRealmReferral(tgsReq.Body);
        }

        return null;
    }
}
