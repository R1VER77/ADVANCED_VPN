# Terms of service

These terms govern your use of the cypherpunk_vpn software and, where
applicable, your participation in the project's community and mesh.
Because cypherpunk_vpn is free software rather than a service, most of
the conventional terms (subscription, billing, refunds, support) do not
apply; the terms that do apply are shorter and more honest than the
commercial alternative. The companion [PRIVACY_NOTICE.md](PRIVACY_NOTICE.md)
covers data; this document covers software, contributions and dispute.

## 1. The software, not a service

cypherpunk_vpn is free software published under
[AGPL-3.0-or-later](../LICENSE) with a dual-license commercial path.
The maintainer publishes the source; the maintainer does not operate a
VPN service. When you run cypherpunk_vpn, you are operating your own
VPN using the project's code. You are responsible for:

- the infrastructure you run it on (cloud accounts, hardware tokens,
  exit nodes, network egress);
- the laws of the jurisdictions in which your infrastructure sits
  ([path-selection design](PATH_SELECTION_DESIGN.md) makes this a
  first-class concern);
- the traffic that leaves your exit (see [the threat model](cli/threat-model.md)
  for what an exit operator can see);
- the costs you incur (cover-traffic bandwidth, hardware tokens, cloud
  bills — [FUNDING.md](FUNDING.md) records the maintainer's standing
  on costs).

There is no subscription, no automatic renewal, no billing cycle, no
refund policy and no support contract. If you contributed funding
voluntarily, that contribution is governed by [FUNDING.md](FUNDING.md)
and is not a purchase.

## 2. License

The software is licensed under AGPL-3.0-or-later. Read
[LICENSE](../LICENSE) for the full text and the dual-license
commercial path. The summary:

- **You may** run, study, modify and redistribute the software, with or
  without modification, for any purpose.
- **You must** preserve the AGPL license on downstream copies, and
  under §13, if you run a modified version as a network service
  (including a commercial VPN service, mesh relay, or cloud exit), you
  must offer all network participants prominent access to the
  corresponding source code at no charge.
- **You may not** impose further restrictions on the rights granted by
  AGPL, including in the form of proprietary license terms on
  downstream code that incorporates this software.
- **Commercial licenses** are available from the maintainer for
  enterprises and OEMs that require closed-source deployment. Contact
  the maintainer via the project's issue tracker.

## 3. No warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
The maintainer does not warrant that the software will function
uninterrupted, error-free, or in a way that defeats any specific
adversary.

The [SECURITY.md](../SECURITY.md) file honestly states what this
release does and does not protect against. Of particular note:

- The traffic-analysis defenses are measured against published attacks
  but are not independent evaluations; residual leakage is documented
  in [WF_REAL_RERUN3.md](WF_REAL_RERUN3.md).
- A free-tier server stops forwarding when its monthly cap is reached
  ([FEE_GUARD.md](FEE_GUARD.md)); Fly.io has no hard spending limit.
- No hardware attestation is implemented; the descriptor attestation
  roadmap is in [ROADMAP.md](ROADMAP.md).
- One owner running every hop can correlate the chain end to end; more
  hops under one operator are not anonymity from that operator.
- The cloak's server authentication is the project's composition, with
  regression and mutation tests but not an independent review.
- Endpoint root/host memory inspection is outside the protection
  boundary.

You accept these limitations by running the software. If you need
stronger assurance than this project provides, do not run it; use a
commercial VPN that publishes independent audit results, or do not use
a VPN at all.

## 4. Limitation of liability

To the maximum extent permitted by applicable law, neither the
maintainer nor any contributor is liable for any direct, indirect,
incidental, special, consequential or punitive damages, or any loss of
data, revenue or profit, arising from your use of or inability to use
the software — even if advised of the possibility of such damages.

This limitation reflects the fact that the software is free, the
maintainer receives no payment from you for it, and the burden of
evaluating its fitness for your purpose rests with you. If you require
a liability surface, purchase a commercial license and the
corresponding support contract; the AGPL path provides no such surface.

## 5. Acceptable use

The software is general-purpose networking infrastructure. You may
use it for any lawful purpose. You may not use it in a way that:

- violates the law of the jurisdiction in which your infrastructure
  sits (this is your responsibility to determine, not the project's to
  police);
- infringes the rights of others, including through the distribution of
  content you do not have the right to distribute;
- attempts to disrupt the project's infrastructure (issue tracker,
  signed-commit verification, release distribution).

The project does not monitor your traffic. The project cannot terminate
your use, because there is no account to terminate and no service to
cut. If your behaviour in the project's community spaces (issues, pull
requests) violates the [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md), the
maintainer may ban you from those spaces; this does not affect your
right to use the software under AGPL.

## 6. Contributions

Contributions are governed by [CONTRIBUTING.md](../CONTRIBUTING.md).
Inbound contributions are licensed under AGPL-3.0-or-later on the same
terms as the project (inbound = outbound). You retain your copyright;
you grant the project a license under AGPL. Sign your commits (SSH or
OpenPGP); see [SIGNED_REPOSITORY.md](SIGNED_REPOSITORY.md).

The maintainer decides acceptance and records unresolved objections.
Disagreements are resolved on the merits of the code and evidence, not
the credentials of the contributor.

## 7. Indemnification

To the maximum extent permitted by law, you agree to indemnify the
maintainer and contributors against any claims, losses or damages
arising from your use or misuse of the software, your distribution of
the software to others, or your operation of infrastructure using the
software. This is the symmetric counterpart of §4: you accept the
liability for what you do with the software in exchange for receiving
it without paying for it.

## 8. Dispute resolution

There is no arbitration agreement, no class-action waiver, and no
mandatory forum. There is also no entity to arbitrate with. If you have
a complaint, the path is:

1. Open an issue. Most concerns are resolved by discussion.
2. If the issue is a security vulnerability, follow
   [SECURITY.md](../SECURITY.md) and report privately.
3. If you believe the maintainer has violated the project's
   [PRINCIPLES.md](PRINCIPLES.md) or [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md),
   raise it publicly; the maintainer's decisions are recorded in
   [DECISIONS.md](DECISIONS.md) and can be reopened by new evidence.
4. If none of the above resolves your concern and you believe you have
   a legal claim against the maintainer personally, open an issue asking
   for a service address. Be aware that there is nothing to seize and no
   data to compel — see [PRIVACY_NOTICE.md](PRIVACY_NOTICE.md) §7.

The project does not consent to jurisdiction in any specific forum
because the project is not a legal person. The maintainer's personal
jurisdiction is determined by residence, not by these terms.

## 9. Export control

The software is publicly available open-source code that uses
encryption. Whether exporting it needs a notification or licence
depends on where you are; that check is yours. You may not export, re-export or use the software in
violation of any applicable sanctions regime, including the regimes
administered by the US Department of the Treasury's Office of Foreign
Assets Control, the European Union, the United Kingdom, or any other
jurisdiction in which you operate. The software is not intended for
use by any person or entity on any sanctions list.

## 10. Third-party content

The software depends on third-party libraries, each under their own
license. The full provenance is in [third_party/SOURCES.json](../third_party/SOURCES.json)
and [docs/PROVENANCE.md](PROVENANCE.md). The project does not host
third-party content beyond what is necessary to build the software.

## 11. Termination

Your license to use the software under AGPL is irrevocable, subject to
your continued compliance with AGPL's terms. The maintainer cannot
terminate your license because the maintainer does not control the
software — you have a copy, and AGPL grants you the rights
independently of the maintainer's continued involvement.

If the maintainer stops maintaining the project, the AGPL license
survives. The signed-commit history and the public repository are the
project; the maintainer's continued attention is convenient but not
load-bearing.

## 12. Changes to these terms

Changes are made by signed commit. Material changes (changes to the
license terms, the liability caps, the indemnification, the dispute
clause) are recorded in [CHANGELOG.md](../CHANGELOG.md) and in
[DECISIONS.md](DECISIONS.md) with the reason. The git history of this
file is the canonical version control; no separate change log is
maintained.

## 13. Comparison to commercial VPN terms

The conventional commercial VPN terms of service — like
[OVPN's](https://www.ovpn.com/en/tos) or NordVPN's or ExpressVPN's —
typically run to thousands of words covering subscription, billing,
automatic renewal, refund policy, mandatory binding arbitration with a
class-action waiver, indemnification, export controls and limitation of
liability. Those terms exist because those products are paid services
with a customer relationship.

This project has no customer relationship. The terms above are the
honest minimum: license, no warranty, limitation of liability,
acceptable use, indemnification, no forum. If a future version of the
project forms a paid service or operating entity, those terms would be
added at that time, with a separate document for the service layer and
these terms retained for the software layer.

## 14. Local Gemma troubleshooting assistant

The optional `cypherpunk-vpn-assistant` package includes Google's Gemma 3 1B
model (`gemma-3-1b-it-Q8_0.gguf`) so the desktop app can explain setup or
server failures locally on your own computer without sending logs over the
network. Gemma is provided under and subject to the Gemma Terms of Use found at
`https://ai.google.dev/gemma/terms` and the Gemma Prohibited Use Policy found
at `https://ai.google.dev/gemma/prohibited_use_policy`. By installing or using
the optional assistant package, you agree not to use the bundled Gemma model in
violation of the Gemma Terms of Use or the Gemma Prohibited Use Policy. The
rest of `cypherpunk_vpn` remains free software under AGPL-3.0-or-later and
works in full without the assistant package.
