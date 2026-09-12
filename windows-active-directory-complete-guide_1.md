# Windows Active Directory — Complete Structural Guide

*A module-by-module breakdown, from logical structure through authentication, Group Policy, trusts, and the security model.*

---

## How this guide is organized

Each module builds on the one before it. Modules 1–7 are the **skeleton** (what AD looks like and how the pieces fit together). Modules 8–11 are the **mechanics** (how logon, permissions, policy, and cross-domain access actually work). Modules 12–15 are **operations** (running it, securing it, keeping it alive).

## Table of Contents

- Module 0 — Foundational Concepts
- Module 1 — Logical Structure: Forests, Trees, Domains
- Module 2 — Organizational Units & Containers
- Module 3 — AD Objects & Schema
- Module 4 — Physical Structure: Sites, Subnets, Domain Controllers
- Module 5 — Replication
- Module 6 — FSMO Roles
- Module 7 — DNS Integration
- Module 8 — Authentication: Kerberos & NTLM
- Module 9 — Authorization: Security Principals & ACLs
- Module 10 — Group Policy
- Module 11 — Trusts
- Module 12 — Administration Tools
- Module 13 — Security Model & Hardening
- Module 14 — Backup, Recovery & High Availability
- Module 15 — Hybrid Identity (Azure AD / Entra ID)
- Appendix — Cheat Sheets

---

## Module 0 — Foundational Concepts

**What AD actually is:** a distributed database (the directory) plus a set of services that use it — authentication, authorization, and policy distribution. It's Microsoft's implementation of a directory service, built primarily on three protocols:

| Protocol | Role in AD |
|---|---|
| **LDAP** (389/636) | The query/update language for reading and writing directory objects |
| **Kerberos** (88) | The primary authentication protocol |
| **DNS** (53) | How every AD-aware machine *finds* domain controllers — AD cannot function without it |

**The database itself** lives in a file called `NTDS.dit` on every domain controller (DC), stored in a JET/ESE database. It holds every object and attribute in that DC's domain (plus a partial read-only copy of every object forest-wide, called the Global Catalog — more in Module 4).

**Core vocabulary you'll use constantly:**
- **Object** — anything stored in AD: a user, computer, group, printer, GPO, OU.
- **Attribute** — a property of an object (e.g., a user object has `sAMAccountName`, `memberOf`, `pwdLastSet`).
- **Schema** — the master definition of every object class and attribute that *can* exist in the forest. One schema per forest.
- **Namespace** — the DNS-based naming convention AD uses (`corp.example.com`).
- **Security principal** — any object that can be authenticated and granted permissions: users, computers, and groups.

Everything from here is really just: *how are these objects organized, how do they talk to each other, and how does trust flow between them.*

---

## Module 1 — Logical Structure: Forests, Trees, Domains

This is the "org chart" of AD — it exists independently of physical geography.

```
Forest: contoso.com
│
├── Tree: contoso.com
│   ├── Domain: contoso.com          (forest root domain)
│   │   └── Domain: emea.contoso.com  (child domain — shares contoso.com namespace)
│   └── Domain: apac.contoso.com      (child domain)
│
└── Tree: fabrikam.com                (2nd tree — different namespace, same forest)
    └── Domain: fabrikam.com
```

**Domain** — the fundamental administrative and security boundary.
- Defines a shared security policy (default password policy, Kerberos policy).
- Defines a replication boundary — every DC in a domain holds a full writable copy of *that domain's* objects.
- Identified by a DNS name (`contoso.com`).
- Every domain automatically gets a `krbtgt` account (used to encrypt Kerberos tickets) and default groups (Domain Admins, Domain Users, etc.).

**Tree** — one or more domains that share a contiguous DNS namespace, linked by automatic two-way transitive trust (parent ↔ child). `contoso.com` → `emea.contoso.com` is a tree.

**Forest** — the actual top-level security boundary in AD (not the domain — a common misconception). One forest can contain multiple trees with *different* namespaces (`contoso.com` and `fabrikam.com` can coexist in one forest). Everything in a forest shares:
- One **schema** (object/attribute definitions)
- One **Configuration partition** (sites, replication topology, services config)
- One **Global Catalog**
- Automatic transitive trust between all domains in the forest

**Design implications:**
- **Single-domain forest** — simplest to administer, no internal trust management, fine for most orgs (this is the modern default recommendation).
- **Multi-domain forest** — historically used to isolate replication traffic, apply different domain-wide policies, or reflect a merger/acquisition. Adds real administrative overhead (each domain needs its own DCs, its own FSMO domain-wide roles, its own DNS zone) for benefits that OUs + fine-grained password policies can usually now deliver instead.
- **Multi-forest** — used when you need a *hard* security boundary (the forest, not the domain, is the true trust/isolation boundary in AD — a Domain Admin in one domain can, with effort, compromise the entire forest via the Configuration partition and FSMO structure). Common in regulated environments, or after acquisitions where you don't want two companies fully trusting each other by default.

---

## Module 2 — Organizational Units & Containers

**OUs are for administration, not security boundaries.** This trips people up constantly: an OU is *not* a security boundary like a domain is. Its two real jobs:

1. **Delegation** — grant specific rights over an OU's contents to specific groups (e.g., let the Helpdesk group reset passwords only for users in `OU=Sales`) without adding anyone to Domain Admins.
2. **GPO linking** — Group Policy Objects are linked to OUs to scope which computers/users receive which settings.

**OU vs. Container** — easy to confuse:
- **Containers** (`CN=Users`, `CN=Computers`) are built-in default locations for new accounts. You **cannot** link a GPO directly to them, and delegation is more limited.
- **OUs** (`OU=...`) are the objects you actually create and structure your environment around. Best practice: redirect new user/computer creation out of the default containers into proper OUs (`redirusr`/`redircmp`) so GPOs and delegation apply correctly from day one.

**Common OU design patterns:**
- **Functional/departmental** — `OU=Finance`, `OU=Engineering`, `OU=HR` — mirrors the org chart. Good when policy varies by department.
- **Geographic** — `OU=US`, `OU=EMEA`, `OU=APAC` — good when policy varies by region (legal/compliance requirements, language, local IT teams).
- **Object-type first** — top-level split by `OU=Users`, `OU=Computers`, `OU=Servers`, `OU=Groups`, then subdivided — this is the most common modern approach because it lines up cleanly with how GPOs and delegation actually get applied (you rarely want the *same* policy logic for a department's people and its servers).
- **Tiered (security-first)** — separates OUs by privilege tier (Tier 0 = DCs and their admin accounts, Tier 1 = servers, Tier 2 = workstations/users) — covered more in Module 13. Increasingly the recommended baseline specifically *because* it constrains lateral movement.

A nested example:
```
OU=Corp
├── OU=Tier0-DomainControllers
├── OU=Servers
│   ├── OU=SQL
│   └── OU=Web
├── OU=Workstations
│   ├── OU=Laptops
│   └── OU=Desktops
└── OU=Users
    ├── OU=Finance
    ├── OU=Engineering
    └── OU=Disabled-Accounts
```

---

## Module 3 — AD Objects & Schema

**Security principals** — objects that can authenticate or be granted permissions:

| Object | Notes |
|---|---|
| **User** | Has a password/credential, a unique SID, and a UPN (`user@corp.example.com`) |
| **Computer** | Effectively a user account for the machine itself — has its own SID, password (auto-rotated every 30 days by default), used for machine-level authentication |
| **Group** | A container of other principals, used to assign permissions/rights in bulk |

**Group types:**
- **Security groups** — can be used both for permissions (ACLs) *and* email distribution.
- **Distribution groups** — email-only, cannot be used in an ACL. (Not a security principal — has no SID.)

**Group scopes** (the part people mix up most):

| Scope | Can contain members from | Can be used for permissions | Replication note |
|---|---|---|---|
| **Domain Local** | Any domain in the forest, or trusted domains | Only within its own domain | Membership stored locally |
| **Global** | Only its own domain | Anywhere in the forest (with a trust) | Membership stored locally |
| **Universal** | Any domain in the forest | Anywhere in the forest | Membership replicated to the **Global Catalog** forest-wide — so frequently-changing universal groups generate more replication traffic |

Classic nesting pattern (Microsoft's "AGDLP" / "AGUDLP"): put **A**ccounts into **G**lobal groups, put Global groups into **D**omain **L**ocal groups, assign **P**ermissions to the Domain Local group. (Insert **U**niversal groups in the middle if you're spanning multiple domains in a forest.)

**Other object types:** Contacts (no logon capability, just directory info — e.g., for email routing), Printers, Shared Folders, GPOs (stored as objects too — see Module 10), and **OUs** themselves (technically objects).

**Schema:**
- Forest-wide, single source of truth for every object class (`user`, `computer`, `group`...) and every attribute (`sAMAccountName`, `mail`, `description`...) that can exist.
- Extending the schema (e.g., when Exchange or SCCM installs) is a one-way, forest-wide, replicated operation — deletion of a schema attribute isn't really possible, only deactivation. This is why schema changes require the Schema Admins group and are done deliberately.

**Identifiers:**
- **SID** (Security Identifier) — uniquely identifies a security principal, used in tokens and ACLs. Format: `S-1-5-21-<domain-id>-<RID>`. The last part (RID) is what makes it unique within the domain.
- **GUID** — a truly immutable, forest-unique identifier for *any* object (survives renames, moves, even domain moves), used internally for replication.
- **DN** (Distinguished Name) — the full LDAP path, e.g. `CN=Jane Doe,OU=Finance,DC=corp,DC=example,DC=com`.

---

## Module 4 — Physical Structure: Sites, Subnets, Domain Controllers

This is the layer that maps AD onto your actual network/geography — independent of the logical (domain/OU) structure above.

```
Site: HQ-Site        (Subnets: 10.0.0.0/24, 10.0.1.0/24)
  └── DC1 (Global Catalog), DC2
            │
            │  Site Link "HQ-Branch"  (cost: 100, replicates every 180 min)
            │
Site: Branch-Site    (Subnet: 10.1.0.0/24)
  └── DC3 (RODC)
```

**Site** — a set of well-connected IP subnets (usually = one physical location). Sites exist to control two things:
1. **Logon locality** — a client authenticates against the *closest* DC (same site) rather than crawling the WAN to a DC across the world.
2. **Replication scheduling** — replication *within* a site is fast/frequent (near real-time); replication *between* sites is scheduled and compressed to conserve WAN bandwidth.

**Subnet objects** — you register your IP subnets and associate each with a site, so AD knows which site any given client belongs to based on its IP.

**Domain Controller (DC)** — a server holding a writable copy of its domain's partition, running Kerberos/LDAP services. All DCs are (by default) peers — multi-master (Module 5).

**Global Catalog (GC)** — a DC additionally holding a *partial, read-only* copy of every object in every domain in the forest (a subset of attributes — the ones most commonly searched). Needed for:
- Forest-wide searches (e.g., "find this user" without knowing which domain they're in)
- Universal group membership resolution during logon
- UPN logon resolution across domains

**RODC (Read-Only Domain Controller)** — a DC that holds a read-only copy of the database and, by default, caches *no* user passwords at all (only the passwords of accounts explicitly allowed via its Password Replication Policy). Designed for locations with weaker physical security (branch offices) where a stolen DC shouldn't hand over the keys to the domain.

---

## Module 5 — Replication

AD is **multi-master**: any writable DC can accept a change, and that change then propagates to every other DC. (A handful of operations are still single-master — see FSMO, Module 6.)

**How DCs know what to replicate:**
- Every DC keeps an internal counter, the **USN** (Update Sequence Number), incremented on every local write.
- Each DC tracks the highest USN it has already received *from* every other DC (an "up-to-dateness vector"). When it replicates, it only asks for changes above that watermark — so it never re-pulls something it already has.
- **Conflict resolution** (rare, but happens with simultaneous writes on two DCs) is resolved by attribute-version-number, then by timestamp, then by originating-server GUID as a final tiebreaker.

**Topology:**
- The **KCC** (Knowledge Consistency Checker), running on every DC, automatically builds a replication topology — a ring within each site so no single DC failure cuts off replication.
- Between sites, the **ISTG** (Inter-Site Topology Generator) selects **bridgehead servers** per site to carry inter-site replication traffic, following whatever **Site Links** and costs you've configured (cost = preference; lower cost = preferred path).
- Intra-site replication is near-instant (change notification fires within ~15 seconds, then a few seconds between each subsequent partner). Inter-site replication is scheduled (commonly every 15 min–3 hrs depending on link config) and compressed.

**SYSVOL** — a shared folder (`\\domain\SYSVOL`) on every DC holding Group Policy templates and login scripts. It's replicated separately from the NTDS.dit database, using **DFSR** (Distributed File System Replication) on modern domains — the legacy **FRS** (File Replication Service) was deprecated years ago and shouldn't appear in any current build.

---

## Module 6 — FSMO Roles

Five operations in AD are too risky to be fully multi-master, so each is pinned to exactly one DC at a time — the **FSMO** (Flexible Single Master Operations) roles.

**Forest-wide (one each, per forest):**

| Role | Job | If it's offline |
|---|---|---|
| **Schema Master** | Only DC that can process schema changes | No new schema changes (rare operation anyway) — no immediate day-to-day impact |
| **Domain Naming Master** | Only DC that can add/remove domains from the forest | Can't add/remove domains — no day-to-day impact |

**Domain-wide (one each, *per domain*):**

| Role | Job | If it's offline |
|---|---|---|
| **RID Master** | Allocates blocks of RIDs to every DC in the domain, which DCs use to mint new SIDs for new objects | DCs eventually exhaust their local RID pool and can't create new security principals |
| **PDC Emulator** | Time sync source for the domain, authoritative for password changes/lockouts, processes urgent password changes ahead of normal replication, GPO edit conflict authority, NT4 BDC emulation | Password changes/lockout info can be briefly inconsistent across DCs; time sync issues can cascade into Kerberos failures (Kerberos is time-sensitive — default 5 min skew tolerance) |
| **Infrastructure Master** | Keeps cross-domain object references (e.g., a group in Domain A containing a user from Domain B) up to date after that user is renamed/moved | Stale group-membership *display* info across domains (rarely user-visible for long) |

**Placement rule of thumb:** Infrastructure Master should **not** sit on a Global Catalog server (unless every DC in the domain is also a GC, or it's a single-domain forest) — otherwise it never detects out-of-date references, since GCs already know about every object forest-wide.

**Transfer vs. seize:** a graceful **transfer** is done when the current role holder is online (via `Move-ADDirectoryServerOperationMasterRole` or `ntdsutil`). A **seizure** is the forceful last-resort option when the role holder is permanently gone — the old holder must never be brought back online afterward without being rebuilt, or you risk two DCs believing they hold the same single-master role (a "USN rollback"-style split-brain).

---

## Module 7 — DNS Integration

AD *cannot function* without DNS — it's not optional infrastructure, it's the mechanism clients use to even find a domain controller in the first place.

**AD-integrated zones** — DNS zone data stored *inside* AD itself (as objects, replicated via normal AD replication) rather than in flat zone files. Gives you multi-master DNS updates and automatic replication for free.

**SRV records — how a client actually finds a DC:** when a machine needs to log on, it doesn't have a DC's address hardcoded — it queries DNS for service (SRV) records like:
```
_ldap._tcp.dc._msdcs.corp.example.com
_kerberos._tcp.dc._msdcs.corp.example.com
```
These return the hostnames of DCs offering that service, and — critically — the client can request records scoped to its own **site**, so it prefers a local DC over a distant one. This is the `_msdcs` zone you'll see in every AD DNS setup, and it's what ties Module 4 (sites) directly to real client behavior.

---

## Module 8 — Authentication: Kerberos & NTLM

**Kerberos** is the default, preferred protocol. Walkthrough (the KDC — Key Distribution Center — runs on every DC):

```
Client                              KDC (on a DC)                    Target Server
  │  1. AS-REQ (username +          │                                     │
  │     timestamp encrypted         │                                     │
  │     with password hash)         │                                     │
  │ ───────────────────────────────>│                                     │
  │  2. AS-REP: TGT (encrypted      │                                     │
  │     with krbtgt's hash) +       │                                     │
  │     session key                 │                                     │
  │ <───────────────────────────────│                                     │
  │  3. TGS-REQ (present TGT,       │                                     │
  │     ask for a ticket to a       │                                     │
  │     specific service/SPN)       │                                     │
  │ ───────────────────────────────>│                                     │
  │  4. TGS-REP: service ticket     │                                     │
  │     (encrypted with the         │                                     │
  │     *service account's* hash)   │                                     │
  │ <───────────────────────────────│                                     │
  │  5. AP-REQ — present service ticket directly to the server ──────────>│
  │  6. (mutual auth, optional) AP-REP  <──────────────────────────────────│
```

- **TGT** (Ticket Granting Ticket) — proof you authenticated, valid for the domain (default 10 hrs, renewable up to 7 days). Encrypted with the domain's `krbtgt` account password hash — this is why that single account's hash is such a high-value target (Module 13).
- **Service ticket** — encrypted with the *target service account's* password hash, so only that service can decrypt and trust it.
- **PAC** (Privilege Attribute Certificate) — embedded in the tickets, carries the user's SID and group memberships, digitally signed by the KDC, so the target server can make authorization decisions without a separate directory lookup.
- Kerberos is **time-sensitive** — by default, a 5-minute clock skew between client and KDC will hard-fail authentication, which is exactly why the PDC Emulator's time-sync role (Module 6) matters.

**NTLM** is the legacy fallback — used when Kerberos isn't possible (e.g., authenticating by raw IP instead of hostname, non-domain workgroup auth, or older applications hardcoded to it). It's a challenge-response protocol that never presents Kerberos's mutual-authentication or delegation benefits, and modern hardening guidance is to **restrict/disable NTLM** wherever legacy compatibility doesn't require it.

**LDAP binds** — separately, when an application queries the directory itself (not logging a user on, but *searching* AD), it does so via an LDAP "bind." A **simple bind** sends credentials in the clear unless wrapped in TLS (LDAPS, port 636) — a common hardening item is enforcing **LDAP signing/channel binding** to prevent relay attacks against unsigned LDAP traffic.

---

## Module 9 — Authorization: Security Principals & ACLs

Authentication proves *who you are*; this module is *what you're allowed to touch*.

- **Access token** — created at logon, contains your user SID, every group SID you belong to (including nested groups), and your assigned privileges (like "Back up files and directories"). This token is what gets checked against every object you try to access.
- **Well-known SIDs worth knowing:** `S-1-1-0` (Everyone), `S-1-5-11` (Authenticated Users), and domain-relative ones like RID `500` (built-in Administrator), `502` (krbtgt), `512` (Domain Admins), `518` (Schema Admins), `519` (Enterprise Admins).
- **DACL** (Discretionary Access Control List) — the list of Access Control Entries (ACEs) on an object that determine who can do what (read, write, delete, "extended rights" like reset-password). Most day-to-day permission questions in AD ("why can this helpdesk group reset passwords in this OU but not that one") are DACL questions.
- **SACL** (System Access Control List) — controls *auditing*, not access — defines which actions on the object get logged to the Security event log.
- **Inheritance** — ACEs can flow down from a parent container (a domain, or an OU) to everything beneath it, unless explicitly blocked on a child object. This is the technical mechanism behind OU-level delegation from Module 2.
- **Effective permissions** are the union of everything your token's SIDs are granted, minus anything explicitly denied (an explicit Deny always wins over an Allow, at any level).

---

## Module 10 — Group Policy

A **GPO** (Group Policy Object) is itself two linked pieces: the **GPC** (Group Policy Container, an AD object holding version info and links) and the **GPT** (Group Policy Template, the actual settings files, stored in SYSVOL — this is why SYSVOL replication in Module 5 matters so much).

**Linking** — a GPO does nothing until it's *linked* to a Site, Domain, or OU. One GPO can be linked in multiple places; one container can have multiple GPOs linked to it.

**Processing order — remember "LSDOU":**
1. **L**ocal Group Policy (on the machine itself)
2. **S**ite
3. **D**omain
4. **O**U (outermost OU first, working inward to the OU that actually contains the object)

Later-processed settings win on conflict — so the OU closest to the actual user/computer object normally has the final say.

**Modifiers to that default:**
- **Block Inheritance** (set on a domain or OU) — stops GPOs linked *above* it from applying, **except**:
- **Enforced** (set on a GPO link) — forces that GPO to apply regardless of Block Inheritance anywhere below it. Enforced + Block Inheritance is a common combination for security baselines that must never be overridden by a lower-level admin.
- **Security filtering** — restricts a linked GPO to only apply to specific security groups (technically: requires both Read and Apply Group Policy permissions on the GPO).
- **WMI filtering** — conditionally applies a GPO based on a query against the target machine (e.g., "only if this is a laptop," "only if OS = Windows 11").
- **Loopback processing** (Merge or Replace mode) — makes *user*-side settings apply based on the *computer's* OU rather than the user's own OU. The classic use case is kiosks/terminal servers/conference-room PCs where you want consistent behavior regardless of who logs in.

---

## Module 11 — Trusts

A trust lets security principals in one domain be authenticated/authorized to access resources in another.

| Trust type | Transitivity | Direction | Created |
|---|---|---|---|
| **Parent-Child** | Transitive | Two-way | Automatic (when a child domain is created) |
| **Tree-Root** | Transitive | Two-way | Automatic (when a new tree is added to a forest) |
| **Shortcut** | Transitive | One- or two-way | Manual — optimizes the authentication *path* between two domains that are otherwise many hops apart in a large forest |
| **External** | Non-transitive | One- or two-way | Manual — connects to a specific domain outside the forest (or a legacy NT4 domain) |
| **Forest** | Transitive (within the two forests) | One- or two-way | Manual — connects two entire forests |
| **Realm** | Transitive or non-transitive | One- or two-way | Manual — connects to a non-Windows Kerberos realm (e.g., an MIT Kerberos or Unix environment) |

**Direction matters and is easy to get backwards:** if Domain A trusts Domain B, users **from B** can access resources **in A** — the trust "points" toward the domain whose users are being trusted-into. (Mnemonic: trust flows opposite to access — the *trusting* domain is the one giving up control.)

**SID filtering** is enabled by default on external and forest trusts — it strips out SID-history-based claims that don't correspond to the trusted domain, specifically to prevent a compromised trusted domain from forging membership in a highly privileged group of yours.

---

## Module 12 — Administration Tools

| Tool | Use |
|---|---|
| **Active Directory Users and Computers** (`dsa.msc`) | The classic GUI for day-to-day object management |
| **Active Directory Administrative Center** (`dsac.exe`) | Newer GUI, exposes fine-grained password policies, Recycle Bin, PowerShell history pane |
| **ADSI Edit** (`adsiedit.msc`) | Raw, low-level LDAP editor — direct attribute editing, used for things the GUI tools hide |
| **Sites and Services** (`dssite.msc`) | Manage sites, subnets, site links, replication schedules |
| **PowerShell `ActiveDirectory` module** | Scriptable management — `Get-ADUser`, `New-ADUser`, `Add-ADGroupMember`, `Get-ADComputer`, `Get-ADDomainController`, `Get-ADForest`, `Get-ADTrust`, `Get-ADReplicationSite`, `Set-ADAccountPassword` |
| **`repadmin`** | Replication diagnostics — `repadmin /replsummary`, `repadmin /showrepl` |
| **`dcdiag`** | Overall DC health check — `dcdiag /v` for verbose output |
| **`nltest`** | Trust/DC discovery — `nltest /dsgetdc:domain`, `nltest /domain_trusts` |
| **`ntdsutil`** | Low-level database maintenance, FSMO seizure, offline defrag |
| **`setspn`** | View/manage Service Principal Names (relevant to Kerberos delegation, Module 13) |
| **`klist`** | View cached Kerberos tickets on the local session |

---

## Module 13 — Security Model & Hardening

*(Framed at the awareness/defensive level — mechanisms and mitigations, since these matter directly for your work.)*

**The Tiered Administration Model** is the foundational hardening concept in modern AD guidance:
- **Tier 0** — domain controllers, and anything that can control them: Domain Admins, Enterprise Admins, Schema Admins, any account with replication rights, any account whose credentials get cached on a DC.
- **Tier 1** — member servers and the apps running on them.
- **Tier 2** — workstations, help-desk-level access.

The rule that actually matters: **never log a higher-tier credential onto a lower-tier machine.** A Domain Admin logging into a regular workstation to "just fix something quickly" caches credential material on that workstation — and workstations are the most-exposed, most-frequently-compromised tier. Most real-world domain compromises follow exactly this path: compromise a workstation → wait for/harvest a privileged credential that touched it → escalate to Tier 0.

**Built-in privileged groups worth knowing the blast radius of:** Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators (can back up/restore *anything*, including the entire AD database), Server Operators, DNS Admins (can load an arbitrary DLL into the DNS service running on a DC — a frequently-cited privilege-escalation path).

**Delegation of control** (Module 2) exists specifically so you rarely *need* to add anyone to those groups — grant the narrow permission (e.g., reset-password on one OU) directly instead.

**Attack classes worth understanding conceptually** (mechanism + why it's mitigated the way it is — not operational steps):

| Attack class | Mechanism | Primary mitigation |
|---|---|---|
| **Kerberoasting** | Any authenticated user can request a service ticket for any account with a registered SPN; that ticket is encrypted with the *service account's* password hash and can be taken offline for cracking | Long, random service-account passwords; use **gMSAs** (Group Managed Service Accounts) with automatically rotated 120+ character passwords |
| **AS-REP Roasting** | If an account has "Do not require Kerberos pre-authentication" set, its AS-REP can be requested without any credential and cracked offline | Keep pre-auth enabled (the default); strong passwords as a backstop |
| **Unconstrained delegation abuse** | A server configured for unconstrained delegation retains a copy of *every* client TGT that authenticates to it — compromising that server can yield tickets for anyone who logged in | Use constrained or resource-based constrained delegation instead; never leave unconstrained delegation on internet-facing or easily-compromised hosts |
| **DCSync** | Replication rights ("Replicating Directory Changes" + "...All") let a principal request directory data *as if it were a DC* — normally reserved for Domain Admins and the replication service itself | Tightly audit who/what holds these rights; monitor for the specific access via Event ID 4662 |
| **Pass-the-Hash** | NTLM authentication only requires the password *hash*, not the plaintext — a captured hash can be replayed directly | Restrict/disable NTLM where feasible; Credential Guard; unique local admin passwords via **LAPS** |
| **Golden/Silver Tickets** | TGTs are encrypted with the `krbtgt` account's hash — if that hash is ever stolen, an attacker can forge valid TGTs indefinitely (Golden); a Silver Ticket does the same for one service using a stolen service-account hash | Rotate `krbtgt` password twice, with a replication-convergence gap between rotations (a known, published remediation step); monitor for anomalous ticket lifetimes/encryption types |

**Monitoring basics** — key Security-log Event IDs worth alerting on: `4768`/`4769` (TGT/service ticket requests — volume spikes are a Kerberoasting indicator), `4662` (object access, filterable to sensitive attribute GUIDs like the replication rights above), `4728`/`4732`/`4756` (additions to privileged groups), `4670` (permissions changed on an object). Tools like Microsoft Defender for Identity are purpose-built to correlate these signals into actual attack-path detections.

---

## Module 14 — Backup, Recovery & High Availability

- **System State backup** — the minimum backup unit that includes AD; captures the NTDS.dit database, SYSVOL, registry, and boot files needed to restore a DC.
- **AD Recycle Bin** (available at Windows Server 2008 R2 forest functional level and above) — lets you restore a deleted object *with* its attributes and group memberships intact, instead of the old tombstone-reanimation process which lost most attributes.
- **Non-authoritative restore** — restore a DC from backup, then let normal replication catch it back up to the current state of the rest of the domain. Used for a single failed DC.
- **Authoritative restore** — restore a DC from backup, then explicitly mark specific objects as "more authoritative" so that restored version *overwrites* what's on every other DC instead of being overwritten by them. Used to undo a bad deletion that's already replicated everywhere.
- **RODCs** (Module 4) double as a disaster-recovery/security control for branch locations with weak physical security.

---

## Module 15 — Hybrid Identity (Azure AD / Entra ID)

Worth a mention since almost no modern AD deployment is purely on-prem anymore:

- **Microsoft Entra Connect** (formerly Azure AD Connect) synchronizes on-prem AD objects/password hashes to Entra ID (cloud), so users get one identity across on-prem and cloud (Microsoft 365, Azure, SaaS apps via SSO).
- **Password Hash Sync (PHS)** vs. **Pass-Through Authentication (PTA)** vs. **Federation (AD FS)** are the three main authentication models for hybrid — they trade off differently on where the actual credential validation happens (cloud vs. on-prem) and how much on-prem infrastructure has to stay online for cloud logon to work.
- This is genuinely its own deep topic — flag it if you want a dedicated module built out the same way as the ones above.

---

## Appendix — Quick Reference Cheat Sheets

**FSMO roles at a glance**

| Scope | Role |
|---|---|
| Forest (×1) | Schema Master |
| Forest (×1) | Domain Naming Master |
| Domain (×1 per domain) | RID Master |
| Domain (×1 per domain) | PDC Emulator |
| Domain (×1 per domain) | Infrastructure Master |

**Group Policy processing order:** Local → Site → Domain → OU (outer→inner) — *"LSDOU"*, last-applied wins unless Enforced is set upstream.

**Group scope quick check:** Domain Local = permissions *within* its own domain, members from anywhere → Global = members from *its own* domain, usable *anywhere* → Universal = members from anywhere, usable anywhere, cached in the GC.

**Trust transitivity:** Parent-Child ✅ · Tree-Root ✅ · Shortcut ✅ · Forest ✅ (within scope) · External ❌ · Realm depends on config.

---

## Suggested next step

If you want to actually cement this rather than just read it, the highest-leverage move is standing up a small lab: 2–3 VMs, one forest root domain, a child domain or a second site, and walking through Modules 1–7 hands-on before touching the security material in Module 13 — the attack classes make a lot more intuitive sense once you've built the plumbing they're exploiting yourself. Happy to spec out that lab build (VM count, roles, step order) if you want it.
