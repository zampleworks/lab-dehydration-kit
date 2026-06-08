# lab-dehydration-kit

A collection of scripts to ease deployment of lab environments.

## ADDS

Builds a complete Active Directory domain from scratch — OU tree, users,
groups, delegations, GPOs, and hardening — driven entirely by CSV data
files. Edit the CSVs to describe *your* organisation; run two scripts;
get a production-grade lab domain.

---

### Quick start

1. **Prepare a fresh Windows Server** (2022 or 2025 recommended).
2. Copy the `ADDS` folder to `C:\Install\` on the server.
3. **Install the forest** (promotes the server to DC, reboots):

   ```powershell
   .\Install-AddsService.ps1 -DomainDnsName corp.example.com `
                              -DomainNetBiosName CORP
   ```

4. **After reboot, populate AD content** (all 17 steps, in order):

   ```powershell
   .\Install-AddsContent.ps1
   ```

   Or run individual steps:

   ```powershell
   .\Install-AddsContent.ps1 -Step Groups
   .\Install-AddsContent.ps1 -Step WmiFilters,SecurityBaselines
   ```

Both scripts support `-WhatIf` for a dry-run preview of all AD changes.

---

### The security model

The design follows Microsoft's
[Privileged Access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
strategy. Everything is partitioned into three administrative tiers:

| Tier | Scope | Examples |
|------|-------|----------|
| **T0** | Directory service control plane | Domain Controllers, PKI, IGA, EDR-T0, Monitoring-T0 |
| **T1** | Application servers | SQL, SharePoint, SAP, line-of-business servers |
| **EA** | Enterprise Access / endpoints | Employee workstations, help-desk, EUC (end-user computing) |

**The core principle:** a T0 admin account can only log on to T0
resources, a T1 admin can only reach T1, and EA handles the employee
endpoint layer. Credentials never travel across tier boundaries.

This is enforced at multiple levels:
- **Authentication policies and silos** gate where Kerberos tickets can
  be issued.
- **Separation-of-duty GPOs** restrict interactive logon, RDP, and
  service logon at each tier boundary via user-rights assignments linked
  to per-app server OUs.
- **Claim groups** (`Claim-T0-Admin`, `Claim-T1-User`, etc.) tie
  accounts to their tier for policy evaluation.
- **AES-only Kerberos** on every admin and service account (RC4
  disabled per-account).

#### The RBAC model

Day-to-day administration never requires Domain Admin. Instead, the
delegation model uses three layers of nesting:

```
User account
  +-- Role group          (what the person does)
        +-- Permission group    (atomic AD or OS right)
              +-- [ACE on OU]         (applied by the Delegations step)
```

**Role groups** (e.g. `Adm-T0-DS-Admin`, `Adm-EA-Helpdesk-Admin`)
represent a job function. They contain no direct permissions themselves.

**Permission groups** (e.g. `Pm-T0-AD-User-Admin-PwReset`) hold exactly
one atomic right — an ACE on an OU. This makes rights composable:
assigning a new capability to a role is just adding a group membership.

**The AD-vs-OS distinction** matters for permission placement. A
permission that operates on AD objects (creating users, resetting
passwords, linking GPOs) is part of the AD namespace — its group lives
in the T0 Permissions OU regardless of which tier it targets, because AD
itself is T0 infrastructure. A permission that operates on OS resources
(local admin, interactive logon, LAPS read) is in the OS namespace — its
group lives in the target tier's OU.

Wiring a new delegation always follows the same steps:

1. Create a permission group in `Groups.csv`
2. Define the ACE in `Delegations.csv` (pick a verb)
3. Nest the permission group into a role via `GroupMembers.csv`

#### The App concept

Applications are the building blocks of the tiered environment. Each row
in `Apps.csv` represents one application at one tier and drives the
`New-AdkApp` cmdlet, which provisions a complete, self-contained
infrastructure stack:

- **Server OU** under the tier's Computers OU (e.g. `T0\Computers\DS`)
- **Admin and service roles** (`Adm-T0-DS-Admin`, `Svc-T0-DS`)
- **Server groups** for the app, management, and database servers
- **Permission groups** for local admin, logon, LAPS, and service logon
- **Domain-join permission group** with delegation on the app's server
  OU, auto-wired to the tier's deploy role
- **GPO-edit permission groups** (empty by default, operator populates)
- **SoD GPO** restricting logon to the correct groups, linked to the
  server OU

Two optional features are controlled by flags:

| Flag | What it adds |
|------|--------------|
| `HasSaw` | SAW (Secure Admin Workstation) OU, groups, GPO, and user role |
| `HasAma` | AMA (Authentication Mechanism Assurance) groups for certificate step-up auth |

**Structural memberships** are wired automatically inside each app:

- Admin role gets local admin on servers (and SAW if `HasSaw`)
- Service account role gets service logon
- Local admin implies interactive logon, RDP, and LAPS access
- AMA admin nests into the admin role (when `HasAma`)
- Tier deploy role gets domain-join permission

The `DS` app (Domain Services) provisions infrastructure for
AD-supporting servers (Entra Connect, ADFS, etc.) but not domain
controllers themselves. The AD service uses the name "DS" to keep the
"AD" token free for the AD-namespace prefix in permission groups.

#### Domain join delegation

Domain join is fully delegated — no account can join machines without
explicit permission. The design hardens against both unauthenticated
joins and the Creator-Owner exploitation vectors identified by
KB5020276 (Oct 2022, enforced Aug 2024).

**Three layers of defence:**

1. **Domain-level lockdown** — the DomainHardening step sets
   `ms-DS-MachineAccountQuota = 0` and redirects the default computer
   container to a staging OU.

2. **Delegated join permission** — deploy service accounts hold the
   `DomainJoin` verb via a tier-level join group
   (`Pm-T0-AD-JoinComputer`) that covers all app OUs via inheritance.
   Each app also gets a per-app join group
   (`Pm-AD-T0-DS-JoinComputer`) scoped to its own server OU, so
   app-admin join can be granted independently.

3. **DenyJoinAbuse** — explicit Deny ACEs on the parent computer OUs
   (`T0/Computers`, `T1/Computers`, `OrgRoot/Computers`,
   `NewComputers`, `DisabledComputers`) targeting the deploy Adm
   groups. These block the Shelltrail attack vectors where a join
   service account exploits its Creator-Owner status:
   - Deny Read on LAPS password attributes (Legacy and Windows LAPS)
   - Deny Write on `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

   The deny ACEs inherit to all descendant computer objects, so per-app
   entries are not needed.

**Ownership remediation** — the companion script
`Reset-ComputerObjectOwnership.ps1` (in the WisaIdentityServices
AD-Management repo) resets computer object owners to Domain Admins. This
satisfies KB5020276 reuse validation without the
`ComputerAccountReuseAllowlist` GPO.

#### Authentication mechanism assurance (AMA)

AMA groups allow certificate-based step-up authentication to be mapped
to AD group membership. When a user authenticates with a smart card
whose certificate contains a specific issuance policy OID, the auth
subsystem adds the corresponding AMA group to the token.

The toolkit creates tier-level AMA groups (`Ama-T0-Admin`,
`Ama-T1-User`) from `Groups.csv` and optionally per-app AMA groups
(`Ama-T0-DS-Admin`, `Ama-T0-DS-User`) from `Apps.csv` when
`HasAma = true`. All AMA groups live in the T0 AMA OU regardless of
tier, because AMA is an AD-level construct.

Per-app AMA admin groups nest into the app's admin role — so
authenticating with the right certificate automatically grants admin
privileges for that specific application.

---

### What each step does

`Install-AddsContent.ps1` runs up to 17 steps in a fixed,
dependency-safe order. When a subset is requested with `-Step`, any
unfulfilled dependencies are detected against the live directory and
automatically added to the run list. Use `-SkipStep` to exclude steps
(skipping a dependency prints a warning but is honoured). Use `-Force`
to reimport GPO and ADMX content that already exists.

| # | Step | Purpose |
|---|------|---------|
| 1 | **OuTree** | Creates the full OU hierarchy. Every other step depends on these OUs existing. |
| 2 | **Groups** | Creates security groups — roles, permissions, claims, tier-level AMA, server groups, department role groups. Routes each group to the correct OU based on its type and tier. |
| 3 | **Apps** | Provisions per-application infrastructure from `Apps.csv`. Creates server OUs, role groups, permission groups, server groups, AMA groups, domain-join delegation, SoD GPOs, and structural memberships. This is where most of the operational AD structure comes from. |
| 4 | **Users** | Creates employee accounts, tiered admin and user accounts, and service accounts. All accounts get AES-only Kerberos; passwords are written to an output file. |
| 5 | **Memberships** | Wires the complete RBAC hierarchy by processing group nesting. This connects roles to permissions, admins to their roles, and claims to their tiers. |
| 6 | **Fgpp** | Applies fine-grained password policies — different password rules for service accounts, tiered admins, and employees. Policies are targeted to Claim and Role groups. |
| 7 | **ForestFeatures** | Enables AD Recycle Bin, creates the KDS root key (for gMSA), and extends the schema for Windows LAPS. |
| 8 | **Delegations** | Stamps ACEs on OUs — the actual delegation of authority. First resets built-in delegation (removing inherited AdminSDHolder artefacts), then applies all rules from `Delegations.csv` using the verb registry. |
| 9 | **SodGpos** | Creates separation-of-duty GPOs for the PAW tier — restricting who can log on to privileged access workstations. |
| 10 | **DefaultPolicies** | Imports customised Default Domain Policy and Default Domain Controller Policy from GPO backups. |
| 11 | **WmiFilters** | Creates WMI filters for OS-version targeting (Server 2025, 2022, legacy; Win 11, 10, legacy). |
| 12 | **AdmxTemplates** | Deploys ADMX policy templates to the Central Store in SYSVOL. Optional — skips with a warning if `PolicyDefinitions.zip` is absent. |
| 13 | **SecurityBaselines** | Imports security-baseline GPOs from backups, assigns WMI filters, and links to target OUs. The same backup can serve multiple OS versions via different WMI filters. |
| 14 | **DnsReplication** | Sets forest-wide DNS zone replication scope on the root domain's DNS zones. |
| 15 | **AuthPolicies** | Creates authentication policies and silos for tiered logon control. Reads `Apps.csv` to generate per-app policy bubbles. |
| 16 | **DomainHardening** | Domain-level lockdown (run once): empties Pre-Windows 2000 group, clears operator-group AdminCount, zeroes machine-account quota, redirects default user/computer containers, empties Schema Admins, blocks operator implicit permissions via dSHeuristics. |
| 17 | **ServerHardening** | Per-DC OS hardening: pins NTDS/Netlogon RPC ports, enables KDC audit logging, enforces LDAP channel binding and signing, disables unnecessary services. |

---

### Naming conventions

#### Groups

| Pattern | Meaning | Example |
|---------|---------|---------|
| `Role-Org-*` | Organisation-wide business role | `Role-Org-Employee` |
| `Role-Org-<Dept>-<Role>` | Department role group | `Role-Org-Engineering-Employee` |
| `Device-Org-*` | Device group (client computers) | `Device-Org-Win-Client` |
| `Adm-T<n>-Deploy` | Tier deploy role (domain join) | `Adm-T0-Deploy` |
| `Adm-T<n>-<App>-Admin` | Tier admin role for an application | `Adm-T0-DS-Admin` |
| `Adm-T<n>-<App>-User` | Tier user role (non-admin SAW access) | `Adm-T0-DS-User` |
| `Adm-EA-*` | EA-level admin roles | `Adm-EA-EUC-Admin` |
| `Svc-T<n>-<App>` | Service account role group | `Svc-T0-IGA` |
| `Pm-AD-*` | Permission on AD objects (always T0) | `Pm-AD-GPO-Link-Domain` |
| `Pm-<Tier>-AD-*` | Tier-scoped AD permission (always T0 OU) | `Pm-T0-AD-User-Admin-PwReset` |
| `Pm-AD-<Tier>-<App>-*` | Per-app AD permission (always T0 OU) | `Pm-AD-T0-DS-JoinComputer` |
| `Pm-<Tier>-<App>-Srv-*` | OS-level server permission (target tier) | `Pm-T0-DS-Srv-LocalAdmin` |
| `Pm-<Tier>-<App>-SAW-*` | OS-level SAW permission (target tier) | `Pm-T0-DS-SAW-LocalAdmin` |
| `Srv-T<n>-<App>-*` | Server/workstation group | `Srv-T0-PKI-App Server` |
| `SAW-T<n>-<App>` | Secure admin workstation group | `SAW-T0-DS` |
| `PAW-T<n>` | Privileged access workstation group | `PAW-T0` |
| `Claim-*` | Authentication claim group | `Claim-T0-Admin` |
| `Ama-*` | Authentication mechanism assurance group | `Ama-T0-DS-Admin` |

#### Accounts

| Account type | Pattern | Example | OU |
|-------------|---------|---------|-----|
| Employee | `<sam>` | `anderune` | Org Employees |
| T0 admin | `at0-<sam>` | `at0-anderune` | T0 Admins |
| T0 standard user | `t0-<sam>` | `t0-anderune` | T0 Users |
| T1 admin | `at1-<sam>` | `at1-anderune` | T1 Admins |
| T1 standard user | `t1-<sam>` | `t1-anderune` | T1 Users |
| Service account | `<name>` | `iamadcon` | Per-tier Service Accounts |

---

### Customising for your environment

**Add a new application:**
1. Add a row to `Apps.csv` (e.g. `CRM;T1;true;true;T0 SoD DB Servers;T0 SoD DB SAW`).
2. The module auto-creates the server OU, SAW OU, all permission and
   role groups, AMA groups, domain-join delegation, and SoD GPOs.

**Add an admin for an existing app:**
1. Add the person to `Admins.csv` at the correct tier.
2. Add their admin account's role memberships to `GroupMembers.csv`.

**Add a new delegation:**
1. Add the permission group to `Groups.csv`.
2. Add the delegation rule to `Delegations.csv` (pick a verb).
3. Wire the permission into a role via `GroupMembers.csv`.

**Change the OU structure:**
1. Edit `OU.csv` — add, rename, or re-parent rows.
2. Update any `%Token%` references in other CSVs if token names changed.

**Bring your own users:**
Replace `Employees.csv` with your own data in the same column format.
The AdventureWorks sample data is only a starting point.

---

### GPO backups

The `Gpo/Backups/` folder contains GPO backup sets in the standard
Microsoft format (GUID-named directories with `Backup.xml`). The module
expects three kinds:

- **Security baselines** — referenced by `SecurityBaselines.csv`.
- **SoD (separation-of-duty) GPOs** — referenced by `Apps.csv`.
- **Default Domain / DC policies** — imported by the DefaultPolicies
  step.

GPO backups are **domain-portable** — the module reads each backup's
`Backup.xml` at import time, discovers the source domain and security
principals, and generates a migration table dynamically. There is no
static template to maintain.

**Adding an SoD GPO:**

1. Configure the GPO on any domain. It must contain User Rights
   Assignments referencing groups with the standard suffixes:
   `-InteractiveLogon`, `-RdpLogon`, `-LocalAdmin`, `-ServiceLogon`.
2. Export: `Backup-GPO -Name "T0 SoD DS Servers" -Path C:\Temp\Backups`
3. Copy the `{GUID}` folder into `Gpo/Backups/`.
4. Set `ServerGpoBackup` / `SawGpoBackup` in `Apps.csv` to the
   `DisplayName` in `Backup.xml`.
5. Rebuild the zip (`Tools\Build-Zip.ps1`).

**Adding a security baseline:**

1. Export or download the baseline GPO backup.
2. Drop the `{GUID}` folder into `Gpo/Backups/`.
3. Add a row to `SecurityBaselines.csv` with `BackupGpoName` matching
   `Backup.xml`.

Security baselines import without a migration table and work cross-domain
as long as they reference well-known SIDs (the Microsoft SCT baselines
are safe).

---

### Recovery scripts

The `Recovery/` folder contains standalone scripts for common AD
disaster-recovery tasks (FSMO seizure, krbtgt password rotation,
metadata cleanup, trust password reset). These are operational runbooks
for use after the domain is live.

### Tools

The `Tools/` folder contains utility scripts (`Build-Zip.ps1` for
packaging the kit, `Get-AclSize.ps1` for measuring ACL bloat,
`New-KrbtgtPassword.ps1` for scheduled krbtgt rotation).

---

### Data file reference

All data files live in `Data/` and use **semicolon-delimited CSV**. Edit
these files before running `Install-AddsContent.ps1` — everything that
ends up in AD is driven by what is in these CSVs.

#### OU.csv

Defines every OU. Columns: `Parent` (OU token of parent), `Name` (token
name, used as `%Name%` in other CSVs), `CN` (actual OU name in AD),
`DisplayName`, `Created` (set to `false`).

The token system lets all other CSVs reference OUs by logical name
(e.g. `%T0AdminsOU%`) rather than by distinguished name.

Default structure:

```
DC=corp,DC=example,DC=com
+-- CORP                          (%OrgRoot%)
|   +-- Groups / Roles / Permissions
|   +-- Users / Employees
|   +-- Computers / Clients
+-- NewUsers / NewComputers       (redirected defaults)
+-- DisabledUsers / DisabledComputers
+-- OperationsControl
    +-- T0 / T1 / EA             (each with Computers, Users, Groups sub-OUs)
```

#### Groups.csv

Columns: `Name`, `Type` (routing: `Role`, `DSRole`, `DSPermission`,
`DSServerGroup`, `ClientGroup`, `Claim`, `AMA`), `Scope` (`Universal`,
`DomainLocal`, `Global`), `Tier` (`T0`, `T1`, `EA`).

The `Type` routes the group to its OU. `ClientGroup` routes to the
organisation roles OU. All `DSPermission` groups go to T0 Permissions OU
regardless of `Tier` (AD objects are T0).

#### Apps.csv

Columns: `AppName`, `Tier`, `HasSaw` (`true`/`false`), `HasAma`
(`true`/`false`), `ServerGpoBackup`, `SawGpoBackup`.

Each row provisions a complete per-app infrastructure stack (see
[The App concept](#the-app-concept)).

#### Employees.csv

Employee accounts (AdventureWorks sample data). Columns:
`Samaccountname`, `FirstName`, `MiddleName`, `LastName`, `Initials`,
`Department`, `Division`, `Position`, `Manager`. Optional `EmailDomain`
column for per-user email domain override.

#### Admins.csv

Controls who gets tiered admin accounts. Columns: `Name` (department or
SAM), `Type` (`Dept` = everyone in that department, `Person` = one
individual), `Tier`. Creates admin (`at0-<sam>`) and standard tier-user
(`t0-<sam>`) accounts.

#### ServiceAccounts.csv

Service accounts. Columns: `Name`, `Samaccountname`, `Class` (`T0` or
`T1`). Optional `EmailDomain` column.

#### OrgAccounts.csv

Robot, shared, and external accounts. Columns: `Samaccountname`,
`FirstName`, `LastName`, `Description`, `Type` (`Robot`, `Shared`, or
`External`), `Manager` (SAM of responsible person), `Office`,
`Company`. Optional `EmailDomain` column. Each account is placed in the OU matching its type
and added to the corresponding `Role-Org-<Type>` group.

#### Departments.csv

Columns: `Name`, `Division`, `Head` (SAM of department head). Used with
`DeptRoles.csv` to generate `Role-Org-<Dept>-<Role>` groups and set
`managedBy`.

#### DeptRoles.csv

Plain text, one role suffix per line (e.g. `Management`, `HR`,
`Employee`, `Finance`). Combined with `Departments.csv` to create
department role groups.

#### GroupMembers.csv

Columns: `Member` (user SAM or group name), `MemberOf` (comma-separated
groups). Wires the full RBAC hierarchy.

#### Delegations.csv

Columns: `RoleName` (permission group), `OuName` (OU token, or empty
for domain root), `Verb` (e.g. `CreateUsers`, `ManageGroups`,
`GpoLink`, `DomainJoin`, `DenyJoinAbuse`), `Parameters` (e.g.
`Inheritance=All`). The module ships 38 built-in verbs.

#### FineGrainedPasswordPolicies.csv

Columns: `Name`, `Precedence`, `MinPasswordLength`,
`PasswordHistoryCount`, `ComplexityEnabled`,
`ReversibleEncryptionEnabled`, `MinPasswordAgeDays`,
`MaxPasswordAgeDays` (0 = never expires), `LockoutThreshold`
(0 = disabled), `LockoutObservationWindowMinutes`,
`LockoutDurationMinutes` (0 = admin must unlock), `AppliesTo`
(pipe-separated SAM names).

#### SecurityBaselines.csv

Columns: `GpoName`, `BackupGpoName` (must match `Backup.xml`), `Type`
(`Computer`/`User`), `WmiFilter` (from `WmiFilters.csv`), `LinkTargets`
(pipe-separated OU tokens).

#### WmiFilters.csv

Columns: `Name`, `Description`, `Query` (WQL).

#### EmailDomains.csv

Optional. Columns: `Type` (`Default`, `Employee`, `ServiceAccount`,
`Admin`, `TierUser`), `EmailDomain`. Empty `EmailDomain` = no email for
that type. Per-user `EmailDomain` columns in `Employees.csv` /
`ServiceAccounts.csv` / `OrgAccounts.csv` override type-level config.
