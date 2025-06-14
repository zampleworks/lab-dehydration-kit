# lab-dehydration-kit
A collection of scripts to ease deployment of lab environments.

## ADDS
Scripts to install and configure an Active Directory domain with a security focused delegation and hardening model from the start. Comes with sample data to emulate an organization (based on Microsoft's AdventureWorks sample that comes with SQL server).  
The security model follows the [EA model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model) (but uses the old Tier0/1 nomenclature). Role and permission groups are created and granted proper delegations based on role, and Separation Of Duty is supported via a set of GPOs for different OUs. Authentication policies are created for Tier 0 AD, but can easily be added. They are created in Audit only-mode.