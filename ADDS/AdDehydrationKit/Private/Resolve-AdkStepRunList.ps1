# Dependency resolver for the step registry.
#
# Expands the user's -Step selection by auto-adding any dependency steps
# whose artefacts are not yet present in the live directory. Already-
# fulfilled deps (from a prior run) are left out so the user does not
# re-run work that is already done.
#
# Returns a hashtable:
#   RunList   = [string[]]  steps to execute, in canonical order
#   AutoAdded = [ordered]@{ depName = requiredByName }
#   Errors    = [string[]]  unresolvable dependency messages

function Resolve-AdkStepRunList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $RequestedSteps,

        [Parameter(Mandatory)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $StepRegistry
    )

    $planSet = @{}
    foreach ($s in $RequestedSteps) { $planSet[$s] = $true }

    $autoAdded = [ordered]@{}

    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($name in @($planSet.Keys)) {
            foreach ($dep in $StepRegistry[$name].Deps) {
                if ($planSet.ContainsKey($dep)) { continue }
                $fulfilled = try { & $StepRegistry[$dep].Check $Context } catch { $false }
                if (-not $fulfilled) {
                    $planSet[$dep] = $true
                    if (-not $autoAdded.Contains($dep)) {
                        $autoAdded[$dep] = $name
                    }
                    $changed = $true
                }
            }
        }
    }

    $runList = foreach ($s in $StepRegistry.Keys) {
        if ($planSet.ContainsKey($s)) { $s }
    }

    $errors = @()
    foreach ($s in $runList) {
        foreach ($dep in $StepRegistry[$s].Deps) {
            if ($planSet.ContainsKey($dep)) { continue }
            $ok = try { & $StepRegistry[$dep].Check $Context } catch { $false }
            if (-not $ok) {
                $errors += "  Step '$s' requires '$dep' ($($StepRegistry[$dep].Label)) - not fulfilled and could not be resolved."
            }
        }
    }

    @{
        RunList   = [string[]]$runList
        AutoAdded = $autoAdded
        Errors    = [string[]]$errors
    }
}
