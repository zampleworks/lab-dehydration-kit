# Severity-aware logger for the module. Output routing:
#
#   (default)      Write-Host, uncolored. Used for informational lines that
#                  should appear regardless of -Verbose, including
#                  WhatIf forward-reference / skip notes so they read
#                  consistently with PowerShell's own "What if:" output.
#   -Step          Write-Verbose. Step/progress tracing - only emitted
#                  when caller used -Verbose. PowerShell hosts render the
#                  verbose stream yellow by default, which gives us the
#                  "yellow trace" effect without polluting normal output.
#   -Warning       Write-Host yellow. Real warnings that the operator
#                  should notice even without -Verbose.
#   -IsError       Write-Host red. Real failures.
#   -Success       Write-Host green. Milestone completion markers.
#
# The module-scoped $script:AdkLogLevel variable (set by
# Install-AdkContent from Context.LogLevel / Settings.psd1) controls
# additional filtering:
#   'Normal'  (default) - all severities except -Step (controlled by -Verbose)
#   'Verbose' - also emit -Step trace messages regardless of -Verbose
#   'Quiet'   - suppress info-level (default) messages; only
#               warnings, errors, and success milestones are shown

# Module-scoped log level; set by the orchestrator from Settings.psd1.
# Defaults to 'Normal' when not explicitly set.
if (-not (Get-Variable 'AdkLogLevel' -Scope Script -ErrorAction SilentlyContinue)) {
    $script:AdkLogLevel = 'Normal'
}

function Write-AdkLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Message,

        [switch] $IsError,
        [switch] $Warning,
        [switch] $Success,
        [switch] $Step
    )

    if ($IsError) {
        Write-Host $Message -ForegroundColor Red
    } elseif ($Warning) {
        Write-Host $Message -ForegroundColor Yellow
    } elseif ($Success) {
        Write-Host $Message -ForegroundColor Green
    } elseif ($Step) {
        # In Verbose log level, emit trace messages unconditionally.
        # Otherwise route through the verbose stream so -Verbose gates it.
        if ($script:AdkLogLevel -ieq 'Verbose') {
            Write-Host $Message -ForegroundColor DarkGray
        } else {
            Write-Verbose $Message
        }
    } else {
        # In Quiet mode suppress informational (default) messages.
        if ($script:AdkLogLevel -ieq 'Quiet') { return }
        Write-Host $Message
    }
}

function Write-AdkException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        $ErrorRecord
    )

    Write-AdkLog 'Exception caught' -IsError
    # Include invocation location if available (script name + line number)
    if ($ErrorRecord.InvocationInfo) {
        $inv = $ErrorRecord.InvocationInfo
        $script = if ($inv.ScriptName) { Split-Path $inv.ScriptName -Leaf } else { '<unknown>' }
        Write-AdkLog "  at $script line $($inv.ScriptLineNumber)" -IsError
    }

    $ex = $ErrorRecord
    do {
        Write-AdkLog "  HResult: $($ex.Exception.HResult)" -IsError
        Write-AdkLog "  $($ex.Exception.Message)" -Warning
        if ($ex.Exception.StackTrace) {
            Write-AdkLog "$($ex.Exception.StackTrace)`n" -Warning
        }
        $ex = $ex.Exception.InnerException
    } while ($null -ne $ex)
}
