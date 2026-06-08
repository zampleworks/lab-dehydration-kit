# Generate a random password from a curated alphabet that satisfies the
# default Windows password complexity rules without producing characters
# that frequently break copy-paste (no `<space>`, no `"`, no backticks).

$Script:AdkPwdAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789!#@%&()[]{}=+?^*-_.:,<>|'

function New-RandomPassword {
    [CmdletBinding()]
    param(
        [int] $Length = 128,
        [switch] $ConvertToSecureString
    )

    if ($Length -lt 8) {
        throw "Length must be >= 8 (got $Length)"
    }

    $chars = [char[]]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) {
        $chars[$i] = $Script:AdkPwdAlphabet[(Get-Random -Minimum 0 -Maximum $Script:AdkPwdAlphabet.Length)]
    }

    $pwd = [string]::new($chars)

    if ($ConvertToSecureString) {
        return (ConvertTo-SecureString $pwd -AsPlainText -Force)
    }

    return $pwd
}
