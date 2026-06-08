# Strip diacritics from a string by decomposing to NFD and dropping
# combining marks. Used for UPN/email generation where ASCII is safer.

function Convert-DiacriticCharacters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string] $InputString
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }

    $formD = $InputString.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($char in $formD.ToCharArray()) {
        $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($char)
        if ($cat -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void] $sb.Append($char)
        }
    }

    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}
