param(
    [ValidateSet('Seed','Baseline','Applied','Cleanup')][string]$Mode,
    [ValidateSet('absent','wrong_type','outside','compliant')][string]$Scenario
)
$ErrorActionPreference = 'Stop'
$fixtureKey = 'Software\ScapoliteConverterAcceptance'
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
$key = $null
try {
    if ($Mode -eq 'Cleanup') {
        $base.DeleteSubKeyTree($fixtureKey, $false)
        $Ansible.Changed = $true
        return
    }
    $types = @{ExactDword='DWord'; ExactText='String'; Minimum='DWord'; Maximum='DWord'; ''='String'}
    $expected = @{ExactDword=7; ExactText='hello'; Minimum=15; Maximum=10; ''='default'}
    if ($Scenario -eq 'compliant') { $expected.Minimum = 22; $expected.Maximum = 5 }
    $seed = $expected.Clone()
    if ($Scenario -eq 'outside') { $seed.ExactDword=0; $seed.ExactText='wrong'; $seed.Minimum=14; $seed.Maximum=11; $seed['']='wrong' }
    if ($Scenario -eq 'wrong_type') { $types.ExactDword='String'; $types.ExactText='DWord'; $types.Minimum='String'; $types.Maximum='String'; $types['']='DWord'; $seed.ExactDword='7'; $seed.ExactText=99; $seed.Minimum='15'; $seed.Maximum='10'; $seed['']=99 }
    if ($Mode -eq 'Seed') {
        $base.DeleteSubKeyTree($fixtureKey, $false)
        if ($Scenario -ne 'absent') {
            $key = $base.CreateSubKey($fixtureKey)
            foreach ($name in $seed.Keys) { $key.SetValue($name, $seed[$name], [Microsoft.Win32.RegistryValueKind]$types[$name]) }
        }
        $Ansible.Changed = $true
        return
    }
    $Ansible.Changed = $false
    $key = $base.OpenSubKey($fixtureKey)
    if ($Mode -eq 'Baseline' -and $Scenario -eq 'absent') {
        if ($null -ne $key) { throw 'Check mode created the fixture key' }
        return
    }
    if ($null -eq $key) { throw 'Expected fixture key is absent' }
    if ($Mode -eq 'Applied') {
        $types = @{ExactDword='DWord'; ExactText='String'; Minimum='DWord'; Maximum='DWord'; ''='String'}
        $values = $expected
    } else { $values = $seed }
    foreach ($name in $values.Keys) {
        if ($key.GetValueNames() -notcontains $name) { throw "Missing property: $name" }
        if ($key.GetValueKind($name).ToString() -cne $types[$name]) { throw "Wrong property type: $name" }
        if ($key.GetValue($name).ToString() -cne $values[$name].ToString()) { throw "Wrong property value: $name" }
    }
} finally {
    if ($null -ne $key) { $key.Dispose() }
    $base.Dispose()
}
