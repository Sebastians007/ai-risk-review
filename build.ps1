$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $taskVersion = (python -c 'from core import VERSION; print(VERSION)').Trim()
    $taskDist = 'dist/v' + $taskVersion
    $taskWork = 'build/v' + $taskVersion
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    python -m PyInstaller --noconfirm --clean --onefile --windowed --name AI-Risk-Review --distpath $taskDist --workpath ($taskWork + '/gui') --add-data 'web;web' app.py
    if ($LASTEXITCODE -ne 0) { throw 'Executable build failed.' }
    python -m PyInstaller --noconfirm --clean --onefile --console --name AI-Risk-Review-CLI --distpath $taskDist --workpath ($taskWork + '/cli') --add-data 'web;web' app.py
    if ($LASTEXITCODE -ne 0) { throw 'Terminal executable build failed.' }
    $taskReleaseDir = Join-Path $PSScriptRoot 'releases'
    New-Item -ItemType Directory -Force -Path $taskReleaseDir | Out-Null
    $taskZip = Join-Path $taskReleaseDir ('AI-Risk-Review-v' + $taskVersion + '-windows-x64.zip')
    Compress-Archive -LiteralPath ($taskDist + '/AI-Risk-Review.exe'),($taskDist + '/AI-Risk-Review-CLI.exe'),'README.md','LICENSE','SECURITY.md','examples' -DestinationPath $taskZip -Force
    $taskHash = (Get-FileHash -LiteralPath $taskZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($taskZip + '.sha256') -Value ($taskHash + '  ' + [IO.Path]::GetFileName($taskZip)) -Encoding ascii
    Write-Output ('Release: ' + $taskZip)
    Write-Output ('SHA256: ' + $taskHash)
} finally { Pop-Location }
