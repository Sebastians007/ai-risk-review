$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $taskPython = if (Test-Path -LiteralPath '.venv-build/Scripts/python.exe') { Join-Path $PSScriptRoot '.venv-build/Scripts/python.exe' } else { 'python' }
    $taskVersion = (& $taskPython -c 'from core import VERSION; print(VERSION)').Trim()
    $taskDist = 'dist/v' + $taskVersion
    $taskWork = 'build/v' + $taskVersion
    & $taskPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    & $taskPython -m PyInstaller --noconfirm --clean --onefile --windowed --exclude-module PIL --exclude-module numpy --exclude-module psutil --exclude-module cryptography --exclude-module Crypto --exclude-module Cryptodome --name AI-Risk-Review --distpath $taskDist --workpath ($taskWork + '/gui') --add-data 'web;web' app.py
    if ($LASTEXITCODE -ne 0) { throw 'Executable build failed.' }
    & $taskPython -m PyInstaller --noconfirm --clean --onefile --console --exclude-module PIL --exclude-module numpy --exclude-module psutil --exclude-module cryptography --exclude-module Crypto --exclude-module Cryptodome --name AI-Risk-Review-CLI --distpath $taskDist --workpath ($taskWork + '/cli') --add-data 'web;web' app.py
    if ($LASTEXITCODE -ne 0) { throw 'Terminal executable build failed.' }
    $taskReleaseDir = Join-Path $PSScriptRoot 'releases'
    New-Item -ItemType Directory -Force -Path $taskReleaseDir | Out-Null
    $taskZip = Join-Path $taskReleaseDir ('AI-Risk-Review-v' + $taskVersion + '-windows-x64.zip')
    Compress-Archive -LiteralPath ($taskDist + '/AI-Risk-Review.exe'),($taskDist + '/AI-Risk-Review-CLI.exe'),'README.md','LICENSE','SECURITY.md','THIRD_PARTY_NOTICES.txt','licenses','examples' -DestinationPath $taskZip -Force
    $taskHash = (Get-FileHash -LiteralPath $taskZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($taskZip + '.sha256') -Value ($taskHash + '  ' + [IO.Path]::GetFileName($taskZip)) -Encoding ascii
    Write-Output ('Release: ' + $taskZip)
    Write-Output ('SHA256: ' + $taskHash)
} finally { Pop-Location }
