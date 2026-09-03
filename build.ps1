# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
# Build the garak Bridge Burp extension on Windows.
#
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
#
# Needs a JDK that can target release 17. Looks at JAVA_HOME, then javac on PATH, then the
# JDK bundled with Burp Suite -- so this builds on a machine with no Java installed.
# Dependencies are fetched into lib\ on first run.

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$Montoya = 'lib\montoya-api-2026.7.jar'
$Gson    = 'lib\gson-2.14.0.jar'
$Out     = 'build\garak-bridge.jar'
$Classes = 'build\classes'

function Find-Tool([string]$Name) {
    if ($env:JAVA_HOME) {
        $candidate = Join-Path $env:JAVA_HOME "bin\$Name.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $onPath = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    # Burp ships a full JDK; these are its usual install locations on Windows.
    $burpRoots = @(
        "$env:ProgramFiles\BurpSuitePro",
        "$env:ProgramFiles\BurpSuiteCommunity",
        "$env:LOCALAPPDATA\Programs\BurpSuitePro",
        "$env:LOCALAPPDATA\Programs\BurpSuiteCommunity",
        "$env:USERPROFILE\BurpSuite"
    )
    foreach ($root in $burpRoots) {
        $candidate = Join-Path $root "jre\bin\$Name.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

$javac = Find-Tool 'javac'
if (-not $javac) {
    Write-Error "No javac found. Install a JDK (winget install Microsoft.OpenJDK.21) or set JAVA_HOME."
}
Write-Host "javac:  $javac"

# --- dependencies ---------------------------------------------------------------
New-Item -ItemType Directory -Force -Path 'lib' | Out-Null
$deps = @{
    $Montoya = 'https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar'
    $Gson    = 'https://repo1.maven.org/maven2/com/google/code/gson/gson/2.14.0/gson-2.14.0.jar'
}
foreach ($jar in $deps.Keys) {
    if (Test-Path -LiteralPath $jar) {
        Write-Host "have    $jar"
    } else {
        Write-Host "fetch   $jar"
        Invoke-WebRequest -Uri $deps[$jar] -OutFile $jar -UseBasicParsing
    }
}

# --- compile --------------------------------------------------------------------
if (Test-Path -LiteralPath $Classes) { Remove-Item -Recurse -Force $Classes }
New-Item -ItemType Directory -Force -Path $Classes | Out-Null

$sources = Get-ChildItem -Recurse -Filter '*.java' -Path 'src\main\java' | ForEach-Object { $_.FullName }
Write-Host "source: $($sources.Count) files"

$sourceList = Join-Path $env:TEMP 'garak-bridge-sources.txt'
Set-Content -LiteralPath $sourceList -Value $sources -Encoding UTF8

& $javac --release 17 -nowarn -cp "$Montoya;$Gson" -d $Classes "@$sourceList"
if ($LASTEXITCODE -ne 0) { Write-Error "compilation failed" }
Remove-Item -LiteralPath $sourceList -Force

# --- package --------------------------------------------------------------------
# Gson is shaded in; Montoya is provided by Burp at runtime and must not be.
New-Item -ItemType Directory -Force -Path 'build' | Out-Null

$jarTool = Find-Tool 'jar'
if ($jarTool) {
    # Merge Gson's classes in, then add our own.
    $staging = Join-Path $env:TEMP 'garak-bridge-staging'
    if (Test-Path -LiteralPath $staging) { Remove-Item -Recurse -Force $staging }
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    $gsonZip = Join-Path $env:TEMP 'garak-bridge-gson.zip'
    Copy-Item -LiteralPath $Gson -Destination $gsonZip -Force
    Expand-Archive -LiteralPath $gsonZip -DestinationPath $staging -Force
    Remove-Item -LiteralPath $gsonZip -Force
    Remove-Item -Recurse -Force (Join-Path $staging 'META-INF') -ErrorAction SilentlyContinue
    Copy-Item -Recurse -Force (Join-Path $Classes '*') $staging
    & $jarTool --create --file $Out -C $staging .
    if ($LASTEXITCODE -ne 0) { Write-Error "packaging failed" }
    Remove-Item -Recurse -Force $staging
} else {
    # Burp's bundled runtime has javac but no jar; fall back to the Python packer.
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command py.exe -ErrorAction SilentlyContinue }
    if (-not $python) {
        Write-Error "No 'jar' tool and no Python found. Install a full JDK, or Python, to package the jar."
    }
    & $python.Source 'tools\mkjar.py' $Out $Classes $Gson
    if ($LASTEXITCODE -ne 0) { Write-Error "packaging failed" }
}

$size = [math]::Round((Get-Item -LiteralPath $Out).Length / 1KB)
Write-Host "built:  $((Get-Item -LiteralPath $Out).FullName)  ($size KiB)"
Write-Host ""
Write-Host "Load it in Burp: Extensions -> Installed -> Add -> Java -> $((Get-Item -LiteralPath $Out).FullName)"
