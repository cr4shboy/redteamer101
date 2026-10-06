<#
.SYNOPSIS
    Provision the TOOLING-001 pinned recon binaries into the project, via WSL.

.DESCRIPTION
    Downloads, SHA-256 verifies, validates, and installs exactly three pinned
    upstream release artifacts into "<PROJECT_ROOT>/.tools/wsl/<tool>/<version>/"
    using the already-installed "Ubuntu-24.04" WSL distribution.

    This script is written to be SAFE BY DEFAULT and to FAIL CLOSED:

      * no sudo, no apt/snap/other package manager, no WSL install/update;
      * no change to PATH, shell profiles, /etc, or any system config;
      * HTTPS GET only, from a five-host GitHub allowlist (including
        `release-assets.githubusercontent.com` for GitHub's transient signed
        release redirects). Redirects are NEVER followed automatically: every
        initial and redirect URL is parsed, re-checked against the allowlist,
        and only then contacted, with a bounded redirect count. curl config is
        disabled and the process environment is isolated. Full redirect URLs
        and their query strings are never persisted, logged, or written to any
        report, manifest, console output, or artifact;
      * SHA-256 verification against the official checksum file is MANDATORY
        before an artifact is ever validated, extracted, installed, or run;
      * every archive member is validated (offline Python helper) before
        extraction: absolute paths, '..', drive/UNC paths, NUL/control names,
        symlinks/hardlinks, special entries, and destination escapes are all
        rejected;
      * extraction happens only in a contained staging directory; only the
        expected binary is copied into the version root and the staging tree is
        removed, leaving only the binary, the official checksum file, and
        install-manifest.json;
      * the provisioned binaries are only ever run with "--version" and
        "--help" (stdin redirected from /dev/null) - never with a domain, host,
        URL, config file, or any target input;
      * installs are prepared and validated in contained staging and committed
        transactionally: the previous version directory (and stale reports) must
        be preserved or restored on any failure, and the backup is deleted only
        after every final validation succeeds. Only the exact three authorized
        version directories and two stale TOOLING-001 report files may be
        replaced; no other deletion or destructive scope is permitted.

    See CURRENT_TASK.md (TOOLING-001) for the authoritative authorization.

.PARAMETER RepoRoot
    Project root. Defaults to the parent of this script's "utils" folder.

.PARAMETER Tools
    Subset of pinned tools to provision (subfinder, dnsx, amass). Default: all.

.PARAMETER DryRun
    Run preflight and print the plan (URLs, destinations, allowlist) without
    downloading, extracting, or installing anything.

.PARAMETER KeepArchives
    Keep the downloaded archives under the run's contained transaction scratch
    (".tools/wsl/_txn/<run-id>/downloads/") instead of deleting them after a
    successful verified extraction.

.PARAMETER SelfTest
    Run the offline fail-closed self-tests only (no preflight, no network, no
    WSL, and no ".tools" directory is created).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\utils\provision_wsl_recon_tools.ps1 -DryRun

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\utils\provision_wsl_recon_tools.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\utils\provision_wsl_recon_tools.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [ValidateSet('subfinder', 'dnsx', 'amass')]
    [string[]]$Tools = @('subfinder', 'dnsx', 'amass'),
    [switch]$DryRun,
    [switch]$KeepArchives,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Pinned facts (must match CURRENT_TASK.md exactly) -----------------------
$DistroName   = 'Ubuntu-24.04'
$DistroArch   = 'x86_64'
$ToolingRoot  = '.tools/wsl'          # relative to the project root
$TxnDir       = '_txn'                # per-run transaction scratch under the tooling root
$ReportJsonName = 'tooling-001-report.json'
$ReportMdName   = 'TOOLING-001_REPORT.md'
$MaxRedirects = 5
$MaxValidationChars = 4000

# GitHub release hosts the fetch is allowed to resolve/connect to. Exactly five.
$AllowedHosts = @(
    'github.com',
    'api.github.com',
    'objects.githubusercontent.com',
    'github-releases.githubusercontent.com',
    'release-assets.githubusercontent.com'
)

# Minimal, explicit environment for isolated invocations. Every curl download
# and every provisioned-binary --version/--help run starts from "env -i" with
# only a fixed PATH and a C locale, so no inherited proxy, HOME, XDG, tool,
# provider, or API environment/config can be consumed.
$IsolatedEnv = @(
    'env', '-i',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'LANG=C',
    'LC_ALL=C'
)

# Pinned release matrix. sha256 is cross-checked against the official file.
$ToolMatrix = @(
    [ordered]@{
        name       = 'subfinder'
        version    = '2.16.0'
        artifact   = 'subfinder_2.16.0_linux_amd64.zip'
        checksums  = 'subfinder_2.16.0_checksums.txt'
        url_base   = 'https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/'
        # Relative path of the executable inside the extracted tree.
        member_rel = 'subfinder'
    }
    [ordered]@{
        name       = 'dnsx'
        version    = '1.3.1'
        artifact   = 'dnsx_1.3.1_linux_amd64.zip'
        checksums  = 'dnsx_1.3.1_checksums.txt'
        url_base   = 'https://github.com/projectdiscovery/dnsx/releases/download/v1.3.1/'
        member_rel = 'dnsx'
    }
    [ordered]@{
        name       = 'amass'
        version    = '5.1.1'
        artifact   = 'amass_linux_amd64.tar.gz'
        checksums  = 'amass_checksums.txt'
        url_base   = 'https://github.com/owasp-amass/amass/releases/download/v5.1.1/'
        # The amass tarball nests the binary under a versioned folder.
        member_rel = 'amass_linux_amd64/amass'
    }
)

# --- Generic helpers ---------------------------------------------------------

function Write-NoBomText {
    <# Write UTF-8 text without a BOM (PS 5.1 "Set-Content -Encoding UTF8" adds one). #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowEmptyString()][AllowNull()][string]$Text
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, [string]$Text, $encoding)
}

function Get-UrlHost {
    <# Return the lower-case host of a URL, or throw (without echoing the URL). #>
    param([Parameter(Mandatory)][string]$Url)
    try {
        return ([System.Uri]$Url).Host.ToLowerInvariant()
    }
    catch {
        throw 'Cannot parse the URL host. Refusing.'
    }
}

function Assert-AllowedUrl {
    <#
        Fail closed unless the URL is a credential-free HTTPS URL whose host is
        in the five-host allowlist. Called against the configured URLs and
        against every redirect target BEFORE it is contacted. Diagnostics never
        include the full URL or its query string (they may name only the host),
        so transient signed redirect parameters are never logged or persisted.
    #>
    param([Parameter(Mandatory)][string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw 'Refusing an empty URL.'
    }
    if ([regex]::IsMatch($Url, '[\x00-\x1F\x7F]')) {
        throw 'URL contains control characters. Refusing.'
    }
    if ([regex]::IsMatch($Url, "[`"'\\]")) {
        throw 'URL contains quote or backslash characters. Refusing.'
    }
    if ([regex]::IsMatch($Url, '\s')) {
        throw 'URL contains whitespace. Refusing.'
    }
    $uri = $null
    try {
        $uri = [System.Uri]$Url
    }
    catch {
        throw 'Cannot parse the URL. Refusing.'
    }
    if (-not $uri.IsAbsoluteUri) {
        throw 'URL is not absolute. Refusing.'
    }
    if ($uri.Scheme -ne 'https') {
        throw "Only https URLs are authorized (got '$($uri.Scheme)'). Refusing."
    }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw 'URLs with embedded credentials are forbidden. Refusing.'
    }
    if (-not $uri.IsDefaultPort) {
        throw "Non-default port '$($uri.Port)' is not authorized. Refusing."
    }
    $urlHost = $uri.Host.ToLowerInvariant()
    if ($AllowedHosts -notcontains $urlHost) {
        throw "URL host '$urlHost' is not in the five-host allowlist ($($AllowedHosts -join ', ')). Refusing."
    }
    return $urlHost
}

function Assert-ContainedPath {
    <#
        Fail closed unless ChildPath resolves inside ParentPath. Used to keep
        every write inside <PROJECT_ROOT>/.tools/wsl/ and to confirm archive
        member destinations stay inside the extraction root.
    #>
    param(
        [Parameter(Mandatory)][string]$ParentPath,
        [Parameter(Mandatory)][string]$ChildPath
    )
    $parent = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\', '/')
    $child  = [System.IO.Path]::GetFullPath($ChildPath)
    $sep    = [System.IO.Path]::DirectorySeparatorChar
    $prefix = $parent + $sep
    if (-not $child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$child' is outside the permitted root '$parent'. Refusing."
    }
    return $child
}

function Assert-SafeRelativePath {
    <#
        Reject a relative path that is absolute, UNC, drive-rooted, contains a
        control/NUL character, or contains a '..' segment. Applied to the
        tool-defined member paths before they are used.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RelativePath)
    if ([string]::IsNullOrEmpty($RelativePath)) {
        throw 'Empty relative path is not permitted.'
    }
    if ([regex]::IsMatch($RelativePath, '[\x00-\x1F\x7F]')) {
        throw "Control character in path '$RelativePath'. Refusing."
    }
    if ($RelativePath.StartsWith('\\')) {
        throw "UNC path '$RelativePath' is not permitted."
    }
    $normalized = $RelativePath.Replace('\', '/')
    if ($normalized.StartsWith('/')) {
        throw "Absolute path '$RelativePath' is not permitted."
    }
    if ($normalized -match '^[A-Za-z]:') {
        throw "Drive path '$RelativePath' is not permitted."
    }
    foreach ($segment in $normalized.Split('/')) {
        if ($segment -eq '..') {
            throw "Path traversal segment '..' found in '$RelativePath'."
        }
    }
    return $normalized
}

function Remove-ContainedPath {
    <# Recursively remove a path, but only after proving it is contained. #>
    param(
        [Parameter(Mandatory)][string]$ParentPath,
        [Parameter(Mandatory)][string]$ChildPath
    )
    if (-not (Test-Path -LiteralPath $ChildPath)) { return }
    [void](Assert-ContainedPath -ParentPath $ParentPath -ChildPath $ChildPath)
    Remove-Item -LiteralPath $ChildPath -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-EmptyContainedDirectory {
    <#
        Remove a contained directory only when it exists, is an ordinary
        (non-reparse) directory, is contained under ParentPath, and is empty.
        Returns $true when removed, $false otherwise. A non-empty or unexpected
        directory is never removed. Pure and offline-testable.
    #>
    param(
        [Parameter(Mandatory)][string]$ParentPath,
        [Parameter(Mandatory)][string]$DirPath
    )
    if (-not (Test-Path -LiteralPath $DirPath)) { return $false }
    if (-not (Test-Path -LiteralPath $DirPath -PathType Container)) { return $false }
    [void](Assert-ContainedPath -ParentPath $ParentPath -ChildPath $DirPath)
    $attributes = (Get-Item -LiteralPath $DirPath -Force).Attributes
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $entries = @(Get-ChildItem -LiteralPath $DirPath -Force -ErrorAction SilentlyContinue)
    if ($entries.Count -gt 0) { return $false }
    Remove-Item -LiteralPath $DirPath -Force -ErrorAction SilentlyContinue
    return (-not (Test-Path -LiteralPath $DirPath))
}

function Get-SanitizedExcerpt {
    <# Bound and strip control characters from captured tool output. #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [int]$MaxChars = $MaxValidationChars
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = $Text -replace "`0", ''
    $clean = [regex]::Replace($clean, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
    if ($clean.Length -gt $MaxChars) {
        $clean = $clean.Substring(0, $MaxChars) + '...[truncated]'
    }
    return $clean
}

# --- Checksum helpers --------------------------------------------------------

function Get-ChecksumForArtifact {
    <#
        Parse a ProjectDiscovery/OWASP-style checksum file and return the
        SHA-256 recorded for a specific artifact filename. The file contains
        lines of the form "<64-hex>  <filename>" (two spaces) optionally with a
        leading "*". Throws if the artifact entry is absent.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ChecksumText,
        [Parameter(Mandatory)][string]$ArtifactName
    )
    foreach ($rawLine in ($ChecksumText -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line, '^([0-9a-fA-F]{64})\s+\*?(.+)$')
        if (-not $match.Success) { continue }
        $listedName = $match.Groups[2].Value.Trim().TrimStart('./')
        if ($listedName -eq $ArtifactName) {
            return $match.Groups[1].Value.ToLowerInvariant()
        }
    }
    throw "No checksum entry for '$ArtifactName' in the official checksum file."
}

function Assert-ChecksumMatch {
    <# Fail closed on a missing entry, a malformed hash, or a mismatch. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Expected,
        [Parameter(Mandatory)][string]$ArtifactName
    )
    if ([string]::IsNullOrWhiteSpace($Expected)) {
        throw "Missing expected SHA-256 for '$ArtifactName' (no official checksum entry). Refusing."
    }
    if ($Actual -notmatch '^[0-9a-f]{64}$') {
        throw "Computed SHA-256 for '$ArtifactName' is malformed: '$Actual'. Refusing."
    }
    if ($Actual -ne $Expected) {
        throw "Checksum mismatch for '$ArtifactName': computed $Actual != expected $Expected. Refusing to install."
    }
    return $true
}

# --- Redirect helpers (manual, bounded, allowlist-checked) -------------------

function Resolve-RedirectUrl {
    <#
        Resolve a Location header against the current URL into an absolute URL,
        entirely in memory. Diagnostics never include the Location value, the
        base URL, or any query string.
    #>
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Location
    )
    if ([string]::IsNullOrWhiteSpace($Location)) {
        throw 'Empty redirect Location while resolving a redirect. Refusing.'
    }
    if ([regex]::IsMatch($Location, '[\x00-\x1F\x7F]')) {
        throw 'Redirect Location contains control characters. Refusing.'
    }
    try {
        $baseUri = [System.Uri]$BaseUrl
    }
    catch {
        throw 'Cannot parse the redirect base URL. Refusing.'
    }
    try {
        $nextUri = New-Object System.Uri -ArgumentList @($baseUri, $Location)
    }
    catch {
        throw 'Cannot resolve the redirect Location. Refusing.'
    }
    if (-not $nextUri.IsAbsoluteUri) {
        throw 'Redirect Location did not resolve to an absolute URL. Refusing.'
    }
    return $nextUri.AbsoluteUri
}

function Get-LocationHeader {
    <# Return the first Location header value from a raw header block, or $null. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$HeadersText)
    if ([string]::IsNullOrEmpty($HeadersText)) { return $null }
    foreach ($line in ($HeadersText -split "`r?`n")) {
        $m = [regex]::Match(
            $line,
            '^\s*Location\s*:\s*(.+?)\s*$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
    return $null
}

# --- WSL plumbing ------------------------------------------------------------

function Get-WslExecArgs {
    <#
        Build the wsl.exe argument vector using the explicit "--exec" form so the
        distribution's default shell can never reinterpret the argument vector.
        The command and its arguments are passed verbatim; no shell is implied.
    #>
    param([Parameter(Mandatory)][string[]]$Argv)
    return @('-d', $DistroName, '--exec') + $Argv
}

function Invoke-WslDirect {
    <#
        Run an argument vector directly inside the pinned distribution with the
        explicit "--exec" form (no default-shell reinterpretation, no shell
        wrapper, no inherited shell environment). Returns trimmed stdout.
        -AllowFail returns $null instead of throwing on a non-zero exit.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Argv,
        [string]$InputText,
        [switch]$AllowFail
    )
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        throw 'wsl.exe was not found.'
    }
    if ($Argv.Count -eq 0) {
        throw 'Refusing to run an empty WSL argument vector.'
    }
    $wslArgs = Get-WslExecArgs -Argv $Argv
    # Native stderr redirected to the success stream must not become a
    # terminating PowerShell error on 5.1; the exit code is authoritative.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($PSBoundParameters.ContainsKey('InputText')) {
            $out = $InputText | & wsl.exe @wslArgs 2>&1
        }
        else {
            $out = & wsl.exe @wslArgs 2>&1
        }
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
    $text = ($out | Out-String).Trim()
    if ($code -ne 0 -and -not $AllowFail) {
        throw "WSL command failed (exit $code): $($Argv -join ' ')`n$text"
    }
    if ($code -ne 0) { return $null }
    return $text
}

function Remove-PrivateStdinFromText {
    <#
        Defensively remove a private stdin payload from captured child output so
        a URL or query string carried on stdin can never be returned, logged, or
        persisted, even if the child echoed it. Pure and offline-testable.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [AllowNull()][AllowEmptyString()][string]$InputText
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ([string]::IsNullOrEmpty($InputText)) { return $Text }
    $result = $Text.Replace($InputText, '')
    $trimmed = $InputText.Trim()
    if (-not [string]::IsNullOrEmpty($trimmed)) {
        $result = $result.Replace($trimmed, '[redacted]')
    }
    return $result
}

function Invoke-WslCapture {
    <#
        Run an argument vector directly inside the pinned distribution and
        return both its exit code and combined text WITHOUT throwing, so callers
        that must build redacted diagnostics (for example downloads carrying
        transient signed query strings) never echo command text. An optional
        private stdin string (for example a curl "--config -" payload) is
        written to process stdin; its contents are never returned, logged, or
        included in any error.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Argv,
        [string]$InputText
    )
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        throw 'wsl.exe was not found.'
    }
    if ($Argv.Count -eq 0) {
        throw 'Refusing to run an empty WSL argument vector.'
    }
    $wslArgs = Get-WslExecArgs -Argv $Argv
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($PSBoundParameters.ContainsKey('InputText')) {
            # Private stdin payload: carried in memory, never echoed.
            $out = $InputText | & wsl.exe @wslArgs 2>&1
        }
        else {
            $out = & wsl.exe @wslArgs 2>&1
        }
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
    $text = ($out | Out-String)
    # Defensive: never return the private stdin payload, even if a child process
    # echoed it. The caller parses only status/header markers from this text.
    if ($PSBoundParameters.ContainsKey('InputText')) {
        $text = Remove-PrivateStdinFromText -Text $text -InputText $InputText
    }
    return [ordered]@{
        ExitCode = [int]$code
        Text     = $text
    }
}

function Invoke-WslListCapture {
    <#
        Run a wsl.exe listing subcommand (e.g. --list --quiet) directly, and
        return both its exit code and its combined text so callers can fail
        closed on a native command failure.
    #>
    param([Parameter(Mandatory)][string[]]$WslArgs)
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) {
        throw 'wsl.exe was not found.'
    }
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & wsl.exe @WslArgs 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
    return [ordered]@{
        ExitCode = [int]$code
        Text     = (($out | Out-String))
    }
}

function Get-WslPath {
    <# Convert an absolute Windows path to its WSL (/mnt/<drive>/...) form. #>
    param([Parameter(Mandatory)][string]$WindowsPath)
    $full = [System.IO.Path]::GetFullPath($WindowsPath)
    $m = [regex]::Match($full, '^([A-Za-z]):[\\/](.*)$')
    if (-not $m.Success) {
        throw "Cannot convert '$full' to a WSL path."
    }
    $drive = $m.Groups[1].Value.ToLowerInvariant()
    $rest  = $m.Groups[2].Value.Replace('\', '/')
    return "/mnt/$drive/$rest"
}

# --- Preflight (read-only) ---------------------------------------------------

function Get-DistroNamesFromListOutput {
    <# Parse "wsl.exe --list --quiet" text into distro names. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $result = @()
    if ([string]::IsNullOrEmpty($Text)) { return $result }
    foreach ($line in ($Text -split "`r?`n")) {
        $name = (($line -replace "`0", '')).Trim()
        if ($name -eq '') { continue }
        if ($name -match '^(NAME|Default)\b') { continue }
        $result += $name
    }
    return $result
}

function Test-DistroPresent {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names,
        [string]$Required = $DistroName
    )
    return ($Names -contains $Required)
}

function Get-DistroVersionFromVerboseOutput {
    <#
        Parse "wsl.exe --list --verbose" text and return the VERSION column for
        the required distribution, or $null when it cannot be determined.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [string]$Required = $DistroName
    )
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    foreach ($line in ($Text -split "`r?`n")) {
        $clean = (($line -replace "`0", '')).Trim()
        if ($clean -eq '') { continue }
        $clean = $clean.TrimStart('*').Trim()
        $tokens = $clean -split '\s+'
        if ($tokens.Count -lt 1) { continue }
        if ($tokens[0] -ne $Required) { continue }
        for ($i = $tokens.Count - 1; $i -ge 1; $i--) {
            if ($tokens[$i] -match '^\d+$') { return $tokens[$i] }
        }
        return $null
    }
    return $null
}

function Assert-WslVersion2 {
    <#
        Fail closed unless the read-only listing commands succeeded and the
        pinned distribution's WSL version parsed as exactly 2. CURRENT_TASK
        requires a confirmed WSL 2; an unparseable or missing version is a hard
        failure (never warn-and-continue).
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Version,
        [Parameter(Mandatory)][int]$ListExitCode,
        [Parameter(Mandatory)][int]$VerboseExitCode,
        [string]$Required = $DistroName
    )
    if ($ListExitCode -ne 0) {
        throw "wsl.exe --list --quiet failed (exit $ListExitCode). Refusing."
    }
    if ($VerboseExitCode -ne 0) {
        throw "wsl.exe --list --verbose failed (exit $VerboseExitCode). Refusing."
    }
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Could not determine the WSL version for '$Required' from read-only 'wsl.exe --list --verbose'. Refusing."
    }
    if ($Version -ne '2') {
        throw "Distribution '$Required' is WSL version $Version; TOOLING-001 requires WSL 2. Refusing."
    }
    return $Version
}

function Assert-DistroArch {
    param(
        [Parameter(Mandatory)][string]$Arch,
        [string]$Required = $DistroArch
    )
    if ($Arch -ne $Required) {
        throw "Distribution arch '$Arch' != required '$Required'. Refusing."
    }
    return $Arch
}

function Assert-WslExtractTools {
    <#
        Fail closed unless the extraction/validation tools we rely on already
        exist in the distro. Each check is a static, quote-free direct
        invocation (no shell), requiring a zero exit code:
        tar, sha256sum, curl, python3, chmod, env --version, and the python3
        stdlib zipfile module via "python3 -m zipfile --help" (unzip is not
        installed and installing anything is forbidden).
    #>
    $probes = @(
        @('tar', '--version'),
        @('sha256sum', '--version'),
        @('curl', '--version'),
        @('python3', '--version'),
        @('chmod', '--version'),
        @('env', '--version')
    )
    $missing = @()
    foreach ($probe in $probes) {
        $result = Invoke-WslDirect -Argv $probe -AllowFail
        if ($null -eq $result) { $missing += $probe[0] }
    }
    if ($missing.Count -gt 0) {
        throw "Required utilities missing in '$DistroName': $($missing -join ', '). Refusing (installing them is forbidden)."
    }
    # Quote-free module probe: argparse handles --help and exits 0 when usable.
    $zipOk = Invoke-WslDirect -Argv @('python3', '-m', 'zipfile', '--help') -AllowFail
    if ($null -eq $zipOk) {
        throw "python3 stdlib 'zipfile' is not usable in '$DistroName'. Refusing."
    }
    Write-Host '  extract tools      : tar, python3(zipfile), sha256sum, curl, chmod, env'
}

function Invoke-Preflight {
    <#
        Read-only checks that must all pass before anything is downloaded:
        wsl.exe present, the pinned distribution present, a confirmed WSL 2,
        and x86_64 architecture. Throws (fail closed) on the first problem.
    #>
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) {
        throw 'wsl.exe was not found. TOOLING-001 requires an existing WSL install; installing WSL is forbidden.'
    }
    Write-Host ("  wsl.exe            : {0}" -f $wsl.Source)

    # Read-only listing probes; the native exit codes are authoritative.
    $listResult    = Invoke-WslListCapture -WslArgs @('--list', '--quiet')
    $verboseResult = Invoke-WslListCapture -WslArgs @('--list', '--verbose')

    if ($listResult.ExitCode -ne 0) {
        throw "wsl.exe --list --quiet failed (exit $($listResult.ExitCode)). Refusing:`n$($listResult.Text)"
    }
    $names = Get-DistroNamesFromListOutput -Text $listResult.Text
    if (-not (Test-DistroPresent -Names $names)) {
        throw "Distribution '$DistroName' is not installed (found: '$($names -join ', ')'). Refusing."
    }
    Write-Host ("  distro             : {0}" -f $DistroName)

    # CURRENT_TASK requires a confirmed WSL 2; unparseable/missing is fatal.
    $version = Get-DistroVersionFromVerboseOutput -Text $verboseResult.Text
    [void](Assert-WslVersion2 -Version $version -ListExitCode $listResult.ExitCode -VerboseExitCode $verboseResult.ExitCode)
    Write-Host ("  wsl version        : {0}" -f $version)

    $arch = Invoke-WslDirect -Argv @('uname', '-m')
    [void](Assert-DistroArch -Arch $arch)
    Write-Host ("  arch               : {0}" -f $arch)
    Write-Host ("  kernel             : {0}" -f (Invoke-WslDirect -Argv @('uname', '-s')))

    Assert-WslExtractTools
    return $wsl.Source
}

# --- Download (manual redirects, sanitized curl) -----------------------------

function Get-DownloadDiagnostic {
    <#
        Build a redacted download diagnostic that may include only the host, a
        redirect HTTP status, and a curl exit code. It can never contain a full
        URL or query string.
    #>
    param(
        [string]$UrlHost = 'unknown',
        [string]$Status = '',
        [int]$ExitCode = -1
    )
    $parts = @("host=$UrlHost")
    if (-not [string]::IsNullOrEmpty($Status)) { $parts += "status=$Status" }
    if ($ExitCode -ge 0) { $parts += "curl_exit=$ExitCode" }
    return ('download ' + ($parts -join ' '))
}

function Get-HeadersFromCurlOutput {
    <# Return the in-memory header block that precedes curl's status marker. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $marker = [regex]::Match($Text, '__TOOLING001_STATUS__\d{3}__END__')
    if ($marker.Success) { return $Text.Substring(0, $marker.Index) }
    return $Text
}

function Get-HttpStatusFromCurlOutput {
    <# Return the HTTP status carried by curl's write-out marker, or ''. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $m = [regex]::Match($Text, '__TOOLING001_STATUS__(\d{3})__END__')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-CurlArgv {
    <#
        Build the curl argument vector. The URL is NEVER part of this vector: it
        is supplied only through a private stdin curl config ("--config -"), so
        a signed redirect URL/query can never be mangled by Windows
        PowerShell/wsl.exe argument transport and can never appear in a process
        command line or failed command string. curl runs under "env -i", with
        config disabled, HTTPS required, GET only, no automatic redirect
        following (--max-redirs 0), and headers captured in memory on stdout
        (--dump-header -). No header file is written.
    #>
    param(
        [Parameter(Mandatory)][string]$OutWsl
    )
    return @($IsolatedEnv) + @(
        'curl',
        '--disable',
        '--silent',
        '--show-error',
        '--proto', '=https',
        '--proto-redir', '=https',
        '--tlsv1.2',
        '--max-redirs', '0',
        '--max-time', '300',
        '--retry', '0',
        '--request', 'GET',
        '--output', $OutWsl,
        '--dump-header', '-',
        '--write-out', '__TOOLING001_STATUS__%{http_code}__END__',
        '--config', '-'
    )
}

function Get-CurlConfigStdin {
    <#
        Build the private curl config stdin payload that supplies the request
        URL. Returned in memory only; never written to a temp config file. The
        URL has already passed Assert-AllowedUrl, which rejects quotes,
        backslashes, control characters, and whitespace, so a single
        double-quoted "url" line is safe and needs no further escaping. The
        explicit GET request and the --output body sink prevent curl from
        treating stdin as a request body.
    #>
    param([Parameter(Mandatory)][string]$Url)
    return ('url = "' + $Url + '"' + "`n")
}

function Invoke-CurlHttpsDownload {
    <#
        Download a URL with manual, bounded redirect handling, capturing
        response headers only in memory. Automatic redirect following is never
        used: each hop is parsed, resolved, re-checked against the allowlist, and
        only then contacted. The URL is supplied to curl only through a private
        stdin config ("--config -"), never on the process command line. The body
        is kept only after an HTTP 200. No header file is written, and no full
        redirect URL or query string is ever logged or returned: callers receive
        only host-level redirect evidence (HTTP status + hostname).

        The -Probe seam exists only so offline self-tests can exercise this
        without WSL/network. A probe is invoked as & $Probe <configText>
        <bodyFile> and must return an object with Status (three-digit string),
        Headers (raw in-memory header text), and ExitCode (integer).
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$ContainmentRoot,
        [int]$MaxHops = $MaxRedirects,
        [scriptblock]$Probe = $null
    )
    if (-not $Probe) {
        $Probe = {
            param([string]$ConfigText, [string]$BodyFile)
            $argv = Get-CurlArgv -OutWsl (Get-WslPath -WindowsPath $BodyFile)
            $capture = Invoke-WslCapture -Argv $argv -InputText $ConfigText
            return [ordered]@{
                Status   = Get-HttpStatusFromCurlOutput -Text $capture.Text
                Headers  = Get-HeadersFromCurlOutput -Text $capture.Text
                ExitCode = [int]$capture.ExitCode
            }
        }
    }

    $current = $Url
    $hops = 0
    $succeeded = $false
    $redirects = [System.Collections.Generic.List[object]]::new()
    try {
        while ($true) {
            [void](Assert-AllowedUrl -Url $current)
            $currentHost = Get-UrlHost -Url $current
            # Delete any stale partial body before each hop; contained under the tooling root.
            if (Test-Path -LiteralPath $OutFile) {
                Remove-ContainedPath -ParentPath $ContainmentRoot -ChildPath $OutFile
            }
            # The URL travels only in the private stdin config, never in argv.
            $configText = Get-CurlConfigStdin -Url $current
            $step = $null
            try {
                $step = & $Probe $configText $OutFile
            }
            catch {
                # Never propagate a probe message: it may carry the URL/query.
                throw ((Get-DownloadDiagnostic -UrlHost $currentHost) + ' (request failed)')
            }
            $status = [string]$step.Status
            $exitCode = [int]$step.ExitCode
            if ($exitCode -ne 0) {
                throw ((Get-DownloadDiagnostic -UrlHost $currentHost -Status $status -ExitCode $exitCode) + ' (request failed)')
            }
            if ($status -notmatch '^\d{3}$') {
                throw ((Get-DownloadDiagnostic -UrlHost $currentHost) + ' (no HTTP status)')
            }

            if ($status -eq '200') {
                if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) {
                    throw ((Get-DownloadDiagnostic -UrlHost $currentHost -Status $status) + ' (empty body)')
                }
                $succeeded = $true
                return [ordered]@{ Redirects = @($redirects) }
            }
            if ($status -match '^(301|302|303|307|308)$') {
                if ($hops -ge $MaxHops) {
                    throw ((Get-DownloadDiagnostic -UrlHost $currentHost -Status $status) + ' (too many redirects)')
                }
                $location = Get-LocationHeader -HeadersText ([string]$step.Headers)
                if ([string]::IsNullOrEmpty($location)) {
                    throw ((Get-DownloadDiagnostic -UrlHost $currentHost -Status $status) + ' (missing Location)')
                }
                $next = Resolve-RedirectUrl -BaseUrl $current -Location $location
                [void](Assert-AllowedUrl -Url $next)
                $nextHost = Get-UrlHost -Url $next
                $redirects.Add([ordered]@{ status = $status; host = $nextHost })
                Write-Host ("    redirect {0} -> {1}" -f $status, $nextHost)
                $current = $next
                $hops++
                continue
            }
            throw ((Get-DownloadDiagnostic -UrlHost $currentHost -Status $status) + ' (unexpected status)')
        }
    }
    finally {
        # Fail closed: never leave a partial body behind on any failure.
        if (-not $succeeded) {
            if (Test-Path -LiteralPath $OutFile) {
                Remove-ContainedPath -ParentPath $ContainmentRoot -ChildPath $OutFile
            }
        }
    }
}

# --- Archive validation ------------------------------------------------------

function Get-ArchiveValidatorArgv {
    <# Static, quote-free direct argv for the stdlib-only archive validator. #>
    param(
        [Parameter(Mandatory)][string]$HelperWsl,
        [Parameter(Mandatory)][string]$ArchiveWsl,
        [Parameter(Mandatory)][string]$ArchiveType,
        [Parameter(Mandatory)][string]$RootWsl
    )
    return @(
        'python3', $HelperWsl,
        '--archive', $ArchiveWsl,
        '--type', $ArchiveType,
        '--root', $RootWsl
    )
}

function Assert-ArchiveMembers {
    <#
        Validate every archive member BEFORE extraction using the offline
        stdlib-only Python helper. Rejects absolute paths, '..', drive/UNC
        paths, NUL/control names, symlinks/hardlinks, special entries, and
        destination escapes.
    #>
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$ArchiveFile,
        [Parameter(Mandatory)][string]$ArchiveType,
        [Parameter(Mandatory)][string]$StagingDir
    )
    $helper = Join-Path $RepoRoot 'utils/validate_tool_archive.py'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
        throw "Archive validator helper not found: $helper"
    }
    $helperWsl  = Get-WslPath -WindowsPath $helper
    $archiveWsl = Get-WslPath -WindowsPath $ArchiveFile
    $rootWsl    = Get-WslPath -WindowsPath $StagingDir
    $argv = Get-ArchiveValidatorArgv -HelperWsl $helperWsl -ArchiveWsl $archiveWsl `
        -ArchiveType $ArchiveType -RootWsl $rootWsl
    $summary = Invoke-WslDirect -Argv $argv
    Write-Host ("    validated members : {0}" -f $summary)
    return $summary
}

# --- Existing-install handling -----------------------------------------------

function Get-ExistingInstallState {
    <#
        Classify an existing per-tool version directory:
          absent  - nothing there;
          complete- binary + official checksum file + manifest, consistent;
          partial - some but not all canonical files, or an inconsistent manifest;
          foreign - non-canonical content that this script must not overwrite.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$DestDir
    )
    if (-not (Test-Path -LiteralPath $DestDir)) { return 'absent' }
    if (-not (Test-Path -LiteralPath $DestDir -PathType Container)) { return 'foreign' }

    $manifestPath = Join-Path $DestDir 'install-manifest.json'
    $checksumPath = Join-Path $DestDir $Tool.checksums
    $binaryPath   = Join-Path $DestDir $Tool.name
    foreach ($p in @($manifestPath, $checksumPath, $binaryPath)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return 'partial' }
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifestPackage  = $manifest.package
        $manifestTool     = $manifest.tool
        $manifestVersion  = $manifest.version
        $manifestArtifact = $manifest.artifact
        if ($manifestPackage -ne 'TOOLING-001') { return 'foreign' }
        if ($manifestTool -ne $Tool.name -or $manifestVersion -ne $Tool.version) { return 'foreign' }
        if ($manifestArtifact -ne $Tool.artifact) { return 'foreign' }
        $expected = Get-ChecksumForArtifact `
            -ChecksumText (Get-Content -LiteralPath $checksumPath -Raw) `
            -ArtifactName $Tool.artifact
        if ($manifest.sha256 -ne $expected) { return 'partial' }
    }
    catch {
        return 'partial'
    }
    return 'complete'
}

function Get-UnexpectedInstallEntries {
    <#
        Return top-level entries that are not part of the canonical layout.
        Like any PowerShell function, an empty (or single-entry) result is
        unrolled through the pipeline, so callers MUST wrap the call in @(...)
        before using .Count under StrictMode.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$DestDir
    )
    $canonical = @($Tool.name, $Tool.checksums, 'install-manifest.json')
    $unexpected = @()
    if (-not (Test-Path -LiteralPath $DestDir -PathType Container)) { return $unexpected }
    foreach ($item in (Get-ChildItem -LiteralPath $DestDir -Force)) {
        if ($canonical -notcontains $item.Name) { $unexpected += $item.Name }
    }
    return $unexpected
}

# --- Binary validation -------------------------------------------------------

function Get-BinaryValidationArgv {
    <#
        Static, isolated argv for running an installed binary with exactly one
        literal flag and stdin from /dev/null. Runs under "env -i" with only a
        fixed PATH, C locale, and a contained scratch HOME/XDG_CONFIG_HOME. The
        shell program is static; the home, binary, and flag are passed as
        separate positional arguments ($0/$1/$2), never interpolated. The shell
        first changes into the contained home so the tool cannot create config
        relative to the project root.
    #>
    param(
        [Parameter(Mandatory)][string]$BinWsl,
        [Parameter(Mandatory)][ValidateSet('--version', '--help')][string]$Flag,
        [Parameter(Mandatory)][string]$HomeWsl
    )
    return @($IsolatedEnv) + @(
        ('HOME=' + $HomeWsl),
        ('XDG_CONFIG_HOME=' + $HomeWsl + '/.config'),
        'sh', '-c', 'cd "$0" && exec "$1" "$2" < /dev/null',
        $HomeWsl, $BinWsl, $Flag
    )
}

function Invoke-BinaryValidation {
    <#
        Run the installed binary with the literal "--version" and "--help" only
        (stdin from /dev/null) under "env -i" with PATH/C locale and a contained
        scratch HOME/cwd, require zero exit codes, require the version output to
        contain the pinned version, and return a bounded, sanitized summary.

        The scratch home is created under the provided -ScratchRoot (the active
        transaction work root) when given, otherwise under the contained
        ".tools/wsl/_validation/<guid>" scratch. It is always removed in
        finally, and an empty "_validation" parent is removed too. The -Runner
        seam exists only so offline self-tests can exercise this without WSL.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string]$ToolingRootPath,
        [string]$ScratchRoot = '',
        [scriptblock]$Runner = $null
    )
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $BinaryPath)
    $binWsl = Get-WslPath -WindowsPath $BinaryPath

    $usingScratchRoot = -not [string]::IsNullOrEmpty($ScratchRoot)
    if ($usingScratchRoot) {
        [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $ScratchRoot)
        $homeDir = Join-Path $ScratchRoot ('validation-home-' + [System.IO.Path]::GetRandomFileName())
    }
    else {
        $homeDir = Join-Path $ToolingRootPath (Join-Path '_validation' ([System.IO.Path]::GetRandomFileName()))
    }
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $homeDir)
    New-Item -ItemType Directory -Path $homeDir -Force | Out-Null
    $homeWsl = Get-WslPath -WindowsPath $homeDir

    if (-not $Runner) {
        $Runner = { param([string[]]$Argv) Invoke-WslDirect -Argv $Argv }
    }

    try {
        # Invoke-WslDirect throws (fail closed) on any non-zero exit code.
        $versionOut = & $Runner (Get-BinaryValidationArgv -BinWsl $binWsl -Flag '--version' -HomeWsl $homeWsl)
        $helpOut    = & $Runner (Get-BinaryValidationArgv -BinWsl $binWsl -Flag '--help' -HomeWsl $homeWsl)

        if ($versionOut -notmatch [regex]::Escape($Tool.version)) {
            throw ("Version validation failed for '{0}': output did not contain the pinned version '{1}'. Output: {2}" -f `
                $Tool.name, $Tool.version, $versionOut)
        }
        return [ordered]@{
            version_command        = "$($Tool.name) --version"
            version_exit_code      = 0
            version_contains_pinned = $true
            version_output         = Get-SanitizedExcerpt -Text $versionOut
            help_command           = "$($Tool.name) --help"
            help_exit_code         = 0
            help_output            = Get-SanitizedExcerpt -Text $helpOut
            validated_utc          = [DateTime]::UtcNow.ToString('o')
        }
    }
    finally {
        # Always remove the contained validation home, even on failure.
        Remove-ContainedPath -ParentPath $ToolingRootPath -ChildPath $homeDir
        if (-not $usingScratchRoot) {
            $validationParent = Split-Path -Parent $homeDir
            if ((Test-Path -LiteralPath $validationParent) -and
                (@(Get-ChildItem -LiteralPath $validationParent -Force).Count -eq 0)) {
                Remove-ContainedPath -ParentPath $ToolingRootPath -ChildPath $validationParent
            }
        }
    }
}

function New-InstallManifest {
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$Distro,
        [Parameter(Mandatory)][string[]]$AllowedHostsList,
        [Parameter(Mandatory)][string]$ArtifactUrl,
        [Parameter(Mandatory)][string]$ChecksumsUrl,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$Sha256Expected,
        [Parameter(Mandatory)][string]$InstallDir,
        [Parameter(Mandatory)]$Validation,
        [bool]$Reused = $false,
        [bool]$Replaced = $true,
        [AllowEmptyCollection()][array]$RedirectEvidence = @()
    )
    return [ordered]@{
        package                 = 'TOOLING-001'
        tool                    = $Tool.name
        version                 = $Tool.version
        platform                = 'linux_amd64'
        distro                  = $Distro
        artifact                = $Tool.artifact
        artifact_url            = $ArtifactUrl
        checksums_url           = $ChecksumsUrl
        sha256                  = $Sha256
        sha256_expected         = $Sha256Expected
        sha256_verified         = ($Sha256 -eq $Sha256Expected)
        reused_existing_install = $Reused
        replaced_with_canonical = $Replaced
        install_layout          = @('binary', 'checksum_file', 'install-manifest.json')
        redirect_evidence       = @($RedirectEvidence)
        redirect_urls_persisted = $false
        install_dir             = $InstallDir
        installed_utc           = [DateTime]::UtcNow.ToString('o')
        allowed_hosts           = $AllowedHostsList
        validation              = $Validation
    }
}

# --- Transactional install (prepare -> commit -> validate -> cleanup) --------

function Get-ReuseEvidence {
    <#
        Safely validate and reuse an already-canonical version directory. The
        directory is not modified; only local validation evidence is returned.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$DestDir,
        [Parameter(Mandatory)][string]$ToolingRootPath
    )
    $binTarget = Join-Path $DestDir $Tool.name
    $validation = Invoke-BinaryValidation -Tool $Tool -BinaryPath $binTarget -ToolingRootPath $ToolingRootPath
    $checksumText = Get-Content -LiteralPath (Join-Path $DestDir $Tool.checksums) -Raw
    $expected = Get-ChecksumForArtifact -ChecksumText $checksumText -ArtifactName $Tool.artifact
    $manifest = Get-Content -LiteralPath (Join-Path $DestDir 'install-manifest.json') -Raw | ConvertFrom-Json
    $sha = [string]$manifest.sha256
    return [ordered]@{
        tool            = $Tool.name
        version         = $Tool.version
        artifact        = $Tool.artifact
        checksums       = $Tool.checksums
        prepared_dir    = $null
        sha256          = $sha
        sha256_expected = $expected
        sha256_verified = ($sha -eq $expected)
        validation      = $validation
        redirects       = @()
        replaced        = $false
        reused          = $true
    }
}

function New-CanonicalInstall {
    <#
        Prepare one canonical version directory in contained staging:
        download, SHA-256 verify, validate archive members, extract, copy only
        the expected binary, keep the official checksum file, validate the
        binary with --version/--help, and write install-manifest.json into the
        prepared directory. Nothing final is modified here.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$ToolingRootPath,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$FinalInstallDir,
        [Parameter(Mandatory)][string[]]$AllowedHostsList
    )
    $assetUrl = $Tool.url_base + $Tool.artifact
    $sumUrl   = $Tool.url_base + $Tool.checksums
    [void](Assert-AllowedUrl -Url $assetUrl)
    [void](Assert-AllowedUrl -Url $sumUrl)

    $downloadsDir = Join-Path $WorkRoot 'downloads'
    $preparedDir  = Join-Path $WorkRoot (Join-Path 'prepared' (Join-Path $Tool.name $Tool.version))
    $stagingDir   = Join-Path $WorkRoot ('extract-' + $Tool.name + '-' + [System.IO.Path]::GetRandomFileName())
    foreach ($p in @($downloadsDir, $preparedDir, $stagingDir)) {
        [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $p)
    }
    New-Item -ItemType Directory -Path $downloadsDir -Force | Out-Null
    New-Item -ItemType Directory -Path $preparedDir -Force | Out-Null
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

    $assetFile = Join-Path $downloadsDir $Tool.artifact
    $sumFile   = Join-Path $downloadsDir $Tool.checksums
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $assetFile)
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $sumFile)

    $assetWsl   = Get-WslPath -WindowsPath $assetFile
    $stagingWsl = Get-WslPath -WindowsPath $stagingDir

    Write-Host ("  download : {0}" -f $Tool.artifact)
    $assetEvidence = Invoke-CurlHttpsDownload -Url $assetUrl -OutFile $assetFile -ContainmentRoot $ToolingRootPath
    Write-Host ("  download : {0}" -f $Tool.checksums)
    $sumEvidence = Invoke-CurlHttpsDownload -Url $sumUrl -OutFile $sumFile -ContainmentRoot $ToolingRootPath

    foreach ($p in @($assetFile, $sumFile)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Downloaded file missing: $p" }
        if ((Get-Item -LiteralPath $p).Length -eq 0) { throw "Downloaded file is empty: $p" }
    }

    $actualHash = (Invoke-WslDirect -Argv @('sha256sum', $assetWsl)).Split(' ')[0].ToLowerInvariant()
    $checksumText = Get-Content -LiteralPath $sumFile -Raw
    $expectedHash = Get-ChecksumForArtifact -ChecksumText $checksumText -ArtifactName $Tool.artifact
    [void](Assert-ChecksumMatch -Actual $actualHash -Expected $expectedHash -ArtifactName $Tool.artifact)
    Write-Host ("  sha256   : {0}" -f $actualHash)

    $archiveType = if ($Tool.artifact.EndsWith('.zip')) { 'zip' } else { 'targz' }
    [void](Assert-ArchiveMembers -RepoRoot $RepoRoot -ArchiveFile $assetFile -ArchiveType $archiveType -StagingDir $stagingDir)

    if ($archiveType -eq 'zip') {
        Invoke-WslDirect -Argv @('python3', '-m', 'zipfile', '-e', $assetWsl, $stagingWsl) | Out-Null
    }
    else {
        Invoke-WslDirect -Argv @('tar', '-xzf', $assetWsl, '-C', $stagingWsl) | Out-Null
    }

    $memberRel = Assert-SafeRelativePath -RelativePath $Tool.member_rel
    $memberFull = Join-Path $stagingDir ($memberRel.Replace('/', '\'))
    [void](Assert-ContainedPath -ParentPath $stagingDir -ChildPath $memberFull)
    if (-not (Test-Path -LiteralPath $memberFull -PathType Leaf)) {
        throw "Expected binary '$memberRel' not found after validated extraction."
    }

    $binTarget = Join-Path $preparedDir $Tool.name
    Copy-Item -LiteralPath $memberFull -Destination $binTarget -Force
    $binWsl = Get-WslPath -WindowsPath $binTarget
    Invoke-WslDirect -Argv @('chmod', '0755', $binWsl) | Out-Null

    $sumCopy = Join-Path $preparedDir $Tool.checksums
    Copy-Item -LiteralPath $sumFile -Destination $sumCopy -Force

    $validation = Invoke-BinaryValidation -Tool $Tool -BinaryPath $binTarget -ToolingRootPath $ToolingRootPath -ScratchRoot $WorkRoot
    Write-Host ("  version  : {0}" -f (($validation.version_output -split "`r?`n")[0]))

    $unexpected = @(Get-UnexpectedInstallEntries -Tool $Tool -DestDir $preparedDir)
    if ($unexpected.Count -gt 0) {
        throw "Internal error: unexpected entries in prepared install '$preparedDir': $($unexpected -join ', ')."
    }

    # Redirect evidence is recorded as status + host only - never a URL/query.
    $redirects = @(@($assetEvidence.Redirects) + @($sumEvidence.Redirects))

    $manifest = New-InstallManifest -Tool $Tool -Distro $DistroName -AllowedHostsList $AllowedHostsList `
        -ArtifactUrl $assetUrl -ChecksumsUrl $sumUrl -Sha256 $actualHash -Sha256Expected $expectedHash `
        -InstallDir $FinalInstallDir -Validation $validation -Reused $false -Replaced $true `
        -RedirectEvidence $redirects
    Write-NoBomText -Path (Join-Path $preparedDir 'install-manifest.json') -Text ($manifest | ConvertTo-Json -Depth 10)

    if (-not $KeepArchives) {
        Remove-Item -LiteralPath $assetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $sumFile -Force -ErrorAction SilentlyContinue
    }

    return [ordered]@{
        tool            = $Tool.name
        version         = $Tool.version
        artifact        = $Tool.artifact
        checksums       = $Tool.checksums
        prepared_dir    = $preparedDir
        sha256          = $actualHash
        sha256_expected = $expectedHash
        sha256_verified = ($actualHash -eq $expectedHash)
        validation      = $validation
        redirects       = $redirects
        replaced        = $true
        reused          = $false
    }
}

function New-ReportContent {
    <#
        Build the final JSON and Markdown report text from the per-tool
        evidence. Only status+host redirect evidence is included; no full
        redirect URL or query string is ever written.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$ToolingRootPath,
        [Parameter(Mandatory)][string[]]$AllowedHostsList,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Evidence
    )
    $tools = @()
    foreach ($e in $Evidence) {
        $installDir = Join-Path $ToolingRootPath (Join-Path $e.tool $e.version)
        $tools += [ordered]@{
            tool              = $e.tool
            version           = $e.version
            artifact          = $e.artifact
            sha256            = $e.sha256
            sha256_verified   = [bool]$e.sha256_verified
            replaced          = [bool]$e.replaced
            reused            = [bool]$e.reused
            install_dir       = $installDir
            manifest          = (Join-Path $installDir 'install-manifest.json')
            checksums_kept    = (Join-Path $installDir $e.checksums)
            redirect_evidence = @($e.redirects)
            validation        = $e.validation
        }
    }
    $reportObject = [ordered]@{
        package      = 'TOOLING-001'
        generated    = [DateTime]::UtcNow.ToString('o')
        project_root = $ProjectRoot
        tooling_root = $ToolingRootPath
        distro       = $DistroName
        allowlist    = $AllowedHostsList
        live_recon   = $false
        redirect_policy = [ordered]@{
            mode                        = 'manual-bounded'
            max_redirects               = $MaxRedirects
            follow_automatically        = $false
            https_only                  = $true
            get_only                    = $true
            anonymous                   = $true
            curl_config_disabled        = $true
            isolated_environment        = $true
            binary_stdin                = '/dev/null'
            headers_captured_in_memory  = $true
            redirect_urls_not_persisted = $true
        }
        tools = $tools
    }

    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('# TOOLING-001 - Pinned Recon Tool Provisioning Report')
    $md.Add('')
    $md.Add(('- Generated (UTC): {0}' -f $reportObject.generated))
    $md.Add(('- Project root: `{0}`' -f $ProjectRoot))
    $md.Add(('- Tooling root: `{0}`' -f $ToolingRootPath))
    $md.Add(('- WSL distro: `{0}` (linux_amd64)' -f $DistroName))
    $md.Add(('- Allowed download hosts: {0}' -f (($AllowedHostsList | ForEach-Object { "``$_``" }) -join ', ')))
    $md.Add(('- Redirect policy: manual, bounded ({0} max), allowlist-checked on every hop, automatic following disabled.' -f $MaxRedirects))
    $md.Add('- Redirect URL/query strings persisted: **no** (HTTP status + hostname only)')
    $md.Add('- Live reconnaissance performed: **no**')
    $md.Add('')
    $md.Add('| Tool | Version | Artifact | SHA-256 | Verified | Replaced | Reused | Version validated | Install dir |')
    $md.Add('|---|---|---|---|---|---|---|---|---|')
    foreach ($t in $tools) {
        $md.Add(('| {0} | {1} | `{2}` | `{3}` | {4} | {5} | {6} | {7} | `{8}` |' -f `
            $t.tool, $t.version, $t.artifact, $t.sha256,
            ($(if ($t.sha256_verified) { 'yes' } else { 'NO' })),
            ($(if ($t.replaced) { 'yes' } else { 'no' })),
            ($(if ($t.reused) { 'yes' } else { 'no' })),
            ($(if ($t.validation.version_contains_pinned) { 'yes' } else { 'NO' })),
            $t.install_dir))
    }
    $md.Add('')
    $md.Add('Redirect evidence is recorded as HTTP status + hostname only; no full')
    $md.Add('redirect URL or query string is stored. Only `--version` and `--help` are')
    $md.Add('run against the installed binaries (stdin from `/dev/null`); no domain,')
    $md.Add('host, URL, or target input is ever passed. No live recon, DNS query, or')
    $md.Add('target contact is performed.')

    return [ordered]@{
        Json     = ($reportObject | ConvertTo-Json -Depth 12)
        Markdown = ($md -join [Environment]::NewLine)
    }
}

function Assert-FinalInstall {
    <#
        Post-commit validation of one final version directory: canonical layout,
        manifest consistency, checksum evidence, and a fresh --version/--help
        run against the final binary.
    #>
    param(
        [Parameter(Mandatory)]$Tool,
        [Parameter(Mandatory)][string]$FinalDir,
        [Parameter(Mandatory)][string]$ToolingRootPath
    )
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $FinalDir)
    if (-not (Test-Path -LiteralPath $FinalDir -PathType Container)) {
        throw "Final install directory missing: $FinalDir"
    }
    $unexpected = @(Get-UnexpectedInstallEntries -Tool $Tool -DestDir $FinalDir)
    if ($unexpected.Count -gt 0) {
        throw "Final install '$FinalDir' has non-canonical entries: $($unexpected -join ', ')."
    }
    $manifestPath = Join-Path $FinalDir 'install-manifest.json'
    $checksumPath = Join-Path $FinalDir $Tool.checksums
    $binaryPath   = Join-Path $FinalDir $Tool.name
    foreach ($p in @($manifestPath, $checksumPath, $binaryPath)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            throw "Final install '$FinalDir' is missing '$p'."
        }
    }
    if ((Get-Item -LiteralPath $binaryPath).Length -eq 0) {
        throw "Final binary '$binaryPath' is empty."
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.package -ne 'TOOLING-001' -or $manifest.tool -ne $Tool.name -or
        $manifest.version -ne $Tool.version -or $manifest.artifact -ne $Tool.artifact) {
        throw "Final manifest '$manifestPath' is inconsistent."
    }
    $expected = Get-ChecksumForArtifact -ChecksumText (Get-Content -LiteralPath $checksumPath -Raw) -ArtifactName $Tool.artifact
    if ([string]$manifest.sha256 -ne $expected -or -not [bool]$manifest.sha256_verified) {
        throw "Final manifest '$manifestPath' checksum evidence is not verified."
    }
    if (($manifest.PSObject.Properties.Name -contains 'validation') -and
        -not [bool]$manifest.validation.version_contains_pinned) {
        throw "Final manifest '$manifestPath' has no pinned-version validation evidence."
    }
    $validation = Invoke-BinaryValidation -Tool $Tool -BinaryPath $binaryPath -ToolingRootPath $ToolingRootPath
    if (-not $validation.version_contains_pinned) {
        throw "Final binary '$binaryPath' failed version validation."
    }
    return $true
}

function Assert-FinalReports {
    <#
        Post-commit validation of the final JSON/Markdown reports: parse,
        content, five-host allowlist, per-tool status, and report/manifest hash
        agreement. Redirect evidence may contain only status + host.
    #>
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][string]$MdPath,
        [Parameter(Mandatory)][string[]]$ExpectedTools,
        [Parameter(Mandatory)][string[]]$AllowedHostsList,
        [Parameter(Mandatory)][string]$ToolingRootPath
    )
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $JsonPath)
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $MdPath)
    if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) { throw 'Final JSON report is missing.' }
    if (-not (Test-Path -LiteralPath $MdPath -PathType Leaf)) { throw 'Final Markdown report is missing.' }

    $report = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    if ($report.package -ne 'TOOLING-001') { throw 'Final report package mismatch.' }
    if ([bool]$report.live_recon) { throw 'Final report live_recon must be false.' }
    if (@($report.allowlist).Count -ne 5) { throw 'Final report allowlist must have exactly five hosts.' }
    if ((@($report.allowlist) -join ';') -ne ($AllowedHostsList -join ';')) {
        throw 'Final report allowlist does not match the authorized five hosts.'
    }
    $toolNames = @($report.tools | ForEach-Object { $_.tool })
    if (($toolNames -join ';') -ne ($ExpectedTools -join ';')) {
        throw 'Final report tool set mismatch.'
    }
    foreach ($t in @($report.tools)) {
        if (-not [bool]$t.sha256_verified) { throw "Final report tool '$($t.tool)' checksum not verified." }
        if (-not [bool]$t.replaced -and -not [bool]$t.reused) {
            throw "Final report tool '$($t.tool)' has no replacement/reuse status."
        }
        foreach ($redir in @($t.redirect_evidence)) {
            $names = @($redir.PSObject.Properties.Name)
            if (($names -notcontains 'status') -or ($names -notcontains 'host')) {
                throw 'Redirect evidence must contain only status and host.'
            }
        }
        $manifestPath = Join-Path $ToolingRootPath (Join-Path $t.tool (Join-Path $t.version 'install-manifest.json'))
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "Final manifest for '$($t.tool)' is missing."
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([string]$manifest.sha256 -ne [string]$t.sha256) {
            throw "Final report/manifest hash mismatch for '$($t.tool)'."
        }
    }
    $mdText = Get-Content -LiteralPath $MdPath -Raw
    if ($mdText -notmatch 'Pinned Recon Tool Provisioning Report') {
        throw 'Final Markdown report is malformed.'
    }
    return $true
}

function Invoke-InstallTransaction {
    <#
        Commit prepared directories/files transactionally. For every move the
        existing destination (if any) is first renamed into a contained backup;
        prepared sources are then moved into place. If any move or the final
        validation fails, the new destinations are removed and every backup is
        restored, leaving the prior state intact. Backups are deleted only after
        validation succeeds.
    #>
    param(
        [Parameter(Mandatory)][string]$ToolingRootPath,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$InstallMoves,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$FileMoves,
        [Parameter(Mandatory)][string[]]$AllowedDestinations,
        [Parameter(Mandatory)][scriptblock]$ValidateFinal,
        [hashtable]$ValidationContext = @{}
    )
    $backupRoot = Join-Path $WorkRoot 'backup'
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $backupRoot)
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

    $placed = [System.Collections.Generic.List[string]]::new()
    $backups = [System.Collections.Generic.List[object]]::new()
    $succeeded = $false
    try {
        foreach ($move in (@($InstallMoves) + @($FileMoves))) {
            $source = [string]$move.Source
            $dest   = [string]$move.Destination
            [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $source)
            [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $dest)
            if ($AllowedDestinations -notcontains $dest) {
                throw "Refusing an unauthorized transaction destination: $dest"
            }
            if (-not (Test-Path -LiteralPath $source)) {
                throw "Prepared transaction item is missing: $source"
            }
            $destParent = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destParent)) {
                [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $destParent)
                New-Item -ItemType Directory -Path $destParent -Force | Out-Null
            }
            if (Test-Path -LiteralPath $dest) {
                $backupPath = Join-Path $backupRoot ([System.IO.Path]::GetRandomFileName())
                Move-Item -LiteralPath $dest -Destination $backupPath
                $backups.Add([ordered]@{ Backup = $backupPath; Original = $dest })
            }
            Move-Item -LiteralPath $source -Destination $dest
            $placed.Add($dest)
        }
        & $ValidateFinal $ValidationContext
        $succeeded = $true
    }
    catch {
        # Roll back: remove new finals first, then restore every backup.
        foreach ($p in $placed) {
            if (Test-Path -LiteralPath $p) {
                [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $p)
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        foreach ($b in $backups) {
            if (Test-Path -LiteralPath $b.Backup) {
                Move-Item -LiteralPath $b.Backup -Destination $b.Original
            }
        }
        throw
    }
    finally {
        if ($succeeded) {
            Remove-Item -LiteralPath $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Offline self-tests (fail-closed behavior) -------------------------------

function Invoke-SelfTest {
    param(
        [Parameter(Mandatory)][string]$ToolingRootPath,
        [Parameter(Mandatory)][string]$RepoRoot
    )
    $results = [System.Collections.Generic.List[object]]::new()

    function Add-Result {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        $results.Add([ordered]@{ check = $Name; passed = $Passed; detail = $Detail })
    }

    function Test-Throws {
        param([string]$Name, [scriptblock]$Action, [string]$DetailOnSuccess)
        try {
            & $Action | Out-Null
            Add-Result $Name $false 'expected a fail-closed throw, but none occurred'
        }
        catch {
            Add-Result $Name $true ($DetailOnSuccess + ' :: ' + $_.Exception.Message)
        }
    }

    function Test-True {
        param([string]$Name, [scriptblock]$Condition, [string]$Detail)
        try {
            if (& $Condition) { Add-Result $Name $true $Detail }
            else { Add-Result $Name $false ('condition was false :: ' + $Detail) }
        }
        catch {
            Add-Result $Name $false ('condition threw: ' + $_.Exception.Message)
        }
    }

    # 1. Host allowlist and URL hardening.
    Test-Throws 'allowlist-rejects-evil-host' {
        Assert-AllowedUrl -Url 'https://evil.example.com/amass_linux_amd64.tar.gz'
    } 'non-allowlisted host rejected'

    Test-Throws 'allowlist-rejects-github-subdomain-spoof' {
        Assert-AllowedUrl -Url 'https://github.com.evil.example.com/x.zip'
    } 'spoofed host rejected'

    Test-Throws 'allowlist-rejects-http-scheme' {
        Assert-AllowedUrl -Url 'http://github.com/projectdiscovery/subfinder/x.zip'
    } 'plaintext http rejected'

    Test-Throws 'allowlist-rejects-embedded-credentials' {
        Assert-AllowedUrl -Url 'https://user:pass@github.com/x.zip'
    } 'credentialed URL rejected'

    Test-Throws 'allowlist-rejects-nondefault-port' {
        Assert-AllowedUrl -Url 'https://github.com:8443/x.zip'
    } 'non-default port rejected'

    Test-True 'allowlist-accepts-pinned-host' {
        (Assert-AllowedUrl -Url 'https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/x.zip') -eq 'github.com'
    } 'pinned allowlisted host accepted'

    # 2. Manual redirect resolution is checked against the allowlist.
    $redirected = Resolve-RedirectUrl -BaseUrl 'https://github.com/a/b' -Location 'https://evil.example.com/x'
    Test-Throws 'redirect-resolved-host-rejected' {
        Assert-AllowedUrl -Url $redirected
    } 'redirect leaving the allowlist rejected'

    $relativeRedirect = Resolve-RedirectUrl -BaseUrl 'https://github.com/a/b' -Location '/c/d'
    Test-True 'redirect-relative-resolves-on-allowed-host' {
        (Assert-AllowedUrl -Url $relativeRedirect) -eq 'github.com'
    } 'relative redirect resolved and re-checked'

    Test-Throws 'redirect-with-control-chars-rejected' {
        Resolve-RedirectUrl -BaseUrl 'https://github.com/a' -Location "https://github.com/x`nhttps://evil.example.com"
    } 'redirect Location with control characters rejected'

    # 3. Missing distribution / wrong architecture.
    $absentNames = Get-DistroNamesFromListOutput -Text "Ubuntu-22.04`nDebian`n"
    Test-True 'missing-distro-detected' {
        -not (Test-DistroPresent -Names $absentNames)
    } 'missing pinned distribution detected'

    $presentNames = Get-DistroNamesFromListOutput -Text "Ubuntu-24.04`nDebian`n"
    Test-True 'pinned-distro-detected' {
        Test-DistroPresent -Names $presentNames
    } 'pinned distribution detected'

    $verbose = "  NAME            STATE           VERSION`n* Ubuntu-24.04    Running         2`n"
    Test-True 'wsl-version-parsed' {
        (Get-DistroVersionFromVerboseOutput -Text $verbose) -eq '2'
    } 'WSL version parsed from read-only output'

    Test-Throws 'wsl-version-missing-rejected' {
        Assert-WslVersion2 -Version $null -ListExitCode 0 -VerboseExitCode 0
    } 'unparseable/missing WSL version rejected'

    Test-Throws 'wsl-version-empty-rejected' {
        Assert-WslVersion2 -Version '' -ListExitCode 0 -VerboseExitCode 0
    } 'empty WSL version rejected'

    Test-Throws 'wsl-version-not-2-rejected' {
        Assert-WslVersion2 -Version '1' -ListExitCode 0 -VerboseExitCode 0
    } 'WSL version 1 rejected'

    Test-Throws 'wsl-list-command-failure-rejected' {
        Assert-WslVersion2 -Version '2' -ListExitCode 1 -VerboseExitCode 0
    } 'native --list --quiet failure rejected'

    Test-Throws 'wsl-verbose-command-failure-rejected' {
        Assert-WslVersion2 -Version '2' -ListExitCode 0 -VerboseExitCode 1
    } 'native --list --verbose failure rejected'

    Test-True 'wsl-version-2-accepted' {
        (Assert-WslVersion2 -Version '2' -ListExitCode 0 -VerboseExitCode 0) -eq '2'
    } 'confirmed WSL 2 accepted'

    Test-Throws 'wrong-architecture-rejected' {
        Assert-DistroArch -Arch 'aarch64'
    } 'non-x86_64 architecture rejected'

    Test-True 'pinned-architecture-accepted' {
        (Assert-DistroArch -Arch 'x86_64') -eq 'x86_64'
    } 'x86_64 architecture accepted'

    # 4. Project and destination containment.
    Test-Throws 'containment-rejects-outside-root' {
        Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath (Join-Path $env:TEMP 'escape')
    } 'outside-root destination rejected'

    Test-Throws 'containment-rejects-sibling-prefix' {
        Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath ($ToolingRootPath + '-evil/x')
    } 'sibling-prefix destination rejected'

    # 5. Archive member path safety (PowerShell-side names).
    Test-Throws 'member-rejects-dotdot' {
        Assert-SafeRelativePath -RelativePath '../../etc/passwd'
    } 'dotdot member rejected'

    Test-Throws 'member-rejects-absolute' {
        Assert-SafeRelativePath -RelativePath '/etc/passwd'
    } 'absolute member rejected'

    Test-Throws 'member-rejects-drive-path' {
        Assert-SafeRelativePath -RelativePath 'C:/Windows/evil'
    } 'drive-path member rejected'

    Test-Throws 'member-rejects-unc-path' {
        Assert-SafeRelativePath -RelativePath '\\server\share\evil'
    } 'UNC member rejected'

    Test-Throws 'member-rejects-nul-name' {
        Assert-SafeRelativePath -RelativePath "bad`0name"
    } 'NUL member name rejected'

    # 6. Checksum parsing and matching.
    $fakeChecksums = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other_file.zip`n"
    Test-Throws 'checksum-missing-entry' {
        Get-ChecksumForArtifact -ChecksumText $fakeChecksums -ArtifactName 'subfinder_2.16.0_linux_amd64.zip'
    } 'missing checksum entry rejected'

    $goodChecksums = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899  subfinder_2.16.0_linux_amd64.zip`n"
    $parsed = Get-ChecksumForArtifact -ChecksumText $goodChecksums -ArtifactName 'subfinder_2.16.0_linux_amd64.zip'
    Test-True 'checksum-parses-entry' {
        $parsed -eq 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899'
    } 'present entry parsed and lower-cased'

    Test-Throws 'checksum-mismatch-rejected' {
        Assert-ChecksumMatch -Actual ('a' * 64) -Expected ('b' * 64) -ArtifactName 'x.zip'
    } 'checksum mismatch rejected'

    Test-Throws 'checksum-missing-expected-rejected' {
        Assert-ChecksumMatch -Actual ('a' * 64) -Expected '' -ArtifactName 'x.zip'
    } 'missing expected checksum rejected'

    Test-True 'checksum-match-accepted' {
        Assert-ChecksumMatch -Actual ('a' * 64) -Expected ('a' * 64) -ArtifactName 'x.zip'
    } 'matching checksum accepted'

    # 7. Every pinned artifact/tool destination is inside the tooling root.
    foreach ($tool in $ToolMatrix) {
        $dest = Join-Path $ToolingRootPath (Join-Path $tool.name $tool.version)
        try {
            Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $dest | Out-Null
            Add-Result ("containment-{0}" -f $tool.name) $true "dest inside tooling root: $dest"
        }
        catch {
            Add-Result ("containment-{0}" -f $tool.name) $false $_.Exception.Message
        }
    }

    # 8. The in-memory matrix must match the pinned CURRENT_TASK values.
    $expectedMatrix = @(
        'subfinder|2.16.0|subfinder_2.16.0_linux_amd64.zip|subfinder_2.16.0_checksums.txt',
        'dnsx|1.3.1|dnsx_1.3.1_linux_amd64.zip|dnsx_1.3.1_checksums.txt',
        'amass|5.1.1|amass_linux_amd64.tar.gz|amass_checksums.txt'
    )
    $actualMatrix = @($ToolMatrix | ForEach-Object {
        ('{0}|{1}|{2}|{3}' -f $_.name, $_.version, $_.artifact, $_.checksums)
    })
    $matrixOk = (($expectedMatrix -join ';') -eq ($actualMatrix -join ';'))
    Add-Result 'pinned-matrix-canonical' $matrixOk 'tool matrix matches CURRENT_TASK exactly'

    $expectedHosts = @(
        'github.com',
        'api.github.com',
        'objects.githubusercontent.com',
        'github-releases.githubusercontent.com',
        'release-assets.githubusercontent.com'
    )
    $hostsOk = (($expectedHosts -join ';') -eq ($AllowedHosts -join ';')) -and (@($AllowedHosts).Count -eq 5)
    Add-Result 'allowlist-canonical' $hostsOk 'host allowlist is exactly the five CURRENT_TASK hosts'
    Test-True 'allowlist-accepts-signed-redirect-host' {
        (Assert-AllowedUrl -Url 'https://release-assets.githubusercontent.com/asset') -eq 'release-assets.githubusercontent.com'
    } 'release-assets signed-redirect host accepted'

    # 9. Archive member rejection / destination escape via the offline helper.
    $helper = Join-Path $RepoRoot 'utils/validate_tool_archive.py'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
        Add-Result 'archive-helper-offline-selftest' $false "archive validator helper not found: $helper"
    }
    else {
        $pyCommand = $null
        foreach ($candidate in @('python', 'py')) {
            $found = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($found) { $pyCommand = $found; break }
        }
        if (-not $pyCommand) {
            Add-Result 'archive-helper-offline-selftest' $true 'skipped: no Windows python interpreter available'
        }
        else {
            $previousEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $helperOut = (& $pyCommand.Source $helper --self-test 2>&1 | Out-String)
                $helperCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousEap
            }
            if ($helperCode -eq 0) {
                Add-Result 'archive-helper-offline-selftest' $true 'archive traversal/link/escape self-test passed'
            }
            else {
                Add-Result 'archive-helper-offline-selftest' $false ("archive helper self-test exit $helperCode :: " + (($helperOut -split "`r?`n") -join ' '))
            }
        }
    }

    # 10. Static, isolated command construction (env -i; no auto-follow; no
    #     header file; URL never on the process command line).
    $signedUrl = 'https://release-assets.githubusercontent.com/asset?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20260101%2Fregion&X-Amz-Signature=deadbeef&token=SECRETVALUE'
    $curlArgv = Get-CurlArgv -OutWsl '/mnt/c/tmp/x'
    $curlText = ($curlArgv -join ' ')
    Add-Result 'curl-argv-uses-env-i' `
        (($curlArgv.Count -ge 2) -and ($curlArgv[0] -eq 'env') -and ($curlArgv[1] -eq '-i')) `
        'curl runs under env -i (no inherited environment)'
    Add-Result 'curl-argv-no-auto-follow' `
        ((-not ($curlText -match '(^|\s)-L(\s|$)')) -and (-not ($curlText -match '--location'))) `
        'no -L/--location; --max-redirs 0'
    Add-Result 'curl-argv-https-get-only' `
        (($curlText -match '--proto =https') -and ($curlText -match '--proto-redir =https') -and
         ($curlText -match '--request GET') -and ($curlText -match '--max-redirs 0') -and ($curlText -match '--disable')) `
        'HTTPS-only GET with curl config disabled'
    Add-Result 'curl-argv-no-header-file' `
        ((($curlArgv -join '|') -match '--dump-header\|-') -and (-not (($curlArgv -join '|') -match '\.headers'))) `
        'headers captured in memory only; no header file'
    Add-Result 'curl-argv-uses-stdin-config' `
        ((($curlArgv -join '|') -match '--config\|-')) `
        'URL supplied to curl only via --config stdin'
    Add-Result 'curl-argv-no-url-parameter' `
        (-not ((Get-Command Get-CurlArgv).Parameters.ContainsKey('Url'))) `
        'Get-CurlArgv has no URL parameter, so no path can append a URL to argv'
    Add-Result 'signed-url-absent-from-argv' `
        (($curlText -notmatch 'X-Amz') -and ($curlText -notmatch 'token=') -and
         ($curlText -notmatch 'deadbeef') -and ($curlText -notmatch 'release-assets') -and
         ($curlText -notmatch '\?') -and ($curlText -notmatch '&')) `
        'signed URL/query never appears in curl argv'
    $configStdin = Get-CurlConfigStdin -Url $signedUrl
    Add-Result 'curl-config-stdin-carries-signed-url' `
        (($configStdin -match 'url = "') -and ($configStdin -match 'X-Amz-Signature=deadbeef') -and
         ($configStdin -match '&') -and ($configStdin -match '%2F') -and ($configStdin -match 'token=SECRETVALUE')) `
        'signed URL carried only in the in-memory stdin config'
    Add-Result 'wsl-capture-supports-private-stdin' `
        ((Get-Command Invoke-WslCapture).Parameters.ContainsKey('InputText')) `
        'Invoke-WslCapture accepts a private stdin payload'
    $scrubbedText = Remove-PrivateStdinFromText -Text ("prefix`n" + $configStdin + 'suffix') -InputText $configStdin
    Add-Result 'wsl-capture-scrubs-private-stdin' `
        (($scrubbedText -notmatch 'SECRETVALUE') -and ($scrubbedText -notmatch 'X-Amz') -and ($scrubbedText -notmatch 'token=')) `
        'captured text never retains the private stdin payload'
    # Static AST check: the curl argv builder never references $Url.
    $selfPath = $PSCommandPath
    if ([string]::IsNullOrEmpty($selfPath)) { $selfPath = Join-Path $RepoRoot 'utils/provision_wsl_recon_tools.ps1' }
    $selfAst = $null
    try {
        $astTokens = $null
        $astErrors = $null
        $selfAst = [System.Management.Automation.Language.Parser]::ParseFile($selfPath, [ref]$astTokens, [ref]$astErrors)
    }
    catch { $selfAst = $null }
    $curlFnAst = $null
    if ($selfAst) {
        $curlFnAst = $selfAst.FindAll({
                param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -eq 'Get-CurlArgv')
            }, $true) | Select-Object -First 1
    }
    $urlRefs = @()
    if ($curlFnAst) {
        $urlRefs = @($curlFnAst.FindAll({
                    param($n) ($n -is [System.Management.Automation.Language.VariableExpressionAst]) -and ($n.VariablePath.UserPath -eq 'Url')
                }, $true))
    }
    Add-Result 'curl-argv-source-has-no-url-variable' `
        (($curlFnAst -ne $null) -and ($urlRefs.Count -eq 0)) `
        'Get-CurlArgv source never references $Url'

    # 10b. Explicit wsl.exe --exec plumbing.
    $execArgs = Get-WslExecArgs -Argv @('uname', '-m')
    Add-Result 'wsl-exec-args-form' `
        (($execArgs.Count -eq 5) -and ($execArgs[0] -eq '-d') -and ($execArgs[1] -eq 'Ubuntu-24.04') -and
         ($execArgs[2] -eq '--exec') -and ($execArgs[3] -eq 'uname') -and ($execArgs[4] -eq '-m') -and
         (-not ($execArgs -contains '--'))) `
        'wsl.exe argv uses -d <distro> --exec <cmd> ... (no bare --)'
    $wslHelpersExecOk = $true
    foreach ($helperName in @('Invoke-WslDirect', 'Invoke-WslCapture')) {
        $helperAst = $null
        if ($selfAst) {
            $helperAst = $selfAst.FindAll({
                    param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -eq $helperName)
                }, $true) | Select-Object -First 1
        }
        $execCallCount = 0
        if ($helperAst) {
            $execCallCount = @($helperAst.FindAll({
                        param($n) ($n -is [System.Management.Automation.Language.CommandAst]) -and ($n.GetCommandName() -eq 'Get-WslExecArgs')
                    }, $true)).Count
        }
        if (-not $helperAst -or $execCallCount -eq 0) { $wslHelpersExecOk = $false }
    }
    Add-Result 'wsl-helpers-use-exec' $wslHelpersExecOk 'Invoke-WslDirect/Invoke-WslCapture use Get-WslExecArgs (--exec)'

    # 10c. Binary validation argv: static shell, positional home/bin/flag.
    $testHomeWsl = '/mnt/c/red-teaming/.tools/wsl/_validation/abc'
    $verArgv = Get-BinaryValidationArgv -BinWsl '/mnt/c/tools/subfinder' -Flag '--version' -HomeWsl $testHomeWsl
    Add-Result 'binary-validation-env-i' `
        (($verArgv.Count -ge 2) -and ($verArgv[0] -eq 'env') -and ($verArgv[1] -eq '-i')) `
        'binary validation runs under env -i'
    Add-Result 'binary-validation-devnull' `
        ((($verArgv -join '|') -match '/dev/null')) `
        'binary validation stdin is /dev/null'
    Add-Result 'binary-validation-static-shell' `
        ($verArgv -contains 'cd "$0" && exec "$1" "$2" < /dev/null') `
        'shell command text is static; no interpolation'
    Add-Result 'binary-validation-home-contained' `
        (($verArgv -contains ('HOME=' + $testHomeWsl)) -and ($verArgv -contains ('XDG_CONFIG_HOME=' + $testHomeWsl + '/.config'))) `
        'HOME/XDG_CONFIG_HOME point at the contained validation home'
    Add-Result 'binary-validation-positional-args' `
        (($verArgv[-3] -eq $testHomeWsl) -and ($verArgv[-2] -eq '/mnt/c/tools/subfinder') -and ($verArgv[-1] -eq '--version')) `
        'home, binary, and flag are separate positional args'
    Test-Throws 'binary-validation-rejects-other-flags' {
        Get-BinaryValidationArgv -BinWsl '/mnt/c/tools/subfinder' -Flag '--evil' -HomeWsl $testHomeWsl
    } 'non-literal validation flag rejected'

    # 10d. Validation scratch lifecycle (offline runner seam; temp tooling root).
    $bvRoot = Join-Path $env:TEMP ('provision-bv-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $bvRoot -Force | Out-Null
    try {
        $fakeBin = Join-Path $bvRoot 'subfinder'
        [System.IO.File]::WriteAllText($fakeBin, 'binary')
        $fakeTool = [ordered]@{ name = 'subfinder'; version = '2.16.0' }
        $script:bvSeen = @()
        $runnerOk = {
            param([string[]]$Argv)
            $script:bvSeen += ,$Argv
            if ($Argv[-1] -eq '--version') { return 'subfinder version 2.16.0' }
            return ''
        }
        $bvValue = Invoke-BinaryValidation -Tool $fakeTool -BinaryPath $fakeBin -ToolingRootPath $bvRoot -Runner $runnerOk
        $bvFirst = $script:bvSeen[0]
        $bvRootWsl = Get-WslPath -WindowsPath $bvRoot
        $bvHome = (@($bvFirst | Where-Object { $_ -like 'HOME=*' })[0]).Substring(5)
        $bvHomeOk = $bvHome.StartsWith($bvRootWsl + '/_validation/')
        $bvCwdOk = ($bvFirst[-3] -eq $bvHome)
        $bvExecOk = ($bvFirst -contains 'cd "$0" && exec "$1" "$2" < /dev/null')
        $bvCleanOk = -not (Test-Path -LiteralPath (Join-Path $bvRoot '_validation'))
        Add-Result 'binary-validation-contained-home' ($bvHomeOk -and $bvCwdOk -and $bvExecOk) 'validation HOME/cwd contained under the tooling root'
        Add-Result 'binary-validation-cleans-home-on-success' `
            (([bool]$bvValue.version_contains_pinned) -and $bvCleanOk) `
            'validation scratch removed after success'

        $runnerFail = { param([string[]]$Argv) throw 'injected validation failure' }
        $bvThrew = $false
        try {
            Invoke-BinaryValidation -Tool $fakeTool -BinaryPath $fakeBin -ToolingRootPath $bvRoot -Runner $runnerFail | Out-Null
        }
        catch { $bvThrew = $true }
        $bvCleanFail = $bvThrew -and (-not (Test-Path -LiteralPath (Join-Path $bvRoot '_validation')))
        Add-Result 'binary-validation-cleans-home-on-failure' $bvCleanFail 'validation scratch removed after failure'

        $txnScratch = Join-Path $bvRoot 'txnscratch'
        New-Item -ItemType Directory -Path $txnScratch -Force | Out-Null
        $script:bvSeen = @()
        $bvValue2 = Invoke-BinaryValidation -Tool $fakeTool -BinaryPath $fakeBin -ToolingRootPath $bvRoot -ScratchRoot $txnScratch -Runner $runnerOk
        $txnHome = (@($script:bvSeen[0] | Where-Object { $_ -like 'HOME=*' })[0]).Substring(5)
        $txnHomeWinOk = $txnHome.StartsWith((Get-WslPath -WindowsPath $txnScratch) + '/validation-home-')
        $txnCleanOk = (Test-Path -LiteralPath $txnScratch) -and (@(Get-ChildItem -LiteralPath $txnScratch -Force).Count -eq 0)
        Add-Result 'binary-validation-uses-txn-scratch' ($txnHomeWinOk -and $txnCleanOk) 'transaction work root used and cleaned'
    }
    finally {
        Remove-Item -LiteralPath $bvRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $archiveArgv = Get-ArchiveValidatorArgv -HelperWsl '/h.py' -ArchiveWsl '/a.zip' -ArchiveType 'zip' -RootWsl '/root'
    $archiveSafe = $true
    foreach ($element in $archiveArgv) {
        if ($element -match "[`"'\\]") { $archiveSafe = $false }
    }
    Add-Result 'archive-argv-quote-free' $archiveSafe 'archive validator argv contains no shell metacharacters'

    # 11. Download behavior offline: cleanup, no header file, no query leakage,
    #     and URL transport via the private stdin config seam only.
    $cleanupRoot = Join-Path $env:TEMP ('provision-selftest-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $cleanupRoot -Force | Out-Null
    try {
        # Rejected non-allowlisted redirect: body removed, diagnostics redacted.
        $bodyA = Join-Path $cleanupRoot 'a.zip'
        $probeBad = {
            param($ConfigText, $BodyFile)
            [System.IO.File]::WriteAllText($BodyFile, 'partial-body')
            return [ordered]@{ Status = '302'; Headers = "HTTP/1.1 302 Found`r`nLocation: https://evil.example.com/x?secret=SUPERSECRET`r`n"; ExitCode = 0 }
        }
        $msgA = ''
        try {
            Invoke-CurlHttpsDownload -Url 'https://github.com/start' -OutFile $bodyA -ContainmentRoot $cleanupRoot -Probe $probeBad | Out-Null
        }
        catch { $msgA = $_.Exception.Message }
        $cleanA = ($msgA -ne '') -and (-not (Test-Path -LiteralPath $bodyA)) -and
            (-not (Test-Path -LiteralPath ($bodyA + '.headers'))) -and
            ($msgA -notmatch 'SUPERSECRET') -and ($msgA -notmatch '\?')
        Add-Result 'download-rejected-redirect-redacted-cleanup' $cleanA 'rejected redirect removes body; no header file; no query leak'

        # Unexpected status: body removed, no header file.
        $bodyB = Join-Path $cleanupRoot 'b.zip'
        $probe500 = {
            param($ConfigText, $BodyFile)
            [System.IO.File]::WriteAllText($BodyFile, 'error-body')
            return [ordered]@{ Status = '500'; Headers = "HTTP/1.1 500 Server Error`r`n"; ExitCode = 0 }
        }
        $threwB = $false
        try {
            Invoke-CurlHttpsDownload -Url 'https://github.com/start' -OutFile $bodyB -ContainmentRoot $cleanupRoot -Probe $probe500 | Out-Null
        }
        catch { $threwB = $true }
        $cleanB = $threwB -and (-not (Test-Path -LiteralPath $bodyB)) -and (-not (Test-Path -LiteralPath ($bodyB + '.headers')))
        Add-Result 'download-cleans-on-unexpected-status' $cleanB 'non-200 status removed body; no header file'

        # Allowed signed redirect then 200: the probe receives the signed URL
        # only through the in-memory stdin config; evidence is status+host.
        $bodyC = Join-Path $cleanupRoot 'c.zip'
        $script:probeSeenConfig = ''
        $probeSigned = {
            param($ConfigText, $BodyFile)
            $script:probeSeenConfig = $ConfigText
            if ($ConfigText -match 'url = "https://github\.com/') {
                return [ordered]@{ Status = '302'; Headers = "HTTP/1.1 302 Found`r`nLocation: https://release-assets.githubusercontent.com/asset?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20260101%2Fregion&X-Amz-Signature=deadbeef&token=SECRETVALUE`r`n"; ExitCode = 0 }
            }
            [System.IO.File]::WriteAllText($BodyFile, 'final-body')
            return [ordered]@{ Status = '200'; Headers = "HTTP/1.1 200 OK`r`n"; ExitCode = 0 }
        }
        $signedResult = Invoke-CurlHttpsDownload -Url 'https://github.com/start' -OutFile $bodyC -ContainmentRoot $cleanupRoot -Probe $probeSigned
        $evJson = ($signedResult.Redirects | ConvertTo-Json -Compress -Depth 6)
        $signedOk = (Test-Path -LiteralPath $bodyC) -and
            (-not (Test-Path -LiteralPath ($bodyC + '.headers'))) -and
            (@($signedResult.Redirects).Count -eq 1) -and
            ($signedResult.Redirects[0].host -eq 'release-assets.githubusercontent.com') -and
            ($signedResult.Redirects[0].status -eq '302') -and
            ($evJson -notmatch 'SECRETVALUE') -and ($evJson -notmatch '\?') -and
            ($script:probeSeenConfig -match 'token=SECRETVALUE') -and
            ($script:probeSeenConfig -match 'X-Amz-Signature=deadbeef')
        Add-Result 'download-signed-redirect-stdin-no-query-leak' $signedOk 'signed URL carried via stdin config; evidence status+host only'

        # Live-failure scenario: a curl exit code on a signed URL is redacted.
        $bodyD = Join-Path $cleanupRoot 'd.zip'
        $probeFail = {
            param($ConfigText, $BodyFile)
            return [ordered]@{ Status = ''; Headers = ''; ExitCode = 127 }
        }
        $failMsg = ''
        try {
            Invoke-CurlHttpsDownload -Url $signedUrl -OutFile $bodyD -ContainmentRoot $cleanupRoot -Probe $probeFail | Out-Null
        }
        catch { $failMsg = $_.Exception.Message }
        $failOk = ($failMsg -match 'host=release-assets\.githubusercontent\.com') -and
            ($failMsg -match 'curl_exit=127') -and
            ($failMsg -notmatch 'SECRETVALUE') -and ($failMsg -notmatch '\?') -and
            ($failMsg -notmatch 'X-Amz') -and (-not (Test-Path -LiteralPath $bodyD))
        Add-Result 'download-curl-exit-redacted' $failOk 'curl_exit redacted to host/status; no query leak'

        # Redacted curl-failure diagnostic.
        $diag = Get-DownloadDiagnostic -UrlHost 'release-assets.githubusercontent.com' -Status '302' -ExitCode 22
        $diagOk = ($diag -match 'host=release-assets\.githubusercontent\.com') -and ($diag -match 'status=302') -and
            ($diag -match 'curl_exit=22') -and ($diag -notmatch '\?') -and ($diag -notmatch 'https://')
        Add-Result 'download-diagnostic-redacted' $diagOk 'diagnostic is host/status/exit only'

        # URL/redirect diagnostics never echo the URL or query string.
        $allowedMsg = ''
        try { Assert-AllowedUrl -Url 'https://evil.example.com/x?secret=SUPERSECRET' | Out-Null } catch { $allowedMsg = $_.Exception.Message }
        Add-Result 'allowlist-diagnostic-redacted' `
            (($allowedMsg -ne '') -and ($allowedMsg -notmatch 'SUPERSECRET') -and ($allowedMsg -notmatch '\?') -and ($allowedMsg -notmatch 'https://')) `
            'allowlist failure does not echo URL/query'

        $resolveMsg = ''
        try { Resolve-RedirectUrl -BaseUrl 'https://github.com/a' -Location "bad`nsecret" | Out-Null } catch { $resolveMsg = $_.Exception.Message }
        Add-Result 'redirect-diagnostic-redacted' `
            (($resolveMsg -ne '') -and ($resolveMsg -notmatch 'secret') -and ($resolveMsg -notmatch 'https://')) `
            'redirect failure does not echo Location/base URL'
    }
    finally {
        Remove-Item -LiteralPath $cleanupRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 12. Report content contains host-level redirect evidence only.
    $fakeEvidence = @([ordered]@{
        tool            = 'subfinder'
        version         = '2.16.0'
        artifact        = 'subfinder_2.16.0_linux_amd64.zip'
        checksums       = 'subfinder_2.16.0_checksums.txt'
        prepared_dir    = $null
        sha256          = ('a' * 64)
        sha256_expected = ('a' * 64)
        sha256_verified = $true
        validation      = [ordered]@{ version_contains_pinned = $true }
        redirects       = @([ordered]@{ status = '302'; host = 'release-assets.githubusercontent.com' })
        replaced        = $true
        reused          = $false
    })
    $reportContentProbe = New-ReportContent -ProjectRoot $RepoRoot -ToolingRootPath $ToolingRootPath `
        -AllowedHostsList $AllowedHosts -Evidence $fakeEvidence
    $reportOk = ($reportContentProbe.Json -match 'release-assets\.githubusercontent\.com') -and
        ($reportContentProbe.Json -notmatch '\?') -and
        ($reportContentProbe.Json -notmatch 'SUPERSECRET') -and
        ($reportContentProbe.Markdown -notmatch '\?') -and
        ($reportContentProbe.Json -match 'redirect_urls_not_persisted')
    Add-Result 'report-content-no-redirect-urls' $reportOk 'reports record host-level redirect evidence only'

    # 13. Transaction commit/rollback (filesystem only, in a temp directory).
    $txnTestRoot = Join-Path $env:TEMP ('provision-txn-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $txnTestRoot -Force | Out-Null
    function New-FakeInstallDir {
        param([string]$Path, [string]$Content)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $Path 'marker.txt'), $Content)
        return $Path
    }
    try {
        # Success: prepared items committed; backups removed.
        $rootA = Join-Path $txnTestRoot 'success'
        New-Item -ItemType Directory -Path $rootA -Force | Out-Null
        $oldDir1 = New-FakeInstallDir (Join-Path $rootA 'subfinder/2.16.0') 'old-subfinder'
        $oldRep  = Join-Path $rootA 'tooling-001-report.json'
        [System.IO.File]::WriteAllText($oldRep, 'old-report')
        $workA   = Join-Path $rootA '_txn/work'
        $srcDir1 = New-FakeInstallDir (Join-Path $workA 'prepared/subfinder/2.16.0') 'new-subfinder'
        $srcRep  = Join-Path $workA 'prepared-reports/tooling-001-report.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $srcRep) -Force | Out-Null
        [System.IO.File]::WriteAllText($srcRep, 'new-report')
        Invoke-InstallTransaction -ToolingRootPath $rootA -WorkRoot $workA `
            -InstallMoves @([ordered]@{ Source = $srcDir1; Destination = $oldDir1 }) `
            -FileMoves @([ordered]@{ Source = $srcRep; Destination = $oldRep }) `
            -AllowedDestinations @($oldDir1, $oldRep) `
            -ValidateFinal { param($ctx) } -ValidationContext @{}
        $okA = ((Get-Content -LiteralPath (Join-Path $oldDir1 'marker.txt') -Raw) -eq 'new-subfinder') -and
            ((Get-Content -LiteralPath $oldRep -Raw) -eq 'new-report') -and
            (-not (Test-Path -LiteralPath (Join-Path $workA 'backup')))
        Add-Result 'transaction-success-commits-and-deletes-backups' $okA 'prepared items committed; backups removed'

        # Post-validation failure: old dir/report restored, new items removed.
        $rootB = Join-Path $txnTestRoot 'postfail'
        New-Item -ItemType Directory -Path $rootB -Force | Out-Null
        $oldDir2 = New-FakeInstallDir (Join-Path $rootB 'dnsx/1.3.1') 'old-dnsx'
        $oldRep2 = Join-Path $rootB 'TOOLING-001_REPORT.md'
        [System.IO.File]::WriteAllText($oldRep2, 'old-md')
        $workB   = Join-Path $rootB '_txn/work'
        $srcDir2 = New-FakeInstallDir (Join-Path $workB 'prepared/dnsx/1.3.1') 'new-dnsx'
        $srcRep2 = Join-Path $workB 'prepared-reports/TOOLING-001_REPORT.md'
        New-Item -ItemType Directory -Path (Split-Path -Parent $srcRep2) -Force | Out-Null
        [System.IO.File]::WriteAllText($srcRep2, 'new-md')
        $threwB = $false
        try {
            Invoke-InstallTransaction -ToolingRootPath $rootB -WorkRoot $workB `
                -InstallMoves @([ordered]@{ Source = $srcDir2; Destination = $oldDir2 }) `
                -FileMoves @([ordered]@{ Source = $srcRep2; Destination = $oldRep2 }) `
                -AllowedDestinations @($oldDir2, $oldRep2) `
                -ValidateFinal { param($ctx) throw 'injected post-validation failure' } -ValidationContext @{}
        }
        catch { $threwB = $true }
        $restoredB = $threwB -and
            ((Get-Content -LiteralPath (Join-Path $oldDir2 'marker.txt') -Raw) -eq 'old-dnsx') -and
            ((Get-Content -LiteralPath $oldRep2 -Raw) -eq 'old-md') -and
            (-not (Test-Path -LiteralPath (Join-Path $workB 'prepared/dnsx/1.3.1')))
        Add-Result 'transaction-postvalidation-failure-restores' $restoredB 'post-validation failure restored old dir/report'

        # Commit failure: a missing prepared source rolls back everything.
        $rootC = Join-Path $txnTestRoot 'commitfail'
        New-Item -ItemType Directory -Path $rootC -Force | Out-Null
        $oldDir3 = New-FakeInstallDir (Join-Path $rootC 'amass/5.1.1') 'old-amass'
        $oldRep3 = Join-Path $rootC 'tooling-001-report.json'
        [System.IO.File]::WriteAllText($oldRep3, 'old-report3')
        $workC      = Join-Path $rootC '_txn/work'
        $srcDir3    = New-FakeInstallDir (Join-Path $workC 'prepared/amass/5.1.1') 'new-amass'
        $missingSrc = Join-Path $workC 'prepared/amass/9.9.9'
        $secondDest = Join-Path $rootC 'dnsx/1.3.1'
        $threwC = $false
        try {
            Invoke-InstallTransaction -ToolingRootPath $rootC -WorkRoot $workC `
                -InstallMoves @(
                    [ordered]@{ Source = $srcDir3; Destination = $oldDir3 },
                    [ordered]@{ Source = $missingSrc; Destination = $secondDest }
                ) `
                -FileMoves @([ordered]@{ Source = (Join-Path $workC 'prepared-reports/x.json'); Destination = $oldRep3 }) `
                -AllowedDestinations @($oldDir3, $oldRep3, $secondDest) `
                -ValidateFinal { param($ctx) } -ValidationContext @{}
        }
        catch { $threwC = $true }
        $restoredC = $threwC -and
            ((Get-Content -LiteralPath (Join-Path $oldDir3 'marker.txt') -Raw) -eq 'old-amass') -and
            ((Get-Content -LiteralPath $oldRep3 -Raw) -eq 'old-report3') -and
            (-not (Test-Path -LiteralPath $secondDest))
        Add-Result 'transaction-commit-failure-restores' $restoredC 'missing prepared source rolled back to prior state'

        # Unauthorized destination must be refused (no broad destructive scope).
        $rootD = Join-Path $txnTestRoot 'unauthorized'
        New-Item -ItemType Directory -Path $rootD -Force | Out-Null
        $workD   = Join-Path $rootD '_txn/work'
        $srcD    = New-FakeInstallDir (Join-Path $workD 'prepared/x') 'x'
        $badDest = Join-Path $rootD 'not-authorized-dir'
        $threwD = $false
        try {
            Invoke-InstallTransaction -ToolingRootPath $rootD -WorkRoot $workD `
                -InstallMoves @([ordered]@{ Source = $srcD; Destination = $badDest }) `
                -FileMoves @() -AllowedDestinations @(Join-Path $rootD 'other') `
                -ValidateFinal { param($ctx) } -ValidationContext @{}
        }
        catch { $threwD = $true }
        $refusedD = $threwD -and (-not (Test-Path -LiteralPath $badDest))
        Add-Result 'transaction-refuses-unauthorized-destination' $refusedD 'unauthorized destination refused'

        # The validation seam used by the real commit can call script functions.
        $rootE = Join-Path $txnTestRoot 'seam'
        New-Item -ItemType Directory -Path $rootE -Force | Out-Null
        $workE = Join-Path $rootE '_txn/work'
        $srcE  = New-FakeInstallDir (Join-Path $workE 'prepared/x') 'x'
        $destE = Join-Path $rootE 'seam-install'
        Invoke-InstallTransaction -ToolingRootPath $rootE -WorkRoot $workE `
            -InstallMoves @([ordered]@{ Source = $srcE; Destination = $destE }) `
            -FileMoves @() -AllowedDestinations @($destE) `
            -ValidateFinal { param($ctx) [void](Assert-ContainedPath -ParentPath $ctx.Root -ChildPath $ctx.Dest) } `
            -ValidationContext @{ Root = $rootE; Dest = $destE }
        $seamOk = (Test-Path -LiteralPath (Join-Path $destE 'marker.txt'))
        Add-Result 'transaction-validation-seam-resolves-functions' $seamOk 'validation seam can call script functions'
    }
    finally {
        Remove-Item -LiteralPath $txnTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 14. Unexpected-entry counting under StrictMode (zero/one/multiple).
    $ueRoot = Join-Path $env:TEMP ('provision-ue-' + [System.IO.Path]::GetRandomFileName())
    function New-CanonicalFixtureDir {
        param([string]$Path, [string[]]$Extras)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $Path 'subfinder'), 'bin')
        [System.IO.File]::WriteAllText((Join-Path $Path 'subfinder_2.16.0_checksums.txt'), 'sum')
        [System.IO.File]::WriteAllText((Join-Path $Path 'install-manifest.json'), '{}')
        foreach ($e in $Extras) { [System.IO.File]::WriteAllText((Join-Path $Path $e), 'x') }
        return $Path
    }
    try {
        $ueTool = [ordered]@{ name = 'subfinder'; checksums = 'subfinder_2.16.0_checksums.txt' }
        $zeroDir = New-CanonicalFixtureDir (Join-Path $ueRoot 'zero') @()
        $oneDir  = New-CanonicalFixtureDir (Join-Path $ueRoot 'one') @('README.md')
        $manyDir = New-CanonicalFixtureDir (Join-Path $ueRoot 'many') @('README.md', 'LICENSE.md')

        # The raw pipeline result for zero unrolls to $null; the @() wrap is the
        # required safe form (checked without touching .Count on the raw value).
        $rawZero = Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $zeroDir
        Add-Result 'unexpected-raw-zero-unrolls-to-null' ($null -eq $rawZero) 'documented reason for the @() wrap under StrictMode'

        # Prepared/final/existing decisions wrap the call in @() before .Count.
        $zeroPrepared = @(Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $zeroDir)
        $oneFinal     = @(Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $oneDir)
        $manyExisting = @(Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $manyDir)
        Add-Result 'unexpected-zero-count-no-throw' ($zeroPrepared.Count -eq 0) 'zero unexpected entries handled under StrictMode'
        Add-Result 'unexpected-one-count' ($oneFinal.Count -eq 1) 'one unexpected entry counted'
        Add-Result 'unexpected-multiple-count' ($manyExisting.Count -eq 2) 'multiple unexpected entries counted'

        # The exact decision patterns must not throw when there are zero entries.
        $zeroDecisionThrew = $false
        $zeroDecisionTriggered = $false
        $zeroDecisionGuard = $false
        try {
            if (@(Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $zeroDir).Count -eq 0) { $zeroDecisionTriggered = $true }
            if (@(Get-UnexpectedInstallEntries -Tool $ueTool -DestDir $zeroDir).Count -gt 0) { $zeroDecisionGuard = $true }
        }
        catch { $zeroDecisionThrew = $true }
        Add-Result 'unexpected-zero-decision-patterns' `
            ((-not $zeroDecisionThrew) -and $zeroDecisionTriggered -and (-not $zeroDecisionGuard)) `
            'zero-entry decision patterns do not throw'
    }
    finally {
        Remove-Item -LiteralPath $ueRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 15. Empty scratch-parent cleanup (offline, temp directory).
    $spRoot = Join-Path $env:TEMP ('provision-sp-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $spRoot -Force | Out-Null
    try {
        $emptyParent = Join-Path $spRoot '_txn'
        New-Item -ItemType Directory -Path $emptyParent -Force | Out-Null
        $removed = Remove-EmptyContainedDirectory -ParentPath $spRoot -DirPath $emptyParent
        Add-Result 'empty-parent-removed' ($removed -and -not (Test-Path -LiteralPath $emptyParent)) 'empty contained parent removed'

        $nonEmptyParent = Join-Path $spRoot 'keep/_txn'
        New-Item -ItemType Directory -Path $nonEmptyParent -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $nonEmptyParent 'child.txt'), 'x')
        $kept = Remove-EmptyContainedDirectory -ParentPath $spRoot -DirPath $nonEmptyParent
        Add-Result 'non-empty-parent-preserved' `
            ((-not $kept) -and (Test-Path -LiteralPath $nonEmptyParent) -and (Test-Path -LiteralPath (Join-Path $nonEmptyParent 'child.txt'))) `
            'non-empty contained parent preserved'

        $missingRemoved = Remove-EmptyContainedDirectory -ParentPath $spRoot -DirPath (Join-Path $spRoot 'does-not-exist')
        Add-Result 'missing-parent-not-removed' (-not $missingRemoved) 'missing parent is a no-op'

        $filePath = Join-Path $spRoot 'a-file'
        [System.IO.File]::WriteAllText($filePath, 'x')
        $fileRemoved = Remove-EmptyContainedDirectory -ParentPath $spRoot -DirPath $filePath
        Add-Result 'file-not-removed' ((-not $fileRemoved) -and (Test-Path -LiteralPath $filePath)) 'a plain file is not removed'

        Test-Throws 'parent-cleanup-requires-containment' {
            $outside = Join-Path $env:TEMP ('provision-outside-' + [System.IO.Path]::GetRandomFileName())
            New-Item -ItemType Directory -Path $outside -Force | Out-Null
            try { Remove-EmptyContainedDirectory -ParentPath $spRoot -DirPath $outside | Out-Null }
            finally { Remove-Item -LiteralPath $outside -Recurse -Force -ErrorAction SilentlyContinue }
        } 'outside-root parent removal refused'
    }
    finally {
        Remove-Item -LiteralPath $spRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $failed = @($results | Where-Object { -not $_.passed })
    Write-Host ''
    Write-Host '--- Self-test results (offline, no network, no WSL) ---'
    foreach ($r in $results) {
        $mark = if ($r.passed) { 'PASS' } else { 'FAIL' }
        Write-Host ("  [{0}] {1}" -f $mark, $r.check)
    }
    Write-Host ''
    Write-Host ("Self-test: {0} passed, {1} failed." -f ($results.Count - $failed.Count), $failed.Count)
    return $results
}


# --- Resolve project root and tooling root -----------------------------------

if (-not $RepoRoot) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepoRoot = Split-Path -Parent $scriptDir
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'src'))) {
    throw "RepoRoot '$RepoRoot' does not look right (no 'src' folder found)."
}
if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
    throw "RepoRoot '$RepoRoot' is not a directory."
}

$ToolingRootPath = Join-Path $RepoRoot $ToolingRoot
$ToolingRootPath = [System.IO.Path]::GetFullPath($ToolingRootPath)
# Fail closed: the tooling root must be inside the project root.
$ToolingRootPath = Assert-ContainedPath -ParentPath $RepoRoot -ChildPath $ToolingRootPath

if ($SelfTest) {
    $results = Invoke-SelfTest -ToolingRootPath $ToolingRootPath -RepoRoot $RepoRoot
    $failed = @($results | Where-Object { -not $_.passed })
    if ($failed.Count -gt 0) { exit 1 }
    exit 0
}

$selected = @($ToolMatrix | Where-Object { $Tools -contains $_.name })
if ($selected.Count -eq 0) {
    throw 'No tools selected. Nothing to do.'
}

Write-Host '=== TOOLING-001 provisioning: pinned recon tools (project-local, WSL) ==='
Write-Host ''
Write-Host 'Preflight (read-only):'

if ($DryRun) {
    Write-Host '  [dry-run] skipping live WSL probes'
}
else {
    $wslSource = Invoke-Preflight
}

Write-Host ("  project root       : {0}" -f $RepoRoot)
Write-Host ("  tooling root       : {0}" -f $ToolingRootPath)
Write-Host ("  allowlisted hosts  : {0}" -f ($AllowedHosts -join ', '))
Write-Host ''

# Plan / summary table.
Write-Host 'Plan:'
foreach ($tool in $selected) {
    Write-Host ("  {0} {1}" -f $tool.name, $tool.version)
    Write-Host ("    artifact : {0}" -f ($tool.url_base + $tool.artifact))
    Write-Host ("    checksums: {0}" -f ($tool.url_base + $tool.checksums))
    Write-Host ("    install  : {0}" -f (Join-Path $ToolingRootPath (Join-Path $tool.name $tool.version)))
}
Write-Host ''

if ($DryRun) {
    Write-Host 'Dry run complete. No download, no extraction, no install.'
    exit 0
}

Write-Host 'Running offline fail-closed self-tests ...'
$stResults = Invoke-SelfTest -ToolingRootPath $ToolingRootPath -RepoRoot $RepoRoot
$stFailed = @($stResults | Where-Object { -not $_.passed })
if ($stFailed.Count -gt 0) {
    throw 'Offline self-tests failed; refusing to proceed.'
}
Write-Host ''

# --- Transactional provisioning (prepare -> commit -> validate) --------------

$finalReportJson = Join-Path $ToolingRootPath $ReportJsonName
$finalReportMd   = Join-Path $ToolingRootPath $ReportMdName
[void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $finalReportJson)
[void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $finalReportMd)

# Exact authorized destinations: only these may ever be replaced.
$authorizedDirs = @()
foreach ($tool in $selected) {
    $authorizedDirs += (Join-Path $ToolingRootPath (Join-Path $tool.name $tool.version))
}
$authorizedDestinations = @($authorizedDirs + @($finalReportJson, $finalReportMd))

$txnId    = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [System.IO.Path]::GetRandomFileName()
$workRoot = Join-Path $ToolingRootPath (Join-Path $TxnDir $txnId)
[void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $workRoot)

$evidence      = [System.Collections.Generic.List[object]]::new()
$installMoves  = @()
$fileMoves     = @()
$selectedTools = @($selected)

try {
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null

    # Prepare phase: build and validate every replacement in contained staging.
    foreach ($tool in $selectedTools) {
        Write-Host ("--- {0} {1} ---" -f $tool.name, $tool.version)
        $destDir = Join-Path $ToolingRootPath (Join-Path $tool.name $tool.version)
        [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $destDir)
        $state = Get-ExistingInstallState -Tool $tool -DestDir $destDir

        if ($state -eq 'foreign') {
            throw "Existing content at '$destDir' is not a recognized TOOLING-001 install. Refusing."
        }
        if ($state -eq 'complete') {
        $unexpected = @(Get-UnexpectedInstallEntries -Tool $tool -DestDir $destDir)
        if ($unexpected.Count -eq 0) {
                Write-Host '  existing install   : canonical; validating and reusing (no replacement).'
                $evidence.Add((Get-ReuseEvidence -Tool $tool -DestDir $destDir -ToolingRootPath $ToolingRootPath))
                Write-Host ''
                continue
            }
            Write-Host ("  existing install   : non-canonical (unexpected: {0}); staging canonical replacement." -f ($unexpected -join ', '))
        }
        elseif ($state -eq 'partial') {
            Write-Host '  existing install   : partial; staging canonical replacement.'
        }
        else {
            Write-Host '  existing install   : absent; staging fresh install.'
        }

        $prepared = New-CanonicalInstall -Tool $tool -RepoRoot $RepoRoot -ToolingRootPath $ToolingRootPath `
            -WorkRoot $workRoot -FinalInstallDir $destDir -AllowedHostsList $AllowedHosts
        $evidence.Add($prepared)
        $installMoves += [ordered]@{ Source = [string]$prepared.prepared_dir; Destination = $destDir }
        Write-Host ''
    }

    # Prepare final reports in staging so they can be committed atomically.
    $preparedReportsDir = Join-Path $workRoot 'prepared-reports'
    [void](Assert-ContainedPath -ParentPath $ToolingRootPath -ChildPath $preparedReportsDir)
    New-Item -ItemType Directory -Path $preparedReportsDir -Force | Out-Null
    $reportContent = New-ReportContent -ProjectRoot $RepoRoot -ToolingRootPath $ToolingRootPath `
        -AllowedHostsList $AllowedHosts -Evidence $evidence
    $preparedReportJson = Join-Path $preparedReportsDir $ReportJsonName
    $preparedReportMd   = Join-Path $preparedReportsDir $ReportMdName
    Write-NoBomText -Path $preparedReportJson -Text $reportContent.Json
    Write-NoBomText -Path $preparedReportMd -Text $reportContent.Markdown
    $fileMoves += [ordered]@{ Source = $preparedReportJson; Destination = $finalReportJson }
    $fileMoves += [ordered]@{ Source = $preparedReportMd; Destination = $finalReportMd }

    # Commit phase plus post-commit validation, with rollback on any failure.
    $validationContext = @{
        Selected      = $selectedTools
        ToolingRoot   = $ToolingRootPath
        FinalJson     = $finalReportJson
        FinalMd       = $finalReportMd
        ExpectedTools = @($selectedTools | ForEach-Object { $_.name })
        AllowedHosts  = $AllowedHosts
    }
    $validateFinal = {
        param($ctx)
        foreach ($tool in $ctx.Selected) {
            $finalDir = Join-Path $ctx.ToolingRoot (Join-Path $tool.name $tool.version)
            [void](Assert-FinalInstall -Tool $tool -FinalDir $finalDir -ToolingRootPath $ctx.ToolingRoot)
        }
        [void](Assert-FinalReports -JsonPath $ctx.FinalJson -MdPath $ctx.FinalMd `
            -ExpectedTools $ctx.ExpectedTools -AllowedHostsList $ctx.AllowedHosts -ToolingRootPath $ctx.ToolingRoot)
    }

    Write-Host 'Committing install transaction ...'
    Invoke-InstallTransaction -ToolingRootPath $ToolingRootPath -WorkRoot $workRoot `
        -InstallMoves $installMoves -FileMoves $fileMoves `
        -AllowedDestinations $authorizedDestinations -ValidateFinal $validateFinal `
        -ValidationContext $validationContext
    Write-Host 'Transaction committed and validated.'
}
catch {
    Write-Warning ('Provisioning transaction failed: {0}' -f $_.Exception.Message)
    throw
}
finally {
    # Remove all transaction scratch. On failure the rollback has already
    # restored every authorized old directory/report, so only scratch remains.
    if (Test-Path -LiteralPath $workRoot) {
        Remove-ContainedPath -ParentPath $ToolingRootPath -ChildPath $workRoot
    }
    # Remove the now-empty _txn parent, but never a non-empty one.
    [void](Remove-EmptyContainedDirectory -ParentPath $ToolingRootPath -DirPath (Join-Path $ToolingRootPath $TxnDir))
}


# The JSON/Markdown reports were prepared, committed, and validated by the
# transaction above. Record the final canonical paths for the console summary.

Write-Host '=== Provisioning complete ==='
Write-Host ("  JSON report    : {0}" -f $finalReportJson)
Write-Host ("  Markdown report: {0}" -f $finalReportMd)
Write-Host ''
Write-Host 'Reminder: this package installs tooling only. Do NOT run the binaries'
Write-Host 'against any domain. Only "--version" and "--help" are authorized.'

