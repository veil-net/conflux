# Install conflux on Windows: this machine's binary from a conflux release, checked against the
# release's SHA256SUMS, as C:\Program Files\conflux\conflux.exe, on the machine's PATH.
#
#   irm https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.ps1 | iex
#
# In PowerShell as Administrator, which conflux needs for everything after this as well. It
# installs the binary and nothing else. No boot service, no enrolment, no network joined: that is
# `conflux up`, which is yours to run. Run again, it replaces an older conflux with the release's;
# `conflux update` does the same, and moves a running anchor onto it as well.
#
# Two settings, set in the session first:
#
#   $env:CONFLUX_VERSION = '1.0.0'        a release tag, rather than latest
#   $env:CONFLUX_INSTALL_DIR = 'D:\bin'   where conflux goes, rather than Program Files
#
# Windows PowerShell 5.1 as well as PowerShell 7. Invoke-Expression runs this in the session that
# typed it, so nothing here exits that session: a failure throws. All of it is one script block,
# so a download cut short runs nothing.
& {
    $ErrorActionPreference = 'Stop'

    # Windows PowerShell redraws a progress bar for every chunk, and takes minutes over 55 MB
    # doing it; and it may offer GitHub nothing newer than TLS 1.1, which GitHub refuses.
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Fail([string] $message) { throw "install.ps1: $message" }

    # FirstLine is the first line conflux at $path says to `version`, or nothing if it does not
    # run.
    function FirstLine([string] $path) {
        try { $out = @(& $path version) } catch { return $null }
        if ($LASTEXITCODE -ne 0) { return $null }
        return $out[0]
    }

    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        Fail 'this is not Windows: run install.sh, as https://github.com/veil-net/conflux says'
    }

    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail "run this in PowerShell as Administrator: conflux goes onto the machine's PATH, and every conflux command that changes the machine needs it too"
    }

    # The machine's own architecture, not this process's: an x64 PowerShell on Arm64 Windows is
    # emulated, and the arm64 build runs natively.
    try {
        $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $arch = $null # a .NET older than 4.7.1, which has no RuntimeInformation
    }
    if (-not $arch) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    $arch = switch ($arch) {
        { $_ -in 'X64', 'AMD64' } { 'amd64' }
        'Arm64' { 'arm64' }
        default { Fail "conflux has no build for $arch Windows" }
    }

    $repo = 'veil-net/conflux'
    $tag = if ($env:CONFLUX_VERSION) { $env:CONFLUX_VERSION } else { 'latest' }
    $dir = if ($env:CONFLUX_INSTALL_DIR) { $env:CONFLUX_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'conflux' }
    $dir = [IO.Path]::GetFullPath($dir).TrimEnd('\')
    $exe = Join-Path $dir 'conflux.exe'
    $asset = "conflux-windows-$arch.exe"
    $base = "https://github.com/$repo/releases/download/$tag"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('conflux-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $old = $null

    try {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
        } catch {
            Fail "could not download $base/SHA256SUMS ($($_.Exception.Message)); is $tag a conflux release?"
        }

        $want = $null
        foreach ($line in Get-Content -LiteralPath "$tmp\SHA256SUMS") {
            $sum, $name = -split $line
            if ($name -eq $asset) { $want = $sum.ToLowerInvariant() }
        }
        if (-not $want) { Fail "conflux $tag has no build for windows/$arch" }

        $have = $null
        if (Test-Path -LiteralPath $exe) {
            $have = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        }

        if ($have -eq $want) {
            Write-Host "$exe is already the $tag release's conflux: $(FirstLine $exe)"
        } else {
            if ($have) { $old = FirstLine $exe }

            Write-Host "Downloading $asset from conflux's $tag release"
            $new = Join-Path $tmp 'conflux.exe'
            try {
                Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $new
            } catch {
                Fail "could not download $base/$asset ($($_.Exception.Message))"
            }

            $got = (Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($got -ne $want) { Fail "$asset's SHA-256 is $got, and SHA256SUMS says $want, so nothing was installed" }

            # Run once before it replaces anything: the digest says these are the release's bytes,
            # this says they are a conflux that starts on this machine.
            $now = FirstLine $new
            if ("$now" -notlike 'conflux *') { Fail 'the downloaded conflux does not run on this machine, so nothing was installed' }

            # Windows will not replace the image of a running conflux.exe, but will rename it, so
            # the old one is moved aside to conflux.exe.old, and put back if the new one cannot go
            # in. `conflux update` does the same, and removes what an earlier one left.
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            if ($have) {
                Remove-Item -LiteralPath "$exe.old" -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $exe -Destination "$exe.old" -Force
            }
            try {
                Move-Item -LiteralPath $new -Destination $exe
            } catch {
                if ($have) { Move-Item -LiteralPath "$exe.old" -Destination $exe -Force }
                throw
            }
            Remove-Item -LiteralPath "$exe.old" -Force -ErrorAction SilentlyContinue

            Write-Host "Installed ${exe}: $now."
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # On the machine's PATH, as the registry holds it: read unexpanded and written back as the
    # same kind, since a round trip through [Environment] would expand every %SystemRoot% in it.
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
    try {
        $path = [string] $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (@($path -split ';' | ForEach-Object { $_.TrimEnd('\') }) -notcontains $dir) {
            $key.SetValue('Path', $path.TrimEnd(';') + ';' + $dir, $key.GetValueKind('Path'))

            # Told to every window, Explorer's above all, so that what opens from it next has it.
            if (-not ('Conflux.Install.Native' -as [type])) {
                Add-Type -Namespace Conflux.Install -Name Native -MemberDefinition '
                    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
                    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
            }
            $result = [UIntPtr]::Zero
            [void] [Conflux.Install.Native]::SendMessageTimeout([IntPtr] 0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref] $result)

            Write-Host "Added $dir to the machine's PATH. A PowerShell already open finds conflux once reopened; this one does now."
        }
    } finally {
        $key.Close()
    }

    # This session read PATH before it changed.
    if (@($env:Path -split ';' | ForEach-Object { $_.TrimEnd('\') }) -notcontains $dir) {
        $env:Path = $env:Path.TrimEnd(';') + ';' + $dir
    }

    $found = Get-Command conflux -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found -and $found.Source -ne $exe) {
        Write-Host ''
        Write-Host "Your PATH finds another conflux first, at $($found.Source). This one is $exe."
    }

    if ($old) {
        Write-Host ''
        Write-Host "It replaced $old. If this machine already runs an anchor, 'conflux start' moves it onto this one."
    }

    Write-Host ''
    Write-Host 'Nothing has been started. To put this machine on a VeilNet network, start a network,'
    Write-Host 'which prints the taint other machines join it with:'
    Write-Host ''
    Write-Host '  conflux up'
    Write-Host ''
    Write-Host 'or join the network a taint names:'
    Write-Host ''
    Write-Host '  conflux up --taint TAINT'
    Write-Host ''
    Write-Host "In PowerShell as Administrator. See https://github.com/$repo for the rest."
}
