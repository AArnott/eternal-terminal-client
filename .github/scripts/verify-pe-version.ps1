# Verify Windows PE VERSIONINFO on the built et.exe.
# Usage: verify-pe-version.ps1 -ExePath <path> -ExpectedVersion <x.y.z> [-RepositoryUrl <url>]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExePath,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedVersion,

    [string] $RepositoryUrl = "https://github.com/AArnott/eternal-terminal-client"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

$fullPath = (Resolve-Path -LiteralPath $ExePath).Path
$v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath)

Write-Host "FileDescription : $($v.FileDescription)"
Write-Host "ProductName     : $($v.ProductName)"
Write-Host "ProductVersion  : $($v.ProductVersion)"
Write-Host "FileVersion     : $($v.FileVersion)"
Write-Host "LegalCopyright  : $($v.LegalCopyright)"
Write-Host "Language        : $($v.Language)"
Write-Host "Comments        : $($v.Comments)"

if (-not $v.FileDescription) { throw "FileDescription is empty" }
if (-not $v.ProductName) { throw "ProductName is empty" }
if ($v.ProductVersion -ne $ExpectedVersion) {
    throw "ProductVersion '$($v.ProductVersion)' != expected '$ExpectedVersion'"
}
if ($v.FileVersion -notlike "$ExpectedVersion*") {
    throw "FileVersion '$($v.FileVersion)' does not start with '$ExpectedVersion'"
}
if (-not $v.LegalCopyright) { throw "LegalCopyright is empty" }
if ($v.Comments -ne $RepositoryUrl) {
    throw "Comments (repo URL) expected '$RepositoryUrl', got '$($v.Comments)'"
}

# Custom StringFileInfo "Repository" via VerQueryValue
$peVerType = @"
using System;
using System.Runtime.InteropServices;

public static class PeVer {
    [DllImport("version.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool GetFileVersionInfo(string f, int h, int s, byte[] d);

    [DllImport("version.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int GetFileVersionInfoSize(string f, out int h);

    [DllImport("version.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool VerQueryValue(byte[] b, string sp, out IntPtr p, out uint l);

    public static string GetString(string path, string name) {
        int handle;
        int size = GetFileVersionInfoSize(path, out handle);
        if (size <= 0) throw new Exception("GetFileVersionInfoSize failed");
        byte[] buf = new byte[size];
        if (!GetFileVersionInfo(path, 0, size, buf)) {
            throw new Exception("GetFileVersionInfo failed");
        }
        IntPtr p;
        uint len;
        // Common en-US code pages used in VERSIONINFO blocks
        string[] prefixes = {
            "\\StringFileInfo\\040904B0\\",
            "\\StringFileInfo\\040904E4\\"
        };
        foreach (var pre in prefixes) {
            if (VerQueryValue(buf, pre + name, out p, out len) && len > 1) {
                return Marshal.PtrToStringUni(p);
            }
        }
        return null;
    }
}
"@

if (-not ("PeVer" -as [type])) {
    Add-Type -TypeDefinition $peVerType
}

$customRepo = [PeVer]::GetString($fullPath, "Repository")
Write-Host "Repository      : $customRepo"
if ($customRepo -ne $RepositoryUrl) {
    throw "Custom property Repository expected '$RepositoryUrl', got '$customRepo'"
}

Write-Host "PE version resources OK."
