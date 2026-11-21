# Isolated test process only. No account creation, credential reading or persistent changes.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class CaisPrivateAclProbe {
    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disabledCount, [In] SidAndAttributes[] disabled, uint deleteCount, IntPtr deleted, uint restrictedCount, IntPtr restricted, out IntPtr result);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    static void Must(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void Open(string path) {
        using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {}
    }
    public static bool Check(string path) {
        Open(path); // Positive control: the ordinary owner can actually open it.
        IntPtr token = IntPtr.Zero, restricted = IntPtr.Zero, sidMemory = IntPtr.Zero;
        bool impersonating = false;
        try {
            Must(OpenProcessToken(GetCurrentProcess(), 0x000E, out token)); // duplicate/query/impersonate
            SecurityIdentifier sid = WindowsIdentity.GetCurrent().User;
            byte[] bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            sidMemory = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, sidMemory, bytes.Length);
            SidAndAttributes[] disabled = { new SidAndAttributes { Sid = sidMemory, Attributes = 0 } };
            Must(CreateRestrictedToken(token, 1, 1, disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted));
            Must(ImpersonateLoggedOnUser(restricted)); impersonating = true;
            try { Open(path); return false; }
            catch (UnauthorizedAccessException) { return true; }
        } finally {
            if (impersonating) Must(RevertToSelf());
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (sidMemory != IntPtr.Zero) Marshal.FreeHGlobal(sidMemory);
        }
    }
}
'@
if (-not [CaisPrivateAclProbe]::Check($env:CAIS_ACL_TEST_PATH)) { exit 1 }
