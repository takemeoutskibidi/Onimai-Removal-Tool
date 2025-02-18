using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using static SeroXen_Removal_Tool.Native;

namespace SeroXen_Removal_Tool
{
    /// <summary>
    /// Credits to @C5Hackr for the Original SeroXen Removal Tool source code, couldn't of made half of this without his tool.
    /// Credits to @MrThunker for getting detected by Hyperion anticheat
    /// Credits to @Roblox for detecting Onimai
    /// 
    /// Remember, a detection isn't something to flex.
    /// 
    /// OH AND I SENT THIS TO ANTIVIRUS COMPANY!!!!!!!!!!!!!!
    /// 
    /// Ok so all the bullshit out the way this is the official source code to Onimai Removal Tool, which was proudly made by R_0!
    /// 
    /// This tool cannot:
    /// 
    /// - Remove a Bootkit
    /// 
    /// This tool can:
    /// 
    /// - Kill Onimai
    /// - Detected Onimai
    /// - Make sure Onimai stops working
    /// - Give tips to removing Onimai's new bootkit (1.9.9) Update
    /// </summary>

    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeleteFile(string lpFileName);

        const string SystemDir = @"C:\WINDOWS\System32\drivers\";
        const string TargetFile = "ACPIx86.sys";

        static unsafe void Main(string[] args)
        {
            if (!IsAdmin())
            {
                Console.WriteLine("Onimai Removal Tool - 1.9.9");
                Console.WriteLine("");
                if (!Confirm("[+] Onimai Removal Tool Requires Admin, do you want to restart with Admin?", true))
                    return;

                try
                {
                    Restart(true);
                }
                catch
                {
                    Console.WriteLine("");
                    Console.WriteLine("[+] Onimai Removal Tool failed to restart with admin.");
                    Console.ReadKey(true);
                }

                return;
            }
            try
            {
            }
            catch
            {
            }

            Process.EnterDebugMode();

            var iocs = ScanIOCs();

            if (iocs.Length > 0)
            {
                Console.WriteLine("\n[+] Detected IOC's.");

                if (iocs.Contains(IndicatorOfCompromise.Process))
                {
                    IOCCleaner.CleanProcesses();
                }

                foreach (var ioc in iocs)
                {
                    switch (ioc)
                    {
                        case IndicatorOfCompromise.Files:
                            IOCCleaner.CleanFiles();
                            break;

                        case IndicatorOfCompromise.ScheduledTask:
                            IOCCleaner.CleanScheduledTask();
                            break;

                        case IndicatorOfCompromise.Environment:
                            IOCCleaner.CleanEnvironment();
                            break;

                        case IndicatorOfCompromise.Registry:
                            IOCCleaner.CleanRegistry();
                            break;
                    }
                }

                Console.WriteLine("[+] Starting Cleanup.");

                Console.WriteLine("[+] Please reboot your Computer after running this tool.");
                Console.WriteLine("[+] Press any button to exit.");
            }
            else
            {
                Console.WriteLine("[+] No IOC's where detected, press any button to exit.");
            }

            Console.ReadKey(true);
        }

        static bool Confirm(string prompt, bool @default = false)
        {
            while (true) {
                Console.Write($"{prompt} [{(@default ? "Y" : "y")}/{(@default ? "n" : "N")}] ");

                var key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine(@default ? "Yes" : "No");
                    return @default;
                }

                switch (key.KeyChar.ToString().ToLower())
                {
                    case "y":
                        Console.WriteLine("Yes");
                        return true;

                    case "n":
                        Console.WriteLine("No");
                        return false;

                    default:
                        Console.WriteLine();
                        break;
                }
            }
        }

        static bool IsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void Restart(bool runas = false, string args = "")
        {
            Process.Start(new ProcessStartInfo()
            {
                FileName = Assembly.GetExecutingAssembly().Location,
                Arguments = args,
                Verb = runas ? "runas" : "",
            });

            Environment.Exit(0);
        }

        static IndicatorOfCompromise[] ScanIOCs()
        {
            var list = new List<IndicatorOfCompromise>();

            if (IOCDetector.RootkitIOC())
            {
                Console.WriteLine("[+] Onimai Rootkit detected.");
                list.Add(IndicatorOfCompromise.Rootkit);

                IOCCleaner.DetachRootkit();
            }

            if (IOCDetector.FilesIOC())
            {
                Console.WriteLine("[+] Onimai Infected files detected.");
                list.Add(IndicatorOfCompromise.Files);
            }

            if (IOCDetector.ScheduledTaskIOC())
            {
                Console.WriteLine("[+] Onimai Scheduled task detected.");
                list.Add(IndicatorOfCompromise.ScheduledTask);
            }

            if (IOCDetector.RegistryIOC())
            {
                Console.WriteLine("[+] Onimai registry value detected.");
                list.Add(IndicatorOfCompromise.Registry);
            }

            if (IOCDetector.EnvironmentIOC())
            {
                Console.WriteLine("[+] Onimai enviromental variable detected.");
                list.Add(IndicatorOfCompromise.Environment);
            }

            if (IOCDetector.ProcessesIOC())
            {
                Console.WriteLine("[+] Onimai is currently running.");
                list.Add(IndicatorOfCompromise.Process);
            }

            return list.ToArray();
        }
    }

    internal enum IndicatorOfCompromise
    {
        Files,
        ScheduledTask,
        Registry,
        Environment,
        Process,
        Rootkit,
        KillLOLBins,
        ScanUEFI,
        FailSafeMech
    }

    internal static class IOCDetector
    {
        public static bool FilesIOC()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            var mstha = Path.Combine(windows, "$nya-mshta.exe");
            var cmd = Path.Combine(windows, "$nya-cmd.exe");
            var powershell = Path.Combine(windows, "$nya-powershell.exe");

            var any = Directory.GetFiles(windows).Any(filename => filename.ToLower().StartsWith("$nya") && filename.ToLower().EndsWith(".exe"));

            return File.Exists(mstha) || File.Exists(cmd) || File.Exists(powershell) || any;
        }

        public static bool ScheduledTaskIOC()
        {
            using var sched = new TaskService();

            if (sched.RootFolder.Tasks.Any(task => task.Name.ToLower().StartsWith("$nya")))
                return true;

            return false;
        }

        public unsafe static bool RootkitIOC()
        {
            var module = Native.GetModuleHandle(null);
            if (module == IntPtr.Zero)
                return false;

            var signature = *(ushort*)(module.ToInt64() + 64);

            return signature == 0x7260;
        }

        public static bool RegistryIOC()
        {
            return Registry.LocalMachine.OpenSubKey("SOFTWARE").GetValueNames().Any(name => name.ToLower().StartsWith("$nya"));
        }

        public static bool EnvironmentIOC()
        {
            foreach (var key in Environment.GetEnvironmentVariables().Keys) {
                if (key.ToString().ToLower().StartsWith("$nya"))
                    return true;
            }

            return false;
        }

        public static bool ProcessesIOC()
        {
            var names = new string[] { "$nya-cmd", "$nya-mshta", "$nya-powershell" };

            return Process.GetProcesses().Any(proc => names.Contains(proc.ProcessName));
        }
    }

    internal static class IOCCleaner
    {
        public static void CleanFiles()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var files = Directory.GetFiles(windows, "$nya*.exe");

            Console.WriteLine("[+] Deleting files.");

            foreach (var file in files)
            {
                Thread.Sleep(1000);
                try
                {
                    File.Delete(file);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Failed to delete file {file}: {ex.Message}!");
                }
            }
        }

        public static void CleanScheduledTask()
        {
            using var sched = new TaskService();

            Console.WriteLine("[+] Removing scheduled tasks...");

            var tasks = sched.AllTasks.Where(task => task.Name.ToLower().StartsWith("$nya"));

            foreach (var task in tasks)
                task.Folder.DeleteTask(task.Name);
        }

        public static void CleanRegistry()
        {
            using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
            var names = key.GetValueNames().Where(name => name.ToLower().StartsWith("$nya"));

            Console.WriteLine("[+] Removing registry values.");

            foreach (var name in names)
                key.DeleteValue(name);
        }

        public static void CleanEnvironment()
        {
            Console.WriteLine("[+] Cleaning enviromental variables.");

            foreach (var key in Environment.GetEnvironmentVariables().Keys)
                if (key.ToString().ToLower().StartsWith("$nya"))
                {
                    Environment.SetEnvironmentVariable(key.ToString(), null, EnvironmentVariableTarget.Machine);
                    Environment.SetEnvironmentVariable(key.ToString(), null, EnvironmentVariableTarget.Process);
                }
        }

        public static void CleanProcesses()
        {
            var names = new string[] { "$nya-cmd", "$nya-mshta", "$nya-powershell" };
            var processes = Process.GetProcesses().Where(proc => names.Contains(proc.ProcessName));

            int value = 0;

            Console.WriteLine("[+] Killing process.");

            foreach (var process in processes)
                Native.NtSetInformationProcess(process.Handle, 0x1D, ref value, sizeof(int));

            foreach (var process in processes)
                process.Kill();
        }

        public static void DetachRootkit()
        {
            Console.WriteLine("[+] Detatching Rootkit.");
            Unhook.UnhookDll("ntdll.dll");
            Unhook.UnhookDll("kernel32.dll");
            Unhook.UnhookDll("advapi32.dll");
            Unhook.UnhookDll("user32.dll");
            Unhook.UnhookDll("ws2_32.dll");
            Unhook.UnhookDll("wininet.dll");
            Unhook.UnhookDll("mscoree.dll");
            Unhook.UnhookDll("uxtheme.dll");
            Unhook.UnhookDll("dbghelp.dll");
            Unhook.UnhookDll("vmdrv.dll");
            Unhook.UnhookDll("dxgkrnl.dll");
            Unhook.UnhookDll("sechost.dll");
            Unhook.UnhookDll("taskschd.dll");
            Unhook.UnhookDll("pdh.dll");
            Unhook.UnhookDll("psapi.dll");
        }

        public static void ScanUEFI()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Unknown || drive.DriveType == DriveType.Removable)
                {
                    string espPath = $"{drive.Name}EFI\\Microsoft\\Boot\\bootmgfw.efi";
                    if (!File.Exists(espPath))
                    {
                        Console.WriteLine($"[+] Infected bootloader: {espPath}");
                    }
                }
            }
        }

        // Scan UEFI wont work OwO

        public static void FailSafeMech()
        {
            Console.WriteLine("[+] Running SFC.");
            RunCommand("sfc /scannow");
            Console.WriteLine("[+] Running DISM.");
            RunCommand("DISM /Online /Cleanup-Image /RestoreHealth");
        }

        public static void KillLOLBins()
        {
            string[] lolbins = { "$nya-mshta", "$nya-regsvr32", "$nya-wscript", "$nya-cscript", "$nya-powershell" };

            foreach (var processName in lolbins)
            {
                foreach (var process in Process.GetProcessesByName(processName))
                {
                    process.Kill();
                    Console.WriteLine($"[+] Killed LOLBin process: {processName}");
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void ReEnableAMSI()
        {
            IntPtr hModule = LoadLibrary("amsi.dll");
            if (hModule == IntPtr.Zero)
                return;

            IntPtr addr = GetProcAddress(hModule, "AmsiScanBuffer");
            if (addr == IntPtr.Zero)
                return;

            uint oldProtect;
            VirtualProtect(addr, (UIntPtr)5, 0x40, out oldProtect);
            byte[] patch = new byte[] { 0x48, 0x83, 0xEC, 0x28, 0xC3 };
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (UIntPtr)5, oldProtect, out oldProtect);
        }

        static void RunCommand(string command)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + command;
            process.StartInfo.Verb = "runas";
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.OutputDataReceived += (sender, args) => Console.WriteLine(args.Data);
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();
        }
    }

    internal static class Native
    {
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x20007;

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, long dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(
           string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
           IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
    }
}
