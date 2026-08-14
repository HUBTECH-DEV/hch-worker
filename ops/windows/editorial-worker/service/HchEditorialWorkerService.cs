using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Reflection;

[assembly: AssemblyTitle("HCH Editorial Worker Service")]
[assembly: AssemblyDescription("Native Windows service host for the HUBTECH Community Hub editorial worker")]
[assembly: AssemblyCompany("HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA")]
[assembly: AssemblyProduct("HCH Editorial Worker")]
[assembly: AssemblyCopyright("Copyright HUBTECH-DEV")]
[assembly: AssemblyVersion("3.1.0.0")]
[assembly: AssemblyFileVersion("3.1.0.0")]
[assembly: AssemblyInformationalVersion("3.1.0")]

namespace Hch.EditorialWorker.ServiceHost
{
    internal sealed class HchEditorialWorkerService : ServiceBase
    {
        private readonly string powershellPath;
        private readonly string runnerPath;
        private readonly string heartbeatRunnerPath;
        private readonly string controlCliPath;
        private readonly string configPath;
        private readonly string nodePath;
        private readonly string dashboardServerPath;
        private readonly string dashboardRoot;
        private readonly int dashboardPort;
        private readonly string tempRoot;
        private readonly int pollSeconds;
        private readonly int stopTimeoutSeconds;
        private readonly ManualResetEvent stopRequested = new ManualResetEvent(false);
        private readonly object processLock = new object();
        private Thread loopThread;
        private Thread heartbeatThread;
        private Thread dashboardThread;
        private Process activeCycle;
        private Process dashboardProcess;

        internal HchEditorialWorkerService(IDictionary<string, string> options)
        {
            ServiceName = Required(options, "service-name");
            powershellPath = CanonicalFile(Required(options, "powershell"));
            runnerPath = CanonicalFile(Required(options, "runner"));
            heartbeatRunnerPath = CanonicalFile(Required(options, "heartbeat-runner"));
            controlCliPath = CanonicalFile(Required(options, "control-cli"));
            configPath = CanonicalFile(Required(options, "config"));
            nodePath = CanonicalFile(Required(options, "node"));
            dashboardServerPath = CanonicalFile(Required(options, "dashboard-server"));
            dashboardRoot = CanonicalDirectory(Required(options, "dashboard-root"));
            dashboardPort = BoundedInteger(options, "dashboard-port", 4319, 1, 65535);
            tempRoot = CanonicalDirectory(Required(options, "temp-root"));
            pollSeconds = BoundedInteger(options, "poll-seconds", 15, 3, 3600);
            stopTimeoutSeconds = BoundedInteger(options, "stop-timeout-seconds", 3600, 30, 86400);
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            stopRequested.Reset();
            loopThread = new Thread(RunLoop);
            loopThread.IsBackground = true;
            loopThread.Name = "HCH editorial worker service loop";
            loopThread.Start();
            heartbeatThread = new Thread(RunHeartbeatLoop);
            heartbeatThread.IsBackground = true;
            heartbeatThread.Name = "HCH editorial worker node heartbeat loop";
            heartbeatThread.Start();
            dashboardThread = new Thread(RunDashboardSupervisor);
            dashboardThread.IsBackground = true;
            dashboardThread.Name = "HCH local dashboard supervisor";
            dashboardThread.Start();
        }

        protected override void OnStop()
        {
            StopCooperatively();
        }

        protected override void OnShutdown()
        {
            StopCooperatively();
            base.OnShutdown();
        }

        private void StopCooperatively()
        {
            // Prevent a new cycle from starting before local drain is persisted.
            stopRequested.Set();
            InvokeLocalDrain();

            DateTime deadline = DateTime.UtcNow.AddSeconds(stopTimeoutSeconds);
            while (loopThread != null && loopThread.IsAlive && DateTime.UtcNow < deadline)
            {
                RequestAdditionalTime(10000);
                if (loopThread.Join(1000))
                {
                    break;
                }
            }
            while (heartbeatThread != null && heartbeatThread.IsAlive && DateTime.UtcNow < deadline)
            {
                RequestAdditionalTime(10000);
                if (heartbeatThread.Join(1000))
                {
                    break;
                }
            }
            StopDashboardProcess();
            while (dashboardThread != null && dashboardThread.IsAlive && DateTime.UtcNow < deadline)
            {
                RequestAdditionalTime(10000);
                if (dashboardThread.Join(1000)) break;
            }
            // Never kill an active generator. Its journal and lease remain the
            // authority if Windows forcibly terminates the host after this bound.
        }

        private void RunDashboardSupervisor()
        {
            int[] delays = new int[] { 5, 15, 60, 60, 60 };
            int failures = 0;
            DateTime windowStarted = DateTime.UtcNow;
            while (!stopRequested.WaitOne(0))
            {
                Process process = null;
                try
                {
                    process = StartDashboard();
                    lock (processLock) { dashboardProcess = process; }
                    process.WaitForExit();
                    if (stopRequested.WaitOne(0)) return;
                    if ((DateTime.UtcNow - windowStarted).TotalMinutes >= 5)
                    {
                        failures = 0;
                        windowStarted = DateTime.UtcNow;
                    }
                    failures++;
                    WriteOperationalEvent("worker-dashboard-exited", EventLogEntryType.Warning);
                    if (failures > delays.Length)
                    {
                        WriteOperationalEvent("worker-dashboard-restart-limit", EventLogEntryType.Error);
                        return;
                    }
                    if (stopRequested.WaitOne(TimeSpan.FromSeconds(delays[failures - 1]))) return;
                }
                catch (Exception error)
                {
                    WriteOperationalEvent("worker-dashboard-start-failed:" + SafeCode(error.GetType().Name), EventLogEntryType.Error);
                    return;
                }
                finally
                {
                    lock (processLock)
                    {
                        if (ReferenceEquals(dashboardProcess, process)) dashboardProcess = null;
                    }
                    if (process != null) process.Dispose();
                }
            }
        }

        private Process StartDashboard()
        {
            string stateRoot = Directory.GetParent(tempRoot).FullName;
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = nodePath;
            startInfo.WorkingDirectory = dashboardRoot;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.EnvironmentVariables["TEMP"] = tempRoot;
            startInfo.EnvironmentVariables["TMP"] = tempRoot;
            startInfo.Arguments = BuildArguments(new string[] {
                dashboardServerPath,
                "--host", "127.0.0.1",
                "--port", dashboardPort.ToString(),
                "--data-dir", stateRoot,
                "--worker-cli", controlCliPath,
                "--worker-cli-root", Path.GetDirectoryName(controlCliPath),
                "--worker-config", configPath,
                "--worker-config-root", Path.GetDirectoryName(configPath),
                "--powershell", powershellPath,
                "--powershell-root", Path.GetDirectoryName(powershellPath),
                "--control-timeout-ms", "75000",
                "--control-plane-timeout-seconds", "15"
            }, false);
            Process process = new Process();
            process.StartInfo = startInfo;
            if (!process.Start())
            {
                process.Dispose();
                throw new InvalidOperationException("worker-dashboard-child-start-failed");
            }
            return process;
        }

        private void StopDashboardProcess()
        {
            Process process;
            lock (processLock) { process = dashboardProcess; }
            if (process == null) return;
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit(15000);
                }
            }
            catch { }
        }

        private void RunHeartbeatLoop()
        {
            long nextHeartbeatTick = Stopwatch.GetTimestamp();
            double ticksPerSecond = Stopwatch.Frequency;
            while (!stopRequested.WaitOne(0))
            {
                RunOneHeartbeat();
                nextHeartbeatTick += (long)(60 * ticksPerSecond);
                long now = Stopwatch.GetTimestamp();
                while (nextHeartbeatTick <= now)
                {
                    nextHeartbeatTick += (long)(60 * ticksPerSecond);
                }
                TimeSpan remaining = TimeSpan.FromSeconds(
                    (nextHeartbeatTick - now) / ticksPerSecond
                );
                if (stopRequested.WaitOne(remaining))
                {
                    return;
                }
            }
        }

        private void RunOneHeartbeat()
        {
            Process process = null;
            try
            {
                process = StartPowerShell(new string[]
                {
                    "-File", heartbeatRunnerPath,
                    "-ConfigPath", configPath
                });
                if (!process.WaitForExit(20000))
                {
                    WriteOperationalEvent("worker-node-heartbeat-timeout", EventLogEntryType.Warning);
                    process.WaitForExit();
                }
            }
            catch (Exception error)
            {
                WriteOperationalEvent("worker-node-heartbeat-failed:" + SafeCode(error.GetType().Name), EventLogEntryType.Warning);
            }
            finally
            {
                // A request is never killed; its own HTTP deadline is
                // authoritative and this serial loop never overlaps heartbeats.
                if (process != null)
                {
                    process.Dispose();
                }
            }
        }

        private void RunLoop()
        {
            while (!stopRequested.WaitOne(0))
            {
                RunOneCycle();
                if (stopRequested.WaitOne(TimeSpan.FromSeconds(pollSeconds)))
                {
                    return;
                }
            }
        }

        private void RunOneCycle()
        {
            Process process = null;
            try
            {
                process = StartPowerShell(new string[]
                {
                    "-File", runnerPath,
                    "-ConfigPath", configPath
                });
                lock (processLock)
                {
                    activeCycle = process;
                }
                process.WaitForExit();
            }
            catch (Exception error)
            {
                WriteOperationalEvent("worker-cycle-host-failed:" + SafeCode(error.GetType().Name), EventLogEntryType.Error);
            }
            finally
            {
                lock (processLock)
                {
                    if (ReferenceEquals(activeCycle, process))
                    {
                        activeCycle = null;
                    }
                }
                if (process != null)
                {
                    process.Dispose();
                }
            }
        }

        private void InvokeLocalDrain()
        {
            Process process = null;
            try
            {
                process = StartPowerShell(new string[]
                {
                    "-File", controlCliPath,
                    "stop",
                    "-ConfigPath", configPath,
                    "-ControlPlaneTimeoutSeconds", "10",
                    "-NotifyControlPlane"
                });
                if (!process.WaitForExit(60000))
                {
                    WriteOperationalEvent("worker-service-drain-notification-timeout", EventLogEntryType.Warning);
                }
            }
            catch (Exception error)
            {
                WriteOperationalEvent("worker-service-drain-failed:" + SafeCode(error.GetType().Name), EventLogEntryType.Warning);
            }
            finally
            {
                // The process is deliberately not killed on timeout. Local drain
                // is written before the bounded central notification in the CLI.
                if (process != null)
                {
                    process.Dispose();
                }
            }
        }

        private Process StartPowerShell(string[] operationArguments)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = powershellPath;
            startInfo.WorkingDirectory = Path.GetDirectoryName(runnerPath);
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.EnvironmentVariables["TEMP"] = tempRoot;
            startInfo.EnvironmentVariables["TMP"] = tempRoot;
            startInfo.Arguments = BuildArguments(operationArguments, true);
            Process process = new Process();
            process.StartInfo = startInfo;
            if (!process.Start())
            {
                process.Dispose();
                throw new InvalidOperationException("worker-service-child-start-failed");
            }
            return process;
        }

        private static string BuildArguments(string[] operationArguments, bool powershell)
        {
            List<string> arguments = new List<string>();
            if (powershell)
            {
                arguments.Add("-NoLogo");
                arguments.Add("-NoProfile");
                arguments.Add("-NonInteractive");
                arguments.Add("-ExecutionPolicy");
                arguments.Add("RemoteSigned");
            }
            foreach (string argument in operationArguments)
            {
                arguments.Add(Quote(argument));
            }
            return String.Join(" ", arguments.ToArray());
        }

        private static string Quote(string value)
        {
            if (value == null)
            {
                return "\"\"";
            }
            // Windows CommandLineToArgvW-compatible quoting. Backslashes are
            // doubled only when they precede a quote or the closing quote.
            StringBuilder result = new StringBuilder();
            result.Append('"');
            int backslashes = 0;
            foreach (char current in value)
            {
                if (current == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (current == '"')
                {
                    result.Append('\\', (backslashes * 2) + 1);
                    result.Append('"');
                }
                else
                {
                    result.Append('\\', backslashes);
                    result.Append(current);
                }
                backslashes = 0;
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private void WriteOperationalEvent(string code, EventLogEntryType type)
        {
            try
            {
                EventLog.WriteEntry(SafeCode(code), type);
            }
            catch
            {
                // Logging failure must not cause a restart storm.
            }
        }

        private static string SafeCode(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return "worker-service-error";
            }
            char[] result = value.ToLowerInvariant().ToCharArray();
            for (int index = 0; index < result.Length; index++)
            {
                char current = result[index];
                if (!((current >= 'a' && current <= 'z') ||
                      (current >= '0' && current <= '9') ||
                      current == '.' || current == '_' || current == '-' || current == ':'))
                {
                    result[index] = '-';
                }
            }
            string code = new string(result).Trim('-');
            return code.Length > 160 ? code.Substring(0, 160) : code;
        }

        private static string Required(IDictionary<string, string> options, string key)
        {
            string value;
            if (!options.TryGetValue(key, out value) || String.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("worker-service-option-required:" + key);
            }
            return value;
        }

        private static string CanonicalFile(string value)
        {
            string path = Path.GetFullPath(value);
            if (!Path.IsPathRooted(path) || !File.Exists(path))
            {
                throw new ArgumentException("worker-service-file-not-found");
            }
            return path;
        }

        private static string CanonicalDirectory(string value)
        {
            string path = Path.GetFullPath(value);
            if (!Path.IsPathRooted(path) || !Directory.Exists(path))
            {
                throw new ArgumentException("worker-service-directory-not-found");
            }
            return path;
        }

        private static int BoundedInteger(IDictionary<string, string> options, string key, int fallback, int minimum, int maximum)
        {
            string value;
            int parsed;
            if (!options.TryGetValue(key, out value))
            {
                return fallback;
            }
            if (!Int32.TryParse(value, out parsed) || parsed < minimum || parsed > maximum)
            {
                throw new ArgumentException("worker-service-option-invalid:" + key);
            }
            return parsed;
        }

        internal static IDictionary<string, string> ParseOptions(string[] args)
        {
            HashSet<string> allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "service-name", "powershell", "runner", "heartbeat-runner", "control-cli", "config",
                "temp-root", "poll-seconds", "stop-timeout-seconds", "node",
                "dashboard-server", "dashboard-root", "dashboard-port"
            };
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (args.Length == 0 || args.Length % 2 != 0)
            {
                throw new ArgumentException("worker-service-options-invalid");
            }
            for (int index = 0; index < args.Length; index += 2)
            {
                string key = args[index];
                if (!key.StartsWith("--", StringComparison.Ordinal) || !allowed.Contains(key.Substring(2)))
                {
                    throw new ArgumentException("worker-service-option-not-allowed");
                }
                key = key.Substring(2);
                if (result.ContainsKey(key))
                {
                    throw new ArgumentException("worker-service-option-duplicate");
                }
                result.Add(key, args[index + 1]);
            }
            return result;
        }
    }

    internal static class Program
    {
        private static void Main(string[] args)
        {
            IDictionary<string, string> options = HchEditorialWorkerService.ParseOptions(args);
            ServiceBase.Run(new ServiceBase[] { new HchEditorialWorkerService(options) });
        }
    }
}
