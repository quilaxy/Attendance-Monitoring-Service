using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace EventLogOutEmployeeService
{
    public class LoginLogoutMonitorService : ServiceBase
    {
        private EventLog? securityEventLog;
        private EventLog? systemEventLog;
        private string lastActiveUser = string.Empty;
        private CancellationTokenSource? cancellationTokenSource;
        private CancellationToken? cancellationToken;
        private ConcurrentDictionary<string, DateTime> eventFirstTimeDict = new ConcurrentDictionary<string, DateTime>();
        private ConcurrentDictionary<string, SemaphoreSlim> eventProcessingLocks = new ConcurrentDictionary<string, SemaphoreSlim>();
        private readonly object userLock = new object();
        private DateTime serviceStartTime;

        public LoginLogoutMonitorService()
        {
            try
            {
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    int retryCount = 3;
                    Exception? lastException = null;

                    for (int i = 0; i < retryCount; i++)
                    {
                        try
                        {
                            securityEventLog = new EventLog("Security");
                            systemEventLog = new EventLog("System");
                            serviceStartTime = DateTime.Now;

                            SharePointIntegration.SetServiceStartTime(serviceStartTime);

                            if (securityEventLog != null)
                            {
                                securityEventLog.EntryWritten += new EntryWrittenEventHandler(OnSecurityEventWritten);
                            }

                            if (systemEventLog != null)
                            {
                                systemEventLog.EntryWritten += new EntryWrittenEventHandler(OnSystemEventWritten);
                            }

                            break;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            if (i < retryCount - 1)
                            {
                                Thread.Sleep(2000);
                            }
                        }
                    }

                    if (lastException != null && securityEventLog == null)
                    {
                        throw lastException;
                    }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"EmployeeLoginLogoutService constructor error: {ex.Message}",
                    EventLogEntryType.Error, 1001);
                throw;
            }
        }


        public void StartForConsole(string[] args)
        {
            OnStart(args);
        }

        public void StopForConsole()
        {
            OnStop();
        }

        protected override void OnStart(string[] args)
        {
            int maxRetries = 5;
            int currentRetry = 0;

            while (currentRetry < maxRetries)
            {
                try
                {
                    currentRetry++;

                    int delaySeconds = (currentRetry == 1) ? 10 : 3;
                    Thread.Sleep(delaySeconds * 1000);

                    string publishDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                    Directory.SetCurrentDirectory(publishDirectory);

                    // Validate configuration (prefer plain appsettings.json for development,
                    // fallback to appsettings.json.encrypted for production)
                    _ = LoadConfiguration(publishDirectory);

                    cancellationTokenSource = new CancellationTokenSource();
                    cancellationToken = cancellationTokenSource.Token;

                    Thread monitoringThread = new Thread(() => MonitorEvents(cancellationToken.Value));
                    monitoringThread.IsBackground = true;
                    monitoringThread.Start();

                    EventLog.WriteEntry("Application",
                        "EmployeeLoginLogoutService started successfully",
                        EventLogEntryType.Information, 1000);

                    break;
                }
                catch (Exception ex)
                {
                    if (currentRetry >= maxRetries)
                    {
                        EventLog.WriteEntry("Application",
                            $"EmployeeLoginLogoutService failed to start after {maxRetries} attempts: {ex.Message}",
                            EventLogEntryType.Error, 1002);
                        return;
                    }

                    Thread.Sleep(2000);
                }
            }
        }

        private IConfiguration LoadConfiguration(string baseDirectory)
        {
            string plainConfigPath = Path.Combine(baseDirectory, "appsettings.json");
            if (File.Exists(plainConfigPath))
            {
                var plainConfigBuilder = new ConfigurationBuilder()
                    .SetBasePath(baseDirectory)
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

                return plainConfigBuilder.Build();
            }

            string encryptedConfigPath = Path.Combine(baseDirectory, "appsettings.json.encrypted");
            if (!File.Exists(encryptedConfigPath))
            {
                throw new FileNotFoundException(
                    $"Configuration file not found. Expected either '{plainConfigPath}' or '{encryptedConfigPath}'.");
            }

            try
            {
                byte[] encryptedData = File.ReadAllBytes(encryptedConfigPath);
                byte[] decryptedData = ProtectedData.Unprotect(
                    encryptedData,
                    null,
                    DataProtectionScope.LocalMachine
                );

                string jsonContent = Encoding.UTF8.GetString(decryptedData);

                var configBuilder = new ConfigurationBuilder();
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonContent)))
                {
                    configBuilder.AddJsonStream(stream);
                }

                return configBuilder.Build();
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Failed to decrypt configuration: {ex.Message}",
                    EventLogEntryType.Error, 1004);
                throw;
            }
        }

        protected override void OnStop()
        {
            try
            {
                if (securityEventLog != null)
                {
                    securityEventLog.EnableRaisingEvents = false;
                    securityEventLog.EntryWritten -= OnSecurityEventWritten;
                }

                if (systemEventLog != null)
                {
                    systemEventLog.EnableRaisingEvents = false;
                    systemEventLog.EntryWritten -= OnSystemEventWritten;
                }

                cancellationTokenSource?.Cancel();
                Thread.Sleep(1000);

                EventLog.WriteEntry("Application",
                    "EmployeeLoginLogoutService stopped",
                    EventLogEntryType.Information, 1005);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnStop: {ex.Message}",
                    EventLogEntryType.Warning, 1006);
            }
        }

        private void MonitorEvents(CancellationToken cancellationToken)
        {
            try
            {
                if (securityEventLog != null)
                {
                    securityEventLog.EnableRaisingEvents = true;
                }

                if (systemEventLog != null)
                {
                    systemEventLog.EnableRaisingEvents = true;
                }

                Task.Run(() => CleanupOldRecordsTask(cancellationToken), cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(5000);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in MonitorEvents: {ex.Message}",
                    EventLogEntryType.Error, 1007);
            }
        }

        private async Task CleanupOldRecordsTask(CancellationToken cancellationToken)
        {
            int cleanupHour = 3;
            int retentionMonths = 6;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    DateTime now = DateTime.Now;
                    DateTime nextRun = now.Date.AddHours(cleanupHour);

                    if (now.Hour >= cleanupHour)
                    {
                        nextRun = nextRun.AddDays(1);
                    }

                    DateTime todaysCleanup = now.Date.AddHours(cleanupHour);
                    bool missedCleanup = (now.Hour > cleanupHour) && (now.Date == todaysCleanup.Date);

                    if (missedCleanup)
                    {
                        int randomDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                        await Task.Delay(randomDelay, cancellationToken);

                        var sharePointMissed = new SharePointIntegration();
                        await sharePointMissed.CleanupOldRecordsAsync(retentionMonths);
                    }

                    TimeSpan delay = nextRun - now;
                    await Task.Delay(delay, cancellationToken);

                    int scheduledDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                    await Task.Delay(scheduledDelay, cancellationToken);

                    var sharePoint = new SharePointIntegration();
                    await sharePoint.CleanupOldRecordsAsync(retentionMonths);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"Error in CleanupOldRecordsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1008);

                    try
                    {
                        await Task.Delay(TimeSpan.FromHours(1), cancellationToken);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                }
            }
        }

        private async void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            try
            {
                if (e?.Entry == null || e.Entry.Message == null)
                    return;

                var log = e.Entry;
                int eventId = log.EventID;

                if (eventId != 4624 && eventId != 4647)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                if (eventTime.Date < DateTime.Now.Date)
                    return;

                var timeSinceServiceStart = eventTime - serviceStartTime;

                if (timeSinceServiceStart.TotalMinutes < -30)
                    return;

                string eventMessage = log.Message;
                string username = GetUsernameFromEvent(eventMessage, eventId);

                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                    return;

                if (eventId == 4624)
                {
                    lock (userLock)
                    {
                        lastActiveUser = username;
                    }
                }

                if (!await ShouldProcessEventAsync(eventId, username, eventTime))
                    return;

                await ProcessEvent(eventId, username, eventTime, computerName, "Security");
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnSecurityEventWritten: {ex.Message}",
                    EventLogEntryType.Warning, 1009);
            }
        }

        private string? GetMostRecentUser(DateTime beforeTime)
        {
            try
            {
                DateTime lookbackTime = beforeTime.AddHours(-1);
                EventLog secLog = new EventLog("Security");

                int checkCount = 0;
                int maxCheck = 50;

                for (int i = secLog.Entries.Count - 1; i >= 0 && checkCount < maxCheck; i--)
                {
                    checkCount++;
                    EventLogEntry entry = secLog.Entries[i];

                    if ((entry.EventID == 4624 || entry.EventID == 4647) &&
                        entry.TimeGenerated >= lookbackTime &&
                        entry.TimeGenerated <= beforeTime)
                    {
                        if (entry.Message != null)
                        {
                            string username = GetUsernameFromEvent(entry.Message, entry.EventID);

                            if (!string.IsNullOrEmpty(username) && IsValidUsername(username))
                            {
                                return username;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silent fail
            }

            return null;
        }

        private async void OnSystemEventWritten(object sender, EntryWrittenEventArgs e)
        {
            try
            {
                if (e?.Entry == null || e.Entry.Message == null)
                    return;

                var log = e.Entry;
                int eventId = log.EventID;

                if (eventId != 1074 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                if (eventTime.Date < DateTime.Now.Date)
                    return;

                var timeSinceServiceStart = eventTime - serviceStartTime;
                if (timeSinceServiceStart.TotalMinutes < -30)
                    return;

                string username;

                lock (userLock)
                {
                    username = lastActiveUser;
                }

                if (string.IsNullOrEmpty(username))
                {
                    username = GetMostRecentUser(eventTime);

                    if (string.IsNullOrEmpty(username))
                        return;
                }

                if (eventId == 42)
                {
                    SharePointIntegration.MarkSleepEvent(eventTime);
                }

                if (!await ShouldProcessEventAsync(eventId, username, eventTime))
                    return;

                string eventMessage = (eventId == 1074) ? log.Message : null;
                await ProcessEvent(eventId, username, eventTime, computerName, "System", eventMessage);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnSystemEventWritten: {ex.Message}",
                    EventLogEntryType.Warning, 1010);
            }
        }

        private async Task<bool> ShouldProcessEventAsync(int eventId, string username, DateTime eventTime)
        {
            string eventKey = $"{eventId}_{username}";
            var semaphore = eventProcessingLocks.GetOrAdd(eventKey, _ => new SemaphoreSlim(1, 1));

            await semaphore.WaitAsync();

            try
            {
                if (eventFirstTimeDict.TryGetValue(eventKey, out DateTime firstEventTime))
                {
                    var timeDiff = eventTime - firstEventTime;

                    if (timeDiff.TotalMinutes < 0 || timeDiff.TotalDays > 1)
                    {
                        eventFirstTimeDict[eventKey] = eventTime;
                        return true;
                    }

                    if (timeDiff.TotalMinutes < 10)
                    {
                        return false;
                    }
                    else
                    {
                        eventFirstTimeDict[eventKey] = eventTime;
                    }
                }
                else
                {
                    eventFirstTimeDict[eventKey] = eventTime;
                }

                return true;
            }
            finally
            {
                semaphore.Release();
            }
        }

        private string ParseShutdownType(string eventMessage)
        {
            if (string.IsNullOrEmpty(eventMessage))
                return "Shutdown/Restart";

            try
            {
                var regex = new Regex(@"Shut-down Type:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                var match = regex.Match(eventMessage);

                if (match.Success)
                {
                    string shutdownType = match.Groups[1].Value.Trim().ToLower();

                    if (shutdownType.Contains("restart") || shutdownType.Contains("reboot"))
                    {
                        return "Restart";
                    }
                    else if (shutdownType.Contains("power off") || shutdownType.Contains("shutdown"))
                    {
                        return "Shutdown";
                    }
                }

                return "Shutdown/Restart";
            }
            catch
            {
                return "Shutdown/Restart";
            }
        }

        private async Task ProcessEvent(int eventId, string username, DateTime eventTime, string computerName, string logType, string? eventMessage = null)
        {
            try
            {
                string eventType = logType switch
                {
                    "Security" => eventId switch
                    {
                        4624 => "Login",
                        4647 => "Logout",
                        _ => "Unknown Security Event"
                    },
                    "System" => eventId switch
                    {
                        1074 => ParseShutdownType(eventMessage),
                        6008 => "Unexpected Shutdown",
                        41 => "Crash/Rebooted",
                        42 => "Sleep/Standby",
                        _ => "Unknown System Event"
                    },
                    _ => "Unknown Event"
                };

                if (eventTime.Kind == DateTimeKind.Unspecified)
                {
                    eventTime = DateTime.SpecifyKind(eventTime, DateTimeKind.Local);
                }

                if (eventId == 1074 || eventId == 4647 || eventId == 6008 || eventId == 41 || eventId == 42)
                {
                    SharePointIntegration.MarkShutdownEvent(eventTime);
                }

                var sharePoint = new SharePointIntegration();
                string accessToken = await sharePoint.GetAccessTokenAsync(eventTime, eventId);

                if (string.IsNullOrEmpty(accessToken))
                    return;

                await sharePoint.AddRecordToSharePointAsync(accessToken, username, eventTime, eventId, eventType, computerName);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in ProcessEvent: {ex.Message}",
                    EventLogEntryType.Warning, 1011);
            }
        }

        private string? GetUsernameFromEvent(string message, int eventId)
        {
            try
            {
                if (eventId == 4624)
                {
                    int newLogonIndex = message.IndexOf("New Logon:");
                    if (newLogonIndex == -1)
                        return null;

                    string newLogonSection = message.Substring(newLogonIndex);

                    var regexAccountName = new Regex(@"Account Name:\s*([^\r\n]+)");
                    var matchAccountName = regexAccountName.Match(newLogonSection);

                    if (matchAccountName.Success)
                    {
                        string accountName = matchAccountName.Groups[1].Value.Trim();

                        if (string.IsNullOrWhiteSpace(accountName) ||
                            accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            accountName.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                            accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }

                        string normalizedUsername = accountName;
                        if (accountName.Contains("@"))
                        {
                            normalizedUsername = accountName.Split('@')[0].Trim();
                        }

                        return normalizedUsername;
                    }
                }

                if (eventId == 4647)
                {
                    int subjectIndex = message.IndexOf("Subject:");
                    if (subjectIndex == -1)
                        return null;

                    string subjectSection = message.Substring(subjectIndex);

                    var regexAccountName = new Regex(@"Account Name:\s*([^\r\n]+)");
                    var matchAccountName = regexAccountName.Match(subjectSection);

                    if (matchAccountName.Success)
                    {
                        string accountName = matchAccountName.Groups[1].Value.Trim();

                        if (string.IsNullOrWhiteSpace(accountName) ||
                            accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }

                        string normalizedUsername = accountName;
                        if (accountName.Contains("@"))
                        {
                            normalizedUsername = accountName.Split('@')[0].Trim();
                        }

                        return normalizedUsername;
                    }
                }
            }
            catch
            {
                // Silent fail
            }

            return null;
        }

        private bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            var invalidUsernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "SYSTEM", "LOCAL SERVICE", "LOCAL_SYSTEM", "NETWORK SERVICE",
                "ANONYMOUS LOGON", "Guest", "DefaultAccount", "Administrator"
            };

            if (invalidUsernames.Contains(username))
                return false;

            if (username.EndsWith("$"))
                return false;

            var prefixConditions = new string[]
            {
                "DWM-", "UMFD-", "NT Service"
            };

            foreach (var prefix in prefixConditions)
            {
                if (username.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }
    }
}
