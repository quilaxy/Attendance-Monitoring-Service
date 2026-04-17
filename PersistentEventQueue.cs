using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace EventLogOutEmployeeService
{
    public class QueuedAttendanceEvent
    {
        public string QueueId { get; set; } = string.Empty;
        public int EventId { get; set; }
        public string Username { get; set; } = string.Empty;
        public DateTime EventTime { get; set; }
        public string ComputerName { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public int LogonType { get; set; } = 0;
        public DateTime? LoginTime { get; set; }
        public DateTime? ExpectedTimeOut { get; set; }
        public DateTime? ShutdownTime { get; set; }
        public string? ShutdownType { get; set; }
        public bool WriteRawRecord { get; set; } = true;
        public bool RawRecordDispatched { get; set; } = false;
        public bool SummaryDispatched { get; set; } = false;
        public bool IsSummaryEligible { get; set; } = true;
        public string? ShutdownGroupId { get; set; }
        public DateTime? ShutdownGroupHoldUntil { get; set; }
        public bool ShutdownGroupIsRestart { get; set; } = false;

        // Username resolution metadata (audit)
        public string UsernameResolutionSource { get; set; } = "Direct";
        public string? ResolvedUsername { get; set; }
        public string? OriginalUsername { get; set; }
        public bool IsFallback { get; set; } = false;
        public string? FallbackSource { get; set; }
        public string? Status { get; set; }
        public bool PendingUsernameResolution { get; set; } = false;

        // Persistent retry state
        public int DispatchRetryCount { get; set; } = 0;
        public DateTime? NextRetryAtUtc { get; set; }
        public string? LastDispatchError { get; set; }
    }

    public class PersistentEventQueue
    {
        private readonly string queueDirectoryPath;
        private readonly string pendingDirectoryPath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(30);

        public PersistentEventQueue(string queueDirectoryPath)
        {
            this.queueDirectoryPath = queueDirectoryPath;
            pendingDirectoryPath = Path.Combine(queueDirectoryPath, "pending");
            EnsureQueueDirectories();
            CleanupOrphanedTempFiles();
        }

        public async Task<bool> EnqueueIfNotDuplicateAsync(
            QueuedAttendanceEvent item,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();

                var existing = items.FirstOrDefault(x =>
                    x.EventId == item.EventId &&
                    x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                    AbsDiff(x.EventTime, item.EventTime) < DedupWindow);

                if (existing != null)
                {
                    if ((item.EventId == 4624 || item.EventId == 6005) && ShouldReplaceExistingLogin(existing, item))
                    {
                        item.IsSummaryEligible = existing.IsSummaryEligible;
                        item.DispatchRetryCount = existing.DispatchRetryCount;
                        item.NextRetryAtUtc = existing.NextRetryAtUtc;
                        item.LastDispatchError = existing.LastDispatchError;
                        await WriteItemInternalAsync(item);
                        await DeleteItemInternalAsync(existing.QueueId);
                        return true;
                    }

                    return false;
                }

                if (item.EventId == 4624 || item.EventId == 6005)
                {
                    string itemWorkDate = item.EventTime.ToLocalTime().ToString("yyyy-MM-dd");
                    bool alreadyHasLoginToday = items.Any(x =>
                        (x.EventId == 4624 || x.EventId == 6005) &&
                        x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == itemWorkDate &&
                        x.IsSummaryEligible);

                    item.IsSummaryEligible = !alreadyHasLoginToday;
                }

                await WriteItemInternalAsync(item);
                return true;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<QueuedAttendanceEvent?> PeekAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Count == 0 ? null : SortQueue(items)[0];
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<QueuedAttendanceEvent?> PeekNextReadyAsync(DateTime utcNow, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = SortQueue(await ReadAllInternalAsync());
                return items.FirstOrDefault(x => !x.NextRetryAtUtc.HasValue || x.NextRetryAtUtc.Value <= utcNow);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<DateTime?> GetEarliestNextRetryUtcAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                var retries = items
                    .Where(x => x.NextRetryAtUtc.HasValue)
                    .Select(x => x.NextRetryAtUtc!.Value)
                    .ToList();

                return retries.Count == 0 ? null : retries.Min();
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> GroupHas6006Async(string groupId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Any(x =>
                    x.EventId == 6006 &&
                    x.ShutdownGroupId == groupId &&
                    !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> GroupHasHigherPriorityAsync(string groupId, int thanPriority, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Any(x =>
                    x.ShutdownGroupId == groupId &&
                    !x.SummaryDispatched &&
                    GetStaticShutdownPriority(x.EventId, x.EventType) > thanPriority);
            }
            finally
            {
                fileLock.Release();
            }
        }

        private static int GetStaticShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 6006)
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 0 : 5;
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 4;
            if (eventId == 4647) return 2;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            return 0;
        }

        public async Task RemoveByIdAsync(string queueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await DeleteItemInternalAsync(queueId);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task UpdateDispatchStateAsync(
            string queueId,
            bool? rawRecordDispatched = null,
            bool? summaryDispatched = null,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                QueuedAttendanceEvent? item = await ReadByIdInternalAsync(queueId);
                if (item == null)
                    return;

                if (rawRecordDispatched.HasValue)
                    item.RawRecordDispatched = rawRecordDispatched.Value;

                if (summaryDispatched.HasValue)
                    item.SummaryDispatched = summaryDispatched.Value;

                await WriteItemInternalAsync(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task UpdateRetryStateAsync(
            string queueId,
            int retryCount,
            DateTime? nextRetryAtUtc,
            string? lastDispatchError = null,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                QueuedAttendanceEvent? item = await ReadByIdInternalAsync(queueId);
                if (item == null)
                    return;

                item.DispatchRetryCount = retryCount;
                item.NextRetryAtUtc = nextRetryAtUtc;
                item.LastDispatchError = lastDispatchError;
                await WriteItemInternalAsync(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task ReplaceAsync(QueuedAttendanceEvent item, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await WriteItemInternalAsync(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task MarkGroupAsRestartAsync(string groupId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                foreach (var item in items.Where(x => x.ShutdownGroupId == groupId && !x.ShutdownGroupIsRestart))
                {
                    item.ShutdownGroupIsRestart = true;
                    await WriteItemInternalAsync(item);
                }
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task MarkGroupSummaryDispatchedAsync(string groupId, string exceptQueueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                foreach (var item in items.Where(x => x.ShutdownGroupId == groupId && x.QueueId != exceptQueueId && !x.SummaryDispatched))
                {
                    item.SummaryDispatched = true;
                    await WriteItemInternalAsync(item);
                }
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<int> GetCountAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                return (await ReadAllInternalAsync()).Count;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<List<QueuedAttendanceEvent>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                return SortQueue(await ReadAllInternalAsync());
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<string?> FindMostRecentUsernameForComputerAsync(string computerName, DateTime beforeTimeUtc, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                string workDate = beforeTimeUtc.ToLocalTime().ToString("yyyy-MM-dd");
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                var latest = items
                    .Where(x =>
                        (x.EventId == 4624 || x.EventId == 6005) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime <= beforeTimeUtc &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    .OrderByDescending(x => x.EventTime)
                    .FirstOrDefault();

                return latest?.Username;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<string?> FindMostRecent4624UsernameForComputerAsync(string computerName, DateTime beforeTimeUtc, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                string workDate = beforeTimeUtc.ToLocalTime().ToString("yyyy-MM-dd");
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                var latest = items
                    .Where(x =>
                        x.EventId == 4624 &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime <= beforeTimeUtc &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    .OrderByDescending(x => x.EventTime)
                    .FirstOrDefault();

                return latest?.Username;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<(string Username, DateTime EventTime)?> FindFirst4624ForComputerWorkDateAsync(
            string computerName,
            string workDate,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                var first = items
                    .Where(x =>
                        x.EventId == 4624 &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    .OrderBy(x => x.EventTime)
                    .FirstOrDefault();

                if (first == null)
                    return null;

                return (first.Username, first.EventTime);
            }
            finally
            {
                fileLock.Release();
            }
        }

        private static bool ShouldReplaceExistingLogin(QueuedAttendanceEvent existing, QueuedAttendanceEvent incoming)
        {
            if (incoming.EventTime < existing.EventTime)
                return true;

            if (incoming.EventTime > existing.EventTime)
                return false;

            return GetLogonTypePriority(incoming.LogonType) > GetLogonTypePriority(existing.LogonType);
        }

        private static int GetLogonTypePriority(int logonType)
        {
            return logonType switch
            {
                2  => 5,
                10 => 4,
                11 => 3,
                7  => 2,
                _  => 1
            };
        }

        private static TimeSpan AbsDiff(DateTime a, DateTime b)
        {
            var diff = a - b;
            return diff < TimeSpan.Zero ? diff.Negate() : diff;
        }

        private void EnsureQueueDirectories()
        {
            Directory.CreateDirectory(queueDirectoryPath);
            Directory.CreateDirectory(pendingDirectoryPath);
        }

        private void CleanupOrphanedTempFiles()
        {
            try
            {
                foreach (string tempFile in Directory.GetFiles(pendingDirectoryPath, "*.tmp", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        File.Delete(tempFile);
                    }
                    catch (Exception ex)
                    {
                        SafeQueueLog($"Queue temp file cleanup failed '{tempFile}': {ex.Message}", EventLogEntryType.Warning, 1042);
                    }
                }
            }
            catch (Exception ex)
            {
                SafeQueueLog($"Queue temp file scan failed in '{pendingDirectoryPath}': {ex.Message}", EventLogEntryType.Warning, 1042);
            }
        }

        private async Task<List<QueuedAttendanceEvent>> ReadAllInternalAsync()
        {
            EnsureQueueDirectories();
            var items = new List<QueuedAttendanceEvent>();

            foreach (string file in Directory.GetFiles(pendingDirectoryPath, "*.json", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    string content = await File.ReadAllTextAsync(file);
                    if (string.IsNullOrWhiteSpace(content))
                        continue;

                    var item = JsonConvert.DeserializeObject<QueuedAttendanceEvent>(content);
                    if (item != null && !string.IsNullOrWhiteSpace(item.QueueId))
                        items.Add(item);
                }
                catch (Exception ex)
                {
                    SafeQueueLog($"Queue file read failed '{file}': {ex.Message}", EventLogEntryType.Warning, 1042);
                }
            }

            return SortQueue(items);
        }

        private async Task<QueuedAttendanceEvent?> ReadByIdInternalAsync(string queueId)
        {
            string path = BuildItemPath(queueId);
            if (!File.Exists(path))
                return null;

            try
            {
                string content = await File.ReadAllTextAsync(path);
                return JsonConvert.DeserializeObject<QueuedAttendanceEvent>(content);
            }
            catch (Exception ex)
            {
                SafeQueueLog($"Queue file read failed '{path}': {ex.Message}", EventLogEntryType.Warning, 1042);
                return null;
            }
        }

        private async Task WriteItemInternalAsync(QueuedAttendanceEvent item)
        {
            EnsureQueueDirectories();
            string finalPath = BuildItemPath(item.QueueId);
            string tempPath = finalPath + ".tmp";
            string content = JsonConvert.SerializeObject(item, Formatting.Indented);
            await File.WriteAllTextAsync(tempPath, content);
            File.Move(tempPath, finalPath, overwrite: true);
        }

        private Task DeleteItemInternalAsync(string queueId)
        {
            string path = BuildItemPath(queueId);
            if (File.Exists(path))
                File.Delete(path);
            return Task.CompletedTask;
        }

        private string BuildItemPath(string queueId) => Path.Combine(pendingDirectoryPath, $"{queueId}.json");

        private static List<QueuedAttendanceEvent> SortQueue(List<QueuedAttendanceEvent> items)
            => items
                .OrderBy(x => x.EventTime)
                .ThenBy(x => x.QueueId, StringComparer.OrdinalIgnoreCase)
                .ToList();

        private static void SafeQueueLog(string message, EventLogEntryType type, int eventId)
        {
            try
            {
                EventLog.WriteEntry("Application", message, type, eventId);
            }
            catch
            {
            }
        }
    }
}
