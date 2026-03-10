using System;
using System.Collections.Generic;
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

        /// <summary>
        /// Logon type from Windows Security event (e.g. 2=Interactive, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive).
        /// Only relevant for EventId 4624.
        /// </summary>
        public int LogonType { get; set; } = 0;

        public DateTime? LoginTime { get; set; }
        public DateTime? ExpectedTimeOut { get; set; }
        public DateTime? ShutdownTime { get; set; }
        public string? ShutdownType { get; set; }
        public bool WriteRawRecord { get; set; } = true;
        public bool RawRecordDispatched { get; set; } = false;
        public bool SummaryDispatched { get; set; } = false;
    }

    public class ProcessedEventStamp
    {
        public int EventId { get; set; }
        public string Username { get; set; } = string.Empty;
        public string ComputerName { get; set; } = string.Empty;
        public DateTime EventTime { get; set; }
    }

    public class PersistentEventQueue
    {
        private readonly string filePath;
        private readonly string processedIndexPath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Two events with same EventId + Username + ComputerName within this window = duplicate.
        /// </summary>
        private static readonly TimeSpan DedupWindow = TimeSpan.FromMinutes(10);

        public PersistentEventQueue(string filePath)
        {
            this.filePath = filePath;
            processedIndexPath = filePath + ".processed.json";
            EnsureQueueFile();
            EnsureProcessedIndexFile();
        }

        /// <summary>
        /// Enqueues an event if no duplicate exists within the dedup window.
        ///
        /// Dedup rules:
        ///   - Same EventId + Username + ComputerName within 10 minutes = duplicate.
        ///   - For 4624 (Login): if new event is EARLIER than existing, replace it
        ///     (we always want the earliest login time for the day).
        ///   - For all others: first-one-wins; later duplicates are dropped.
        ///
        /// Returns true if the item was enqueued (or replaced), false if skipped.
        /// </summary>
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

                List<ProcessedEventStamp> processed = await ReadProcessedIndexInternalAsync();
                processed = PruneProcessedStamps(processed, item.EventTime);
                bool alreadyProcessed = processed.Any(x =>
                    x.EventId == item.EventId &&
                    x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                    AbsDiff(x.EventTime, item.EventTime) < DedupWindow);

                if (alreadyProcessed)
                {
                    await WriteProcessedIndexInternalAsync(processed);
                    return false;
                }

                if (existing != null)
                {
                    // Login: keep the earliest timestamp. If same timestamp, keep the more
                    // meaningful logon type (e.g. Interactive over Unlock/Cached).
                    if (item.EventId == 4624 && ShouldReplaceExistingLogin(existing, item))
                    {
                        items.Remove(existing);
                        items.Add(item);
                        await WriteAllInternalAsync(items);
                        return true; // replaced with better candidate
                    }

                    // Everything else: skip duplicate
                    return false;
                }

                items.Add(item);
                await WriteAllInternalAsync(items);
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
                return items.Count == 0 ? null : items[0];
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task RemoveByIdAsync(string queueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                QueuedAttendanceEvent? removed = items.FirstOrDefault(x => x.QueueId == queueId);
                items.RemoveAll(x => x.QueueId == queueId);
                await WriteAllInternalAsync(items);

                if (removed != null)
                {
                    List<ProcessedEventStamp> processed = await ReadProcessedIndexInternalAsync();
                    processed.Add(new ProcessedEventStamp
                    {
                        EventId = removed.EventId,
                        Username = removed.Username,
                        ComputerName = removed.ComputerName,
                        EventTime = removed.EventTime
                    });
                    processed = PruneProcessedStamps(processed, removed.EventTime);
                    await WriteProcessedIndexInternalAsync(processed);
                }
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
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                QueuedAttendanceEvent? item = items.FirstOrDefault(x => x.QueueId == queueId);
                if (item == null)
                    return;

                if (rawRecordDispatched.HasValue)
                    item.RawRecordDispatched = rawRecordDispatched.Value;

                if (summaryDispatched.HasValue)
                    item.SummaryDispatched = summaryDispatched.Value;

                await WriteAllInternalAsync(items);
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
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Count;
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
                2  => 5, // Interactive
                10 => 4, // RemoteInteractive
                11 => 3, // CachedInteractive
                7  => 2, // Unlock
                _  => 1
            };
        }

        private static TimeSpan AbsDiff(DateTime a, DateTime b)
        {
            var diff = a - b;
            return diff < TimeSpan.Zero ? diff.Negate() : diff;
        }

        private void EnsureProcessedIndexFile()
        {
            string? directory = Path.GetDirectoryName(processedIndexPath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if (!File.Exists(processedIndexPath))
                File.WriteAllText(processedIndexPath, "[]");
        }

        private async Task<List<ProcessedEventStamp>> ReadProcessedIndexInternalAsync()
        {
            EnsureProcessedIndexFile();
            string content = await File.ReadAllTextAsync(processedIndexPath);
            if (string.IsNullOrWhiteSpace(content))
                return new List<ProcessedEventStamp>();

            return JsonConvert.DeserializeObject<List<ProcessedEventStamp>>(content)
                   ?? new List<ProcessedEventStamp>();
        }

        private async Task WriteProcessedIndexInternalAsync(List<ProcessedEventStamp> stamps)
        {
            string content = JsonConvert.SerializeObject(stamps, Formatting.Indented);

            string directory = Path.GetDirectoryName(processedIndexPath) ?? string.Empty;
            string tempPath = processedIndexPath + ".tmp";
            string backupPath = Path.Combine(directory, $"{Path.GetFileName(processedIndexPath)}.bak");

            await File.WriteAllTextAsync(tempPath, content);

            if (File.Exists(processedIndexPath))
            {
                File.Replace(tempPath, processedIndexPath, backupPath, ignoreMetadataErrors: true);
                if (File.Exists(backupPath))
                    File.Delete(backupPath);
            }
            else
            {
                File.Move(tempPath, processedIndexPath);
            }
        }

        private static List<ProcessedEventStamp> PruneProcessedStamps(
            List<ProcessedEventStamp> stamps,
            DateTime referenceTime)
        {
            return stamps.Where(x => AbsDiff(x.EventTime, referenceTime) < DedupWindow).ToList();
        }

        private void EnsureQueueFile()
        {
            string? directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if (!File.Exists(filePath))
                File.WriteAllText(filePath, "[]");
        }

        private async Task<List<QueuedAttendanceEvent>> ReadAllInternalAsync()
        {
            EnsureQueueFile();
            string content = await File.ReadAllTextAsync(filePath);
            if (string.IsNullOrWhiteSpace(content))
                return new List<QueuedAttendanceEvent>();

            return JsonConvert.DeserializeObject<List<QueuedAttendanceEvent>>(content)
                   ?? new List<QueuedAttendanceEvent>();
        }

        private async Task WriteAllInternalAsync(List<QueuedAttendanceEvent> items)
        {
            string content = JsonConvert.SerializeObject(items, Formatting.Indented);

            string directory = Path.GetDirectoryName(filePath) ?? string.Empty;
            string tempPath = filePath + ".tmp";
            string backupPath = Path.Combine(directory, $"{Path.GetFileName(filePath)}.bak");

            await File.WriteAllTextAsync(tempPath, content);

            if (File.Exists(filePath))
            {
                File.Replace(tempPath, filePath, backupPath, ignoreMetadataErrors: true);
                if (File.Exists(backupPath))
                    File.Delete(backupPath);
            }
            else
            {
                File.Move(tempPath, filePath);
            }
        }
    }
}
