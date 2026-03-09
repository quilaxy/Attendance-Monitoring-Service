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
    }

    public class PersistentEventQueue
    {
        private readonly string filePath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Two events with same EventId + Username + ComputerName within this window = duplicate.
        /// </summary>
        private static readonly TimeSpan DedupWindow = TimeSpan.FromMinutes(10);

        public PersistentEventQueue(string filePath)
        {
            this.filePath = filePath;
            EnsureQueueFile();
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

                if (existing != null)
                {
                    // Login: keep the earliest timestamp (first login of the day matters)
                    if (item.EventId == 4624 && item.EventTime < existing.EventTime)
                    {
                        items.Remove(existing);
                        items.Add(item);
                        await WriteAllInternalAsync(items);
                        return true; // replaced with earlier event
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
                items.RemoveAll(x => x.QueueId == queueId);
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

        private static TimeSpan AbsDiff(DateTime a, DateTime b)
        {
            var diff = a - b;
            return diff < TimeSpan.Zero ? diff.Negate() : diff;
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
            await File.WriteAllTextAsync(filePath, content);
        }
    }
}
