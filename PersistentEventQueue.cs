using System;
using System.Collections.Generic;
using System.IO;
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

        public PersistentEventQueue(string filePath)
        {
            this.filePath = filePath;
            EnsureQueueFile();
        }

        public async Task EnqueueAsync(QueuedAttendanceEvent item, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                items.Add(item);
                await WriteAllInternalAsync(items);
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
                if (items.Count == 0)
                    return null;

                return items[0];
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

        private void EnsureQueueFile()
        {
            string? directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            if (!File.Exists(filePath))
            {
                File.WriteAllText(filePath, "[]");
            }
        }

        private async Task<List<QueuedAttendanceEvent>> ReadAllInternalAsync()
        {
            EnsureQueueFile();
            string content = await File.ReadAllTextAsync(filePath);
            if (string.IsNullOrWhiteSpace(content))
                return new List<QueuedAttendanceEvent>();

            var items = JsonConvert.DeserializeObject<List<QueuedAttendanceEvent>>(content);
            return items ?? new List<QueuedAttendanceEvent>();
        }

        private async Task WriteAllInternalAsync(List<QueuedAttendanceEvent> items)
        {
            string content = JsonConvert.SerializeObject(items, Formatting.Indented);
            await File.WriteAllTextAsync(filePath, content);
        }
    }
}
