using System;
using System.Diagnostics;
using System.IO;

namespace EventLogOutEmployeeService
{
    internal sealed class CheckpointService
    {
        private readonly string dataDirectory;
        private readonly string stopCheckpointPath;
        private readonly string replayCheckpointPath;
        private readonly string stopCheckpointBackupPath;
        private readonly TimeSpan maxReplayLookback;
        private readonly object checkpointWriteLock = new object();
        private bool _lastWrittenCheckpointInitialized = false;
        private DateTime? _lastWrittenCheckpoint = null;
        private readonly Action<string, string, EventLogEntryType, int> writeEventLog;

        public CheckpointService(
            string dataDirectory,
            TimeSpan maxReplayLookback,
            Action<string, string, EventLogEntryType, int> writeEventLog)
        {
            this.dataDirectory = dataDirectory;
            this.maxReplayLookback = maxReplayLookback;
            this.writeEventLog = writeEventLog ?? throw new ArgumentNullException(nameof(writeEventLog));

            stopCheckpointPath = Path.Combine(dataDirectory, "event-stop.checkpoint");
            replayCheckpointPath = Path.Combine(dataDirectory, "event-replay.checkpoint");
            stopCheckpointBackupPath = Path.Combine(dataDirectory, "event-stop.checkpoint.bak");
        }

        public DateTime? LoadStopCheckpoint()
        {
            try
            {
                // Level 1 – Primary checkpoint
                DateTime? checkpoint = TryLoadCheckpoint(stopCheckpointPath);
                if (checkpoint.HasValue)
                {
                    writeEventLog("Application",
                        $"LoadStopCheckpoint: loaded from primary '{stopCheckpointPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Information, 1024);
                    return checkpoint;
                }

                writeEventLog("Application",
                    $"LoadStopCheckpoint: primary not found at '{stopCheckpointPath}', trying backup.",
                    EventLogEntryType.Warning, 1023);

                // Level 2 – Backup checkpoint (in case primary write was interrupted mid-shutdown)
                checkpoint = TryLoadCheckpoint(stopCheckpointBackupPath);
                if (checkpoint.HasValue)
                {
                    writeEventLog("Application",
                        $"LoadStopCheckpoint: loaded from backup '{stopCheckpointBackupPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Warning, 1023);
                    return checkpoint;
                }

                // Level 3 – Derive from replay checkpoint -5 min so we don't miss events
                // written right before the previous service start.
                // If derived timestamp is older than MaxReplayLookback (7 days), clamp to
                // exactly 7 days back — never fall back to an arbitrary short window so that
                // long weekends, public holidays, and extended leave are always covered.
                DateTime now = DateTime.UtcNow;
                DateTime? replayCheckpoint = TryLoadCheckpoint(replayCheckpointPath);
                if (replayCheckpoint.HasValue)
                {
                    DateTime derived = replayCheckpoint.Value.AddMinutes(-5);
                    DateTime maxLookback = now - maxReplayLookback;

                    if (derived < maxLookback)
                    {
                        // Replay checkpoint is stale (e.g. leftover from a reinstall).
                        // Clamp to MaxReplayLookback so we still cover up to 7 days,
                        // rather than collapsing to a tiny 10-minute window.
                        writeEventLog("Application",
                            $"LoadStopCheckpoint: replay checkpoint stale ({replayCheckpoint.Value:O}); " +
                            $"clamping replayFrom to MaxReplayLookback boundary {maxLookback:O} " +
                            $"instead of derived {derived:O}",
                            EventLogEntryType.Warning, 1043);
                        return maxLookback;
                    }

                    writeEventLog("Application",
                        $"LoadStopCheckpoint: both stop checkpoints missing — deriving from replay checkpoint " +
                        $"({replayCheckpoint.Value:O}) -5min → {derived:O}",
                        EventLogEntryType.Warning, 1023);
                    return derived;
                }

                // Level 4 – Fresh install seed.
                // Tidak ada checkpoint sama sekali (primary, backup, replay) — ini fresh install
                // atau DataDirectory baru dibersihkan. Replay dari 00:00 hari ini (local time)
                // agar event login pagi (sebelum service pertama kali distart) ikut masuk.
                // Tidak replay lebih jauh agar tidak flood Security log historical.
                DateTime todayMidnightLocal = DateTime.Today.ToUniversalTime(); // local midnight → UTC
                writeEventLog("Application",
                    $"LoadStopCheckpoint: FRESH INSTALL — no checkpoint found anywhere. " +
                    $"Seeding replayFrom to today local midnight {todayMidnightLocal:O} " +
                    $"so events from 00:00 local today are captured.",
                    EventLogEntryType.Warning, 1023);
                return todayMidnightLocal;
            }
            catch (Exception ex)
            {
                writeEventLog("Application",
                    $"LoadStopCheckpoint: exception {ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1027);
            }

            return null;
        }

        public DateTime? TryLoadStopCheckpoint()
            => TryLoadCheckpoint(stopCheckpointPath);

        public void EnsureCheckpointBootstrap()
        {
            try
            {
                // Hanya pastikan direktori ada — tidak seed checkpoint file.
                // LoadStopCheckpoint() adalah single source of truth untuk semua fallback,
                // termasuk fresh install (Level 4 → today 00:00).
                // Dulu Bootstrap meng-seed Now-1menit sehingga Level 4 tidak pernah tercapai
                // dan event login sebelum service start (misal 07:21) ikut terlewat.
                Directory.CreateDirectory(dataDirectory);

                writeEventLog("Application",
                    $"EnsureCheckpointBootstrap: DataDirectory ensured at '{dataDirectory}'",
                    EventLogEntryType.Information, 1025);
            }
            catch (Exception ex)
            {
                writeEventLog("Application",
                    $"EnsureCheckpointBootstrap failed: {ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1026);
            }
        }

        public void SaveStopCheckpoint(DateTime checkpoint)
        {
            try
            {
                lock (checkpointWriteLock)
                {
                    EnsureLastWrittenCheckpointInitialized();
                    DateTime checkpointUtc = checkpoint.ToUniversalTime();
                    if (_lastWrittenCheckpoint.HasValue && _lastWrittenCheckpoint.Value >= checkpointUtc)
                        return;

                    string? dir = Path.GetDirectoryName(stopCheckpointPath);

                    writeEventLog("Application",
                        $"SaveStopCheckpoint: dir='{dir}' path='{stopCheckpointPath}'",
                        EventLogEntryType.Information, 1020);

                    if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                        writeEventLog("Application",
                            $"SaveStopCheckpoint: created directory '{dir}'",
                            EventLogEntryType.Information, 1021);
                    }

                    string content = checkpointUtc.ToString("O");

                    // Write atomically via temp+rename so the file is never half-written
                    // if Windows kills the process mid-write during system shutdown.
                    // Primary path:
                    string tempPrimary = stopCheckpointPath + ".tmp";
                    File.WriteAllText(tempPrimary, content);
                    File.Move(tempPrimary, stopCheckpointPath, overwrite: true);

                    // Backup path (same trick):
                    string tempBackup = stopCheckpointBackupPath + ".tmp";
                    File.WriteAllText(tempBackup, content);
                    File.Move(tempBackup, stopCheckpointBackupPath, overwrite: true);

                    writeEventLog("Application",
                        $"SaveStopCheckpoint: written '{content}' to primary + backup.",
                        EventLogEntryType.Information, 1022);
                    _lastWrittenCheckpoint = checkpointUtc;
                }
            }
            catch (Exception ex)
            {
                writeEventLog("Application",
                    $"Failed to save stop checkpoint: {ex.GetType().Name}: {ex.Message} | Path='{stopCheckpointPath}'",
                    EventLogEntryType.Warning, 1017);
            }

            private void EnsureLastWrittenCheckpointInitialized()
            {
                if (_lastWrittenCheckpointInitialized)
                    return;

                DateTime? primary = TryLoadCheckpoint(stopCheckpointPath);
                DateTime? backup = TryLoadCheckpoint(stopCheckpointBackupPath);

                if (primary.HasValue && backup.HasValue)
                    _lastWrittenCheckpoint = primary.Value >= backup.Value ? primary.Value : backup.Value;
                else
                    _lastWrittenCheckpoint = primary ?? backup;

                _lastWrittenCheckpointInitialized = true;
            }
        }

        public void SaveReplayCheckpoint(DateTime checkpoint)
        {
            try
            {
                string? dir = Path.GetDirectoryName(replayCheckpointPath);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                // Tulis atomik via temp+rename agar tidak corrupted kalau process mati di tengah write.
                string content = checkpoint.ToUniversalTime().ToString("O");
                string tempPath = replayCheckpointPath + ".tmp";
                File.WriteAllText(tempPath, content);
                File.Move(tempPath, replayCheckpointPath, overwrite: true);
            }
            catch { /* ignore write failures */ }
        }

        /// <summary>Reads and parses a checkpoint file. Returns null if missing or malformed.</summary>
        private static DateTime? TryLoadCheckpoint(string path)
        {
            if (!File.Exists(path))
                return null;

            string value = File.ReadAllText(path).Trim();
            if (!DateTime.TryParse(value, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                return null;

            // Checkpoint disimpan sebagai UTC (Z suffix) — return as UTC.
            return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
        }
    }
}
