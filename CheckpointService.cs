using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace EventLogOutEmployeeService
{
    public partial class LoginLogoutMonitorService
    {
        private sealed class CheckpointService
        {
            private readonly LoginLogoutMonitorService _owner;
            private readonly object _checkpointWriteLock = new object();
            private Timer? _checkpointHeartbeatTimer;

            public CheckpointService(LoginLogoutMonitorService owner)
            {
                _owner = owner;
            }

            public void EnsureCheckpointBootstrap()
            {
                try
                {
                    // Hanya pastikan direktori ada — tidak seed checkpoint file.
                    // LoadStopCheckpoint() adalah single source of truth untuk semua fallback,
                    // termasuk fresh install (Level 4 → today 00:00).
                    // Dulu Bootstrap meng-seed Now-1menit sehingga Level 4 tidak pernah tercapai
                    // dan event login sebelum service start (misal 07:21) ikut terlewat.
                    Directory.CreateDirectory(DataDirectory);

                    SafeWriteEventLog("Application",
                        $"EnsureCheckpointBootstrap: DataDirectory ensured at '{DataDirectory}'",
                        EventLogEntryType.Information, 1025);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"EnsureCheckpointBootstrap failed: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1026);
                }
            }

            public DateTime? LoadStopCheckpoint()
            {
                try
                {
                    // Level 1 – Primary checkpoint
                    DateTime? checkpoint = TryLoadCheckpoint(_owner.stopCheckpointPath);
                    if (checkpoint.HasValue)
                    {
                        SafeWriteEventLog("Application",
                            $"LoadStopCheckpoint: loaded from primary '{_owner.stopCheckpointPath}' → {checkpoint.Value:O}",
                            EventLogEntryType.Information, 1024);
                        return checkpoint;
                    }

                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: primary not found at '{_owner.stopCheckpointPath}', trying backup.",
                        EventLogEntryType.Warning, 1023);

                    // Level 2 – Backup checkpoint (in case primary write was interrupted mid-shutdown)
                    checkpoint = TryLoadCheckpoint(_owner.stopCheckpointBackupPath);
                    if (checkpoint.HasValue)
                    {
                        SafeWriteEventLog("Application",
                            $"LoadStopCheckpoint: loaded from backup '{_owner.stopCheckpointBackupPath}' → {checkpoint.Value:O}",
                            EventLogEntryType.Warning, 1023);
                        return checkpoint;
                    }

                    // Level 3 – Derive from replay checkpoint -5 min so we don't miss events
                    // written right before the previous service start.
                    // If derived timestamp is older than MaxReplayLookback (7 days), clamp to
                    // exactly 7 days back — never fall back to an arbitrary short window so that
                    // long weekends, public holidays, and extended leave are always covered.
                    DateTime now = DateTime.UtcNow;
                    DateTime? replayCheckpoint = TryLoadCheckpoint(_owner.replayCheckpointPath);
                    if (replayCheckpoint.HasValue)
                    {
                        DateTime derived = replayCheckpoint.Value.AddMinutes(-5);
                        DateTime maxLookback = now - MaxReplayLookback;

                        if (derived < maxLookback)
                        {
                            // Replay checkpoint is stale (e.g. leftover from a reinstall).
                            // Clamp to MaxReplayLookback so we still cover up to 7 days,
                            // rather than collapsing to a tiny 10-minute window.
                            SafeWriteEventLog("Application",
                                $"LoadStopCheckpoint: replay checkpoint stale ({replayCheckpoint.Value:O}); " +
                                $"clamping replayFrom to MaxReplayLookback boundary {maxLookback:O} " +
                                $"instead of derived {derived:O}",
                                EventLogEntryType.Warning, 1043);
                            return maxLookback;
                        }

                        SafeWriteEventLog("Application",
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
                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: FRESH INSTALL — no checkpoint found anywhere. " +
                        $"Seeding replayFrom to today local midnight {todayMidnightLocal:O} " +
                        $"so events from 00:00 local today are captured.",
                        EventLogEntryType.Warning, 1023);
                    return todayMidnightLocal;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: exception {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1027);
                }

                return null;
            }

            public DateTime? TryLoadStopCheckpoint()
            {
                return TryLoadCheckpoint(_owner.stopCheckpointPath);
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

            public void SaveStopCheckpoint(DateTime checkpoint)
            {
                try
                {
                    lock (_checkpointWriteLock)
                    {
                        string? dir = Path.GetDirectoryName(_owner.stopCheckpointPath);

                        SafeWriteEventLog("Application",
                            $"SaveStopCheckpoint: dir='{dir}' path='{_owner.stopCheckpointPath}'",
                            EventLogEntryType.Information, 1020);

                        if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                        {
                            Directory.CreateDirectory(dir);
                            SafeWriteEventLog("Application",
                                $"SaveStopCheckpoint: created directory '{dir}'",
                                EventLogEntryType.Information, 1021);
                        }

                        string content = checkpoint.ToUniversalTime().ToString("O");

                        // Write atomically via temp+rename so the file is never half-written
                        // if Windows kills the process mid-write during system shutdown.
                        // Primary path:
                        string tempPrimary = _owner.stopCheckpointPath + ".tmp";
                        File.WriteAllText(tempPrimary, content);
                        File.Move(tempPrimary, _owner.stopCheckpointPath, overwrite: true);

                        // Backup path (same trick):
                        string tempBackup = _owner.stopCheckpointBackupPath + ".tmp";
                        File.WriteAllText(tempBackup, content);
                        File.Move(tempBackup, _owner.stopCheckpointBackupPath, overwrite: true);

                        SafeWriteEventLog("Application",
                            $"SaveStopCheckpoint: written '{content}' to primary + backup.",
                            EventLogEntryType.Information, 1022);
                    }
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Failed to save stop checkpoint: {ex.GetType().Name}: {ex.Message} | Path='{_owner.stopCheckpointPath}'",
                        EventLogEntryType.Warning, 1017);
                }
            }

            public void SaveReplayCheckpoint(DateTime checkpoint)
            {
                try
                {
                    string? dir = Path.GetDirectoryName(_owner.replayCheckpointPath);
                    if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    // Tulis atomik via temp+rename agar tidak corrupted kalau process mati di tengah write.
                    string content = checkpoint.ToUniversalTime().ToString("O");
                    string tempPath = _owner.replayCheckpointPath + ".tmp";
                    File.WriteAllText(tempPath, content);
                    File.Move(tempPath, _owner.replayCheckpointPath, overwrite: true);
                }
                catch { /* ignore write failures */ }
            }

            public void StartCheckpointHeartbeat()
            {
                _checkpointHeartbeatTimer?.Dispose();
                _checkpointHeartbeatTimer = new Timer(_ =>
                {
                    try
                    {
                        // Heartbeat menulis Now tanpa pengurangan — per-event sudah handle
                        // akurasi (eventTime - 1 detik). Heartbeat hanya safety net saat idle.
                        // Interval 15 detik: worst-case gap kalau 6008/power loss = 15 detik,
                        // jauh lebih kecil dari sebelumnya (1 menit). Di environment dengan
                        // Security log 20MB yang cepat rotate dan riwayat 6008, gap kecil
                        // sangat penting agar replay window tidak kehilangan event login pagi.
                        // Overhead: nulis satu file kecil tiap 15 detik — tidak signifikan.
                        SaveStopCheckpoint(DateTime.UtcNow);
                    }
                    catch
                    {
                        // Heartbeat must never crash service.
                    }
                }, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
            }

            public void StopCheckpointHeartbeat()
            {
                _checkpointHeartbeatTimer?.Dispose();
                _checkpointHeartbeatTimer = null;
            }
        }
    }
}
