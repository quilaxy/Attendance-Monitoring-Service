# Attendance Monitoring Service — Technical Documentation

> **Stack:** .NET 8, Windows Service, SharePoint (Microsoft Graph API)  
> **Last updated:** 2026-03-13

---

## Table of Contents

1. [Deploy & Service Management](#1-deploy--service-management)
2. [SharePoint Setup](#2-sharepoint-setup)
3. [Architecture Overview](#3-architecture-overview)
4. [Data Files](#4-data-files)
5. [Windows Event IDs Monitored](#5-windows-event-ids-monitored)
6. [Application Log Event IDs](#6-application-log-event-ids)
7. [Login Filtering](#7-login-filtering)
8. [Admin Login Detection](#8-admin-login-detection)
9. [Checkpoint System](#9-checkpoint-system)
10. [Replay System](#10-replay-system)
11. [Deduplication](#11-deduplication)
12. [Queue System](#12-queue-system)
13. [Dispatch & SharePoint Integration](#13-dispatch--sharepoint-integration)
14. [Summary List Logic](#14-summary-list-logic)
15. [Shutdown Priority](#15-shutdown-priority)
16. [Summary Cache](#16-summary-cache)
17. [Cleanup Task](#17-cleanup-task)
18. [DateTime & Timezone](#18-datetime--timezone)
19. [Username Resolution (System Events)](#19-username-resolution-system-events)
20. [Multi-Device Behavior](#20-multi-device-behavior)

---

## 1. Deploy & Service Management

Run semua command berikut **sebagai Administrator**.

### 1.1 Build & Publish

```bat
dotnet build

dotnet publish "D:\Attendance-Monitoring-Service\Attendance-Monitoring-Service.csproj" `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o "D:\Attendance-Monitoring-Service\Attendance-Monitoring-Service" `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:DebugType=None `
  -p:DebugSymbols=false
```

### 1.2 Install Service

```bat
sc create Attendance-Service ^
  binPath= "C:\Program Files\Attendance-Monitoring-Service\Attendance-Monitoring-Service.exe" ^
  start= auto
```

### 1.3 Start / Stop / Remove

```bat
sc start Attendance-Service
sc stop Attendance-Service
sc delete Attendance-Service
```

### 1.4 Fresh Install / Reset

Sebelum fresh install, hapus semua checkpoint dan cache:

```
C:\ProgramData\Attendance-Monitoring-Service\
  ├── event-stop.checkpoint       ← hapus
  ├── event-stop.checkpoint.bak   ← hapus
  ├── event-replay.checkpoint     ← hapus
  ├── queue\pending\*.json        ← hapus
  └── summary-cache.json          ← hapus
```

---

## 2. SharePoint Setup

### 2.1 Azure App Registration

Service menggunakan **client credentials flow** (app-only, tanpa login user) untuk akses Microsoft Graph API.

**Langkah-langkah:**

1. Buka [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** (atau Azure Active Directory) → **App registrations** → **New registration**
2. Isi form:
   - **Name:** bebas, misal `Attendance-Monitoring-Service`
   - **Supported account types:** Accounts in this organizational directory only (Single tenant)
   - Redirect URI: kosongkan
3. Klik **Register**
4. Setelah terdaftar, catat dua nilai ini dari halaman Overview:
   - **Application (client) ID** → akan diisi ke `ClientId` di `appsettings.json`
   - **Directory (tenant) ID** → akan diisi ke `TenantId` di `appsettings.json`

**Buat Client Secret:**

5. Buka menu **Certificates & secrets** → **Client secrets** → **New client secret**
6. Isi description dan pilih expiry (misal 24 months)
7. Klik **Add** — salin **Value** sekarang, tidak bisa dilihat lagi setelah tutup halaman
8. Value tersebut → isi ke `ClientSecret` di `appsettings.json`

**Tambahkan API Permission:**

9. Buka menu **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
10. Cari dan centang: `Sites.ReadWrite.All`
11. Klik **Add permissions**
12. Klik **Grant admin consent for [nama organisasi]** → konfirmasi **Yes**
13. Pastikan status kolom **Status** berubah menjadi ✅ **Granted for...**

---

### 2.2 SharePoint Site

1. Buka SharePoint (misal `https://contoso.sharepoint.com`)
2. Buat Communication Site baru atau gunakan site yang sudah ada
3. Catat URL site, misal: `https://contoso.sharepoint.com/sites/Attendance`

**Ambil Site ID** via [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer):

```
GET https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/Attendance
```

Dari response JSON, catat nilai field `id`. Formatnya seperti ini:

```
contoso.sharepoint.com,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
```

Nilai inilah yang diisi ke `SiteId` di `appsettings.json`.

---

### 2.3 Raw List — Semua Event Individual

List ini menyimpan **setiap event** yang ditangkap service: login, logout, shutdown, restart, crash.

**Buat List:**

1. Buka SharePoint Site → klik **⚙ gear** → **Site contents** → **+ New** → **List**
2. Pilih **Blank list**
3. **Name:** bebas, misal `AttendanceLog`
4. Klik **Create**

**Kolom yang harus dibuat:**

> Kolom `Title` sudah otomatis ada — tidak perlu dibuat ulang.

| Display Name | Internal Name (harus persis) | Tipe | Catatan |
|---|---|---|---|
| Title | Title | Single line of text | Sudah ada otomatis |
| Username | Username | Single line of text | Buat baru |
| ComputerName | ComputerName | Single line of text | Buat baru |
| EventID | EventID | Number | Buat baru — pilih **Number**, bukan text |
| EventTime | EventTime | Date and Time | Buat baru — aktifkan **Include Time** |
| EventType | EventType | Multiple lines of text | Buat baru — plain text, bukan rich text |

> ⚠️ **Internal name harus persis sama** dengan kolom di atas (case-sensitive). Nama internal ditentukan saat pertama kali kolom dibuat. Jika display name diubah belakangan, internal name tidak berubah.

**Index yang harus dibuat:**

Buka **List Settings** → **Indexed columns** → **Create a new index**:

| Primary Column | Secondary Column | Alasan |
|---|---|---|
| EventTime | (kosongkan) | Query idempotency check (filter `EventTime ge ... le ...`) dan cleanup task |

---

### 2.4 Summary List — Ringkasan Harian per User

List ini menyimpan **satu row per user per hari** — jam masuk pertama dan jam pulang terakhir.

**Buat List:**

1. Buka SharePoint Site → klik **⚙ gear** → **Site contents** → **+ New** → **List**
2. Pilih **Blank list**
3. **Name:** bebas, misal `AttendanceSummary`
4. Klik **Create**

**Kolom yang harus dibuat:**

> Kolom `Title` sudah otomatis ada — tidak perlu dibuat ulang.

| Display Name | Internal Name (harus persis) | Tipe | Catatan |
|---|---|---|---|
| Title | Title | Single line of text | Sudah ada otomatis. Format: `ComputerName\Username\yyyy-MM-dd` |
| Username | Username | Single line of text | Buat baru |
| ComputerName | ComputerName | Single line of text | Buat baru |
| WorkDate | WorkDate | Date and Time | Buat baru — pilih **Date Only** (tanpa time) |
| LoginTime | LoginTime | Date and Time | Buat baru — aktifkan **Include Time** |
| ExpectedTimeOut | ExpectedTimeOut | Date and Time | Buat baru — aktifkan **Include Time** |
| ShutdownTime | ShutdownTime | Date and Time | Buat baru — aktifkan **Include Time** |
| ShutdownType | ShutdownType | Single line of text | Buat baru |
| Status | Status | Single line of text | Optional tapi direkomendasikan: untuk flag `UNCONFIRMED` (fallback 6005) |

**Index yang harus dibuat:**

Buka **List Settings** → **Indexed columns** → **Create a new index** — buat **3 index terpisah**, masing-masing satu kolom:

| Primary Column | Secondary Column | Alasan |
|---|---|---|
| Username | (kosongkan) | OData filter `fields/Username eq '...'` |
| ComputerName | (kosongkan) | OData filter `fields/ComputerName eq '...'` |
| WorkDate | (kosongkan) | OData filter `fields/WorkDate eq '...'` dan cleanup task |

> SharePoint mengindex per-kolom, bukan compound. Dengan ketiga kolom di-index, kombinasi query `Username AND ComputerName AND WorkDate` berjalan tanpa perlu header `Prefer: HonorNonIndexedQueriesWarningMayFailRandomly`, sehingga tidak ada risiko query gagal secara random.

---

### 2.5 Ambil List ID

Setelah kedua list dibuat, ambil ID masing-masing. Cara termudah via Graph Explorer:

```
GET https://graph.microsoft.com/v1.0/sites/{siteId}/lists
```

Dari response, cari berdasarkan `displayName`, lalu catat nilai `id` masing-masing list:

```json
{
  "value": [
    {
      "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "displayName": "AttendanceLog",
      ...
    },
    {
      "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
      "displayName": "AttendanceSummary",
      ...
    }
  ]
}
```

- `AttendanceLog` → `ListId` di `appsettings.json`
- `AttendanceSummary` → `SummaryListId` di `appsettings.json`

---

### 2.6 Regional Settings — Wajib untuk Tampilan Jam yang Benar

Service selalu menyimpan datetime dalam **UTC** ke SharePoint. SharePoint secara otomatis mengkonversi UTC ke timezone lokal untuk **tampilan** — sesuai setting Regional Settings site.

Kalau tidak diset, jam yang tampil di SharePoint akan **bergeser 7 jam** dari waktu sebenarnya.

**Langkah:**

1. Buka SharePoint Site
2. Klik **⚙ gear icon** (pojok kanan atas) → **Site settings**

   > Jika tidak ada opsi Site settings, coba akses langsung:  
   > `https://contoso.sharepoint.com/sites/Attendance/_layouts/15/regionalsetng.aspx`

3. Di bawah **Site Administration** → klik **Regional settings**
4. Ubah **Time zone** menjadi:
   ```
   (UTC+07:00) Bangkok, Hanoi, Jakarta
   ```
5. Klik **OK**

> Data UTC yang tersimpan di SharePoint tidak berubah. Hanya tampilan di browser yang mengikuti timezone ini.

---

### 2.7 appsettings.json

Setelah semua langkah di atas, isi `appsettings.json` yang ada di folder publish:

```json
{
  "AzureSettings": {
    "TenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ClientSecret": "your-client-secret-value"
  },
  "SharePointSettings": {
    "SiteId": "contoso.sharepoint.com,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "ListId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "SummaryListId": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  },
  "AppSettings": {
    "VerboseLogging": false,
    "QueueAlertThreshold": 500,
    "DispatchBackoffSeconds": [30, 60, 120, 300, 600]
  }
}
```

| Key | Sumber |
|---|---|
| `AzureSettings:TenantId` | Directory (tenant) ID dari App Registration |
| `AzureSettings:ClientId` | Application (client) ID dari App Registration |
| `AzureSettings:ClientSecret` | Client secret value yang dibuat di step 2.1 |
| `SharePointSettings:SiteId` | ID dari response Graph API di step 2.2 |
| `SharePointSettings:ListId` | ID raw list (`AttendanceLog`) dari step 2.5 |
| `SharePointSettings:SummaryListId` | ID summary list (`AttendanceSummary`) dari step 2.5 — opsional, jika dikosongkan fitur Summary tidak aktif |
| `AppSettings:VerboseLogging` | `true` untuk debug log detail, `false` untuk log essential |
| `AppSettings:QueueAlertThreshold` | Batas pending queue untuk high-water alert |
| `AppSettings:DispatchBackoffSeconds[]` | Jadwal retry dispatch (default: 30,60,120,300,600 detik; setelah itu tetap interval terakhir) |

---

## 3. Architecture Overview

```
Windows Event Log (Security + System)
        │
        ├── OnSecurityEventWritten (live)
        └── OnSystemEventWritten   (live)
                │
         ShouldSkipLiveEntry?
         (eventTime <= replayUpperBound → skip)
                │
         ProcessSecurityEntryAsync / ProcessSystemEntryAsync
                │
         ┌──────────────────────────────┐
         │   PersistentEventQueue       │  queue\\pending\\*.json
         │   EnqueueIfNotDuplicateAsync │
         └──────────────────────────────┘
                │
         ProcessQueuedEventsTask (background loop)
                │
         TryDispatchQueuedEventAsync
                │
         ┌──────────────┬──────────────┐
         │              │              │
      Raw List     Summary List    SummaryCache
   (ListId)     (SummaryListId)  summary-cache.json
```

---

## 4. Data Files

Lokasi: `C:\ProgramData\Attendance-Monitoring-Service\`

| File | Isi | Ditulis Kapan |
|------|-----|---------------|
| `event-stop.checkpoint` | Timestamp event terakhir diproses (UTC) | Per-event, heartbeat 1 menit, OnStop, crash handler |
| `event-stop.checkpoint.bak` | Backup identik dari primary | Bersamaan dengan primary (atomic write) |
| `event-replay.checkpoint` | `replayUpperBound` dari replay terakhir (UTC) | Setelah `ReplayMissedEventsFromCheckpoint()` selesai |
| `queue\\pending\\*.json` | Antrian event yang belum di-dispatch ke SharePoint (1 file per event) | Persistent — survive restart |
| `summary-cache.json` | Keys summary yang sudah berhasil dikirim ke SharePoint | Setiap `UpsertDailySummaryLoginAsync` berhasil |
| `summary-cache.json.bak` | Backup dari summary-cache sebelum write terakhir | Atomic write (File.Replace) |

### 4.1 Atomic Write Pattern

```
1. Tulis ke  → event-stop.checkpoint.tmp
2. File.Move(tmp → event-stop.checkpoint, overwrite:true)
3. Tulis ke  → event-stop.checkpoint.bak.tmp
4. File.Move(tmp → event-stop.checkpoint.bak, overwrite:true)
```

Crash saat write → file `.tmp` rusak, file utama tetap valid.

---

## 5. Windows Event IDs Monitored

### 5.1 Security Log

| Event ID | Deskripsi |
|----------|-----------|
| 4624 | User login berhasil |
| 4647 | User logout eksplisit |

### 5.2 System Log

| Event ID | Deskripsi |
|----------|-----------|
| 1074 | Shutdown atau restart diinisiasi |
| 6006 | Event Log service berhenti (setelah shutdown/restart) |
| 6008 | Unexpected shutdown (power loss) |
| 41 | Kernel power — system crash |
| 42 | Sleep |

---

## 6. Application Log Event IDs

Semua log ditulis ke **Windows Application Event Log**.

### 6.1 Service Lifecycle

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 0 | Info | Service start / stop (source: Attendance-Service) |
| 1001 | Error | Constructor error — gagal inisialisasi EventLog |
| 1002 | Error | Gagal start setelah max retries |
| 1004 | Error | Gagal decrypt konfigurasi |

### 6.2 Checkpoint

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 1017 | Warning | Gagal save stop checkpoint |
| 1018 | Info | Saving checkpoint (OnStop/OnShutdown) |
| 1019 | Info | Checkpoint saved (OnStop/OnShutdown) |
| 1020 | Info | SaveStopCheckpoint: dir + path info |
| 1021 | Info | SaveStopCheckpoint: created directory |
| 1022 | Info | SaveStopCheckpoint: berhasil ditulis ke primary + backup |
| 1023 | Warning | LoadStopCheckpoint: fallback / exception |
| 1024 | Info | LoadStopCheckpoint: loaded dari primary |
| 1025 | Info | EnsureCheckpointBootstrap: seeded missing checkpoint |
| 1026 | Warning | EnsureCheckpointBootstrap failed |
| 1027 | Warning | LoadStopCheckpoint: exception |
| 1043 | Warning | LoadStopCheckpoint: replay checkpoint stale → clamp ke 7 hari |

### 6.3 Replay

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 1029 | Info | ReplayMissedEvents: no checkpoint found, skipping |
| 1030 | Info | ReplaySystemEvents: found N events |
| 1031 | Info | ReplaySystemEvents: processing EventId=X |
| 1032 | Info | ReplaySecurityEvents: found N events |
| 1033 | Info | ReplaySecurityEvents: processing EventId=X |
| 1034 | Info | ReplayMissedEvents: replayFrom + replayTo |
| 1035 | Warning | ReplaySecurityEvents: fromTime null — skipping |
| 1036 | Warning | ReplaySystemEvents: fromTime null — skipping |
| 1037 | Info | Live event skipped during replay overlap |
| 1038 | Info | Live event skipped — older than replayUpperBound (rate-limited: 1x/30 detik) |

### 6.4 Queue & Dispatch

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 1006 | Warning | HandleServiceStopping: timeout menunggu dispatch selesai |
| 1007 | Error | Error in MonitorEvents |
| 1008 | Warning | Error in CleanupOldRecordsTask |
| 1009 | Warning | Error in ProcessSecurityEntryAsync |
| 1010 | Warning | Error in ProcessSystemEntryAsync |
| 1011 | Warning | Error in ProcessEvent |
| 1014 | Warning | Error in ReplayMissedEventsFromCheckpoint |
| 1015 | Warning | Error in ProcessQueuedEventsTask |
| 1016 | Info | Duplicate event skipped |
| 1028 | Warning | Dispatch failed (exception) |
| 1029 | Warning | Summary permanently failed setelah 5 retry → skip |
| 1040 | Warning | Queue: recovered from backup setelah JsonException |
| 1041 | Warning | Queue: backup recovery failed |
| 1042 | Warning | Queue: JSON corrupted, resetting queue |

### 6.5 Debug System Event Parsing

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 2001 | Warning | DBG-1074: NULL message — skipping |
| 2002 | Info | DBG-1074: message preview |
| 2003 | Info | DBG-1074: GetUserFromSystem1074Message result |
| 2004 | Info | DBG-1074: stored state username + shutdownType |
| 2005 | Info | DBG-6006: resolved username + confirmed shutdownType |
| 2006 | Info | DBG-eventId: username null, fallback lastActiveUser |
| 2007 | Info | DBG-eventId: GetMostRecentUser result |
| 2008 | Warning | DBG-eventId: DROPPING event — no username resolved |
| 2010 | Info | DBG-6006: TryResolve — no prior 1074 state in memory |
| 2011 | Info | DBG-6006: TryResolve — diff > 60 detik |
| 2012 | Info | DBG-6006: TryResolve — matched username + diff |
| 2020 | Info | DBG-1074: broad fallback matched candidate |
| 2021 | Warning | DBG-1074: GetUserFromSystem1074Message exception |

### 6.6 SharePoint Summary

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 3001 | Info | UpsertLogin: user, computer, loginTime, workDate, summaryKey |
| 3002 | Info | UpsertLogin: row exists, storedLogin vs incoming |
| 3003 | Info | UpsertLogin: updating to earlier loginTime |
| 3004 | Info | UpsertLogin: creating new row |
| 3005 | Info | UpsertLogin: successfully created row |
| 3006 | Info | UpsertLogin: deleting duplicate row (auto-cleanup) |
| 3007 | Info | UpsertLogin: cache hit — row already exists, skipping |
| 3008 | Info | FindSummaryItemWithRetry: attempt N not found, retrying |
| 3009 | Warning | FindSummaryItemWithRetry: all attempts exhausted |
| 3010 | Info | TryUpdateShutdown: user, computer, shutdownTime, eventId |
| 3011 | Info | TryUpdateShutdown: SKIP — no matching summary row |
| 3012 | Info | TryUpdateShutdown: found row — loginTime, currentShutdown, allFields |
| 3013 | Info | TryUpdateShutdown: SKIP — IsValidShutdownCandidate=false |
| 3014 | Info | TryUpdateShutdown: SKIP — priority too low |
| 3015 | Info | TryUpdateShutdown: SKIP — same priority, existing later |
| 3016 | Info | TryUpdateShutdown: PATCHING — priority + isNewSession |
| 3017 | Info | TryUpdateShutdown: PATCH success |
| 3018 | Info | TryUpdateShutdown: NEW SESSION detected — reset priority |
| 3019 | Warning | FindSummaryItemForShutdown: cache hit but not found on first attempt, retrying |
| 3020 | Warning | FindSummaryItemAsync: HTTP error |
| 3021 | Info | FindSummaryItemAsync: result count |
| 3022 | Info | TryUpdateShutdown: PATCH body |

### 6.7 Dispatch & Raw List

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 4001 | Warning | Token null — skipping dispatch |
| 4002 | Info | DISPATCH: detail queueId, eventId, needsRaw, needsSummary |
| 4003 | Info | DISPATCH: Raw record sent |
| 4004 | Info | DISPATCH: Sending summary login |
| 4005 | Info | DISPATCH: Sending summary shutdown |
| 4006 | Info | DISPATCH: Summary dispatched |
| 4007 | Info | DISPATCH: Done — doneRaw + doneSummary |
| 4008 | Info | DISPATCH: Shutdown group hold — waiting for 6006 or timer |
| 4009 | Info | DISPATCH: Shutdown group — 6006 already in group or higher priority exists, skipping summary |
| 4010 | Info | Waiting 30 detik for network on fresh boot |
| 4011 | Warning | Token attempt failed: HTTP status |
| 4012 | Warning | Token attempt network error (SocketException) |
| 4013 | Warning | Token attempt exception |
| 4020 | Info | RAW: Inserting — title, eventTime, eventType |
| 4021 | Info | RAW: Idempotency — record already exists, skipping |
| 4022 | Info | RAW: Insert success |
| 4023 | Warning | RAW: Insert attempt failed — HTTP status |
| 4024 | Warning | RAW: Insert attempt exception |
| 4025 | Info | RAW: Idempotency hit — title match dalam window ±60 detik |

### 6.8 Cleanup

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 5001 | Info | Cleanup started — cutoffDate, listId, summaryListId |
| 5002 | Info | Cleanup ListId (raw) selesai — N items deleted |
| 5003 | Info | Cleanup SummaryListId selesai — N items deleted |
| 5004 | Warning | Cleanup gagal fetch items — HTTP error |
| 5005 | Warning | Cleanup gagal delete item — HTTP error (bukan 404) |
| 5006 | Info | SummaryCache cleanup: removed N old entries |

### 6.9 Crash & Unhandled Exceptions

| Event ID | Level | Deskripsi |
|----------|-------|-----------|
| 9996 | Error | Unhandled exception in OnSystemEventWritten |
| 9997 | Error | Unhandled exception in OnSecurityEventWritten |
| 9998 | Error | Unobserved task exception |
| 9999 | Error | Unhandled exception (crash handler) |

---

## 7. Login Filtering

### 7.1 Logon Type

Hanya logon type berikut yang diproses:

| LogonType | Nama | Diproses |
|-----------|------|----------|
| 2 | Interactive | ✅ |
| 7 | Unlock | ✅ |
| 10 | RemoteInteractive (RDP) | ✅ |
| 11 | CachedInteractive | ✅ |
| 3 | Network | ❌ |
| 4 | Batch | ❌ |
| 5 | Service | ❌ |
| Lainnya | — | ❌ |

### 7.2 Username Filtering

| Kondisi | Hasil |
|---------|-------|
| Kosong / whitespace | ❌ rejected |
| `SYSTEM`, `LOCAL SERVICE`, `LOCAL_SYSTEM`, `NETWORK SERVICE` | ❌ rejected |
| `ANONYMOUS LOGON`, `Guest`, `DefaultAccount`, `Administrator` | ❌ rejected |
| Berakhiran `$` | ❌ computer account |
| Prefix `DWM-`, `UMFD-`, `NT Service` | ❌ system account |
| Valid | ✅ diproses |

### 7.3 Username Normalization (4624 / 4647 / 1074)

- Untuk event **4624** dan **4647**, service parse `Security ID` (SID) dari message.
- Jika SID valid, service resolve SID ke `NTAccount` (`DOMAIN\Username`) lalu simpan **display username tanpa domain**.
- Fallback jika translate SID gagal: gunakan `Account Name` yang diparse dari event.
- Akibatnya, variasi seperti `annafi.nur@...` (4624) dan `AnnafiNur` (4647) akan dinormalisasi ke satu username yang konsisten berdasarkan SID.
- Untuk event **1074**, username tetap diambil dari message dan selalu disimpan tanpa domain (format sama seperti 4647).

---

## 8. Admin Login Detection

Windows membuat **2 event 4624** untuk setiap admin login (UAC split token):

| Event | Elevated Token | Keterangan |
|-------|---------------|------------|
| Event 1 | Yes | High integrity token |
| Event 2 | No | Filtered standard token |

Keduanya memiliki field `Linked Logon ID` yang **non-zero** dan saling pointing satu sama lain.

**Filter:** Kalau `Linked Logon ID != 0x0000000000000000` → ini bagian dari admin split token pair → **kedua event di-skip**. Login admin tidak dicatat sebagai attendance karena biasanya hanya untuk keperluan teknis (buka Event Viewer, jalankan sc command, copy file ke Program Files, dll).

---

## 9. Checkpoint System

### 9.1 Writers

| Layer | Trigger | Value Ditulis | Tujuan |
|-------|---------|---------------|--------|
| Per-event | ProcessEvent enqueue | `eventTime - 1 detik` (UTC) | Akurasi — event ini ikut di-replay jika service restart sebelum dispatch selesai |
| Heartbeat | Timer 1 menit | `DateTime.UtcNow` | Safety net saat idle (tidak ada event masuk) |
| OnStop / OnShutdown | Service stop normal | `UtcNow - 5 detik` (jika lebih baru dari existing) | Graceful stop |
| Crash handler | UnhandledException / UnobservedTaskException | `UtcNow - 1 menit` | Last-resort sebelum process mati |

**Guard:** Per-event hanya menulis jika `candidate > existingCheckpoint` — tidak pernah mundur. Tanpa ini, replay event lama bisa overwrite checkpoint hari ini.

### 9.2 LoadStopCheckpoint — 4-Level Fallback

| Level | Kondisi | replayFrom | Event ID |
|-------|---------|-----------|----------|
| 1 Primary | File primary ada dan valid | Isi file | 1024 Info |
| 2 Backup | Primary hilang/rusak | Isi file.bak | 1023 Warning |
| 3 Derived | Kedua stop checkpoint tidak ada, replay checkpoint ada | `replayCheckpoint - 5 menit` | 1023 Warning |
| 3b Derived Stale | Derived < `UtcNow - 7 hari` | `UtcNow - MaxReplayLookback (7 hari)` | 1043 Warning |
| 4 Fresh Install | Tidak ada checkpoint sama sekali | `today 00:00:00 UTC` | 1023 Warning |

---

## 10. Replay System

### 10.1 Flow

```
OnStart()
  → EnableRaisingEvents = true          ← DULU sebelum replay
  → replayTo = DateTime.UtcNow
  → replayUpperBound = replayTo
  → replayInProgress = true
  → replayFrom = LoadStopCheckpoint()
  → ReplaySecurityEvents(replayFrom, replayTo)
      scan Security log
      filter: eventTime > replayFrom && <= replayTo
      filter: EventId 4624, 4647
      pre-filter: LogonType harus valid
      sort: ascending (eventTime)
      process one-by-one
  → ReplaySystemEvents(replayFrom - 30 detik, replayTo)
      scan System log
      filter: eventTime > (replayFrom - 30s) && <= replayTo
      filter: EventId 1074, 6006, 6008, 41, 42
      sort: ascending
      process one-by-one
  → SaveReplayCheckpoint(replayTo)
  → replayInProgress = false
  → StartCheckpointHeartbeat()
```

> **Catatan penting:** `EnableRaisingEvents = true` diaktifkan **sebelum** replay dimulai. Ini mencegah gap: event yang terjadi antara `replayTo` dan saat listener aktif akan muncul sebagai live event dan diproses dengan benar. Event yang terjadi sebelum `replayUpperBound` otomatis di-skip oleh `ShouldSkipLiveEntry`.

### 10.2 Mengapa System Events Replay Dimulai 30 Detik Lebih Awal

1074 dan 6006 bisa terjadi bersamaan di detik yang sama (misalnya 15:53:04 dan 15:53:07). Checkpoint di-save sebagai `eventTime - 1 detik` sehingga 1074 di 15:53:04 menghasilkan checkpoint 15:53:03. Namun karena berbagai faktor timing, 1074 bisa jatuh 1–2 detik sebelum `replayFrom`.

Dengan extend `replayFrom - 30 detik` untuk system events, 1074 selalu masuk replay dan state-nya ter-set di memory **sebelum** 6006 di-replay → pairing 1074↔6006 bekerja → 6006 jadi "Confirmed" bukan "Unconfirmed".

### 10.3 Urutan Replay

| Alasan | Penjelasan |
|--------|-----------|
| Security events dulu | 4624 mengisi `lastActiveUser` yang dibutuhkan system events |
| 1074 sebelum 6006 | `TryResolve1074StateFor6006` butuh `last1074Username` di memory |
| Sort ascending | Memastikan 1074 → 6006 diproses sesuai urutan kronologis |

### 10.4 Live Event Filter

Filter `ShouldSkipLiveEntry` berlaku **permanen** (bukan hanya saat replay):

```
if (eventTime <= replayUpperBound) → SKIP
```

Ini menangani kasus Windows yang mem-fire event lama dari Security log saat `EnableRaisingEvents = true` — bisa terjadi baik saat replay berlangsung maupun setelahnya. Log 1038 di-rate-limit (maksimal 1x per 30 detik) untuk menghindari spam.

---

## 11. Deduplication

### 11.1 Queue-Level Dedup

`PersistentEventQueue.EnqueueIfNotDuplicateAsync`:

| Kriteria | Window | Behaviour |
|---------|--------|-----------|
| EventId + Username + ComputerName sama | 30 detik | Skip duplicate |
| EventId 4624, incoming lebih awal | 30 detik | Replace existing (simpan timestamp paling awal) |

Window 30 detik: cukup lebar untuk menangkap Windows yang kadang fire 2 event 4624 dalam selisih beberapa detik, tapi cukup kecil agar unlock dan login berikutnya tidak saling ter-dedup.

### 11.2 Raw List Idempotency Check

Sebelum insert ke raw list, `RawRecordAlreadyExistsAsync` query SharePoint dengan filter `EventTime` window ±60 detik, lalu cocokkan `Title` dari hasil. Jika ada → skip insert.

### 11.3 IsSummaryEligible

Field pada `QueuedAttendanceEvent` untuk event login (4624 normal atau 6005 fallback):
- `true` hanya jika belum ada event login lain dengan `Username+ComputerName+WorkDate` yang sama di queue
- Memastikan hanya 1 row per hari di SummaryListId dari sisi queue

`IsSummaryEligible` dipersist di file queue per-event, namun `FindSummaryItemWithRetryAsync` di `UpsertDailySummaryLoginAsync` tetap menjadi authoritative check — jika row sudah ada di SharePoint, service tidak akan create baru.

---

## 12. Queue System

### 12.1 PersistentEventQueue

Path: `queue\\pending\\*.json`

Queue di-persist ke disk sehingga event yang belum di-dispatch ke SharePoint tidak hilang kalau service restart / crash.

### 12.2 Shutdown Group

Event 4647, 1074, dan 6006 yang terjadi dalam satu rangkaian shutdown dikelompokkan dalam satu **ShutdownGroup**. Tujuannya agar summary hanya di-dispatch oleh event dengan priority tertinggi di group — mencegah race condition antar event dalam rangkaian yang sama.

**Group key** format: `shutdown_{ComputerName}_{Username}_{WorkDate}_{EpochMenit}`

Epoch menit (bukan detik) dipakai agar event dalam window 60 detik yang sama masuk group yang sama meski ada selisih beberapa detik antar event.

**Fields di `QueuedAttendanceEvent`:**

| Field | Tipe | Keterangan |
|-------|------|-----------|
| `ShutdownGroupId` | `string?` | ID group. Null untuk event non-shutdown (4624, 6008, 41) |
| `ShutdownGroupHoldUntil` | `DateTime?` | Batas waktu hold summary. 10 detik dari event pertama group |
| `ShutdownGroupIsRestart` | `bool` | True jika 1074 di group adalah restart — semua member skip summary |

**Hold logic saat dispatch:**

```
4647 / 1074 di queue, 6006 belum ada, timer belum habis (10 detik)
  → raw dispatch langsung ✅
  → summary DITAHAN (log 4008)

6006 masuk queue → group lengkap
  → 6006 dispatch summary (priority 5) ✅
  → 4647 dan 1074 skip summary — 6006 sudah ada di group (log 4009) ✅

Fast Startup (6006 tidak muncul) → timer 10 detik habis
  → event dengan priority tertinggi yang ada dispatch summary ✅
  → event lain skip summary (log 4009) ✅

1074 Restart masuk queue
  → ShutdownGroupIsRestart = true di-propagate ke semua member group
  → semua member (4647, 1074, 6006) skip summary ✅
```

### 12.3 Dispatch Loop

`ProcessQueuedEventsTask` berjalan sebagai background task:

```
while not cancelled:
  Peek item ready pertama dari queue
  TryDispatchQueuedEventAsync(item)
  
  if success:
    Remove item dari queue
  else:
    retryCount++
    nextRetryAt = now + backoff(retryCount)
    Persist retry state ke file queue item
```

Backoff default: `30s → 60s → 120s → 300s → 600s`, lalu tetap `600s`.
State retry (`DispatchRetryCount`, `NextRetryAtUtc`) disimpan di file queue item (persisten lintas restart).

---

## 13. Dispatch & SharePoint Integration

### 13.1 Raw List (ListId)

Setiap event yang valid dikirim ke raw list sebagai individual record:

| Field SharePoint | Isi |
|----------------|-----|
| Title | `ComputerName\EventId\Username` |
| Username | Username |
| EventID | Event ID Windows |
| EventTime | UTC (format: `yyyy-MM-ddTHH:mm:ssZ`) |
| EventType | Deskripsi event (mis. "User Login\nLogon Type: 11 - CachedInteractive") |
| ComputerName | Nama PC |

**Index yang dibutuhkan di SharePoint:** `EventTime`

### 13.2 Summary List (SummaryListId)

Satu row per user per hari:

| Field SharePoint | Isi |
|----------------|-----|
| Title | `ComputerName\Username\yyyy-MM-dd` |
| Username | Username |
| ComputerName | Nama PC |
| WorkDate | Tanggal kerja (format: `yyyy-MM-dd`) |
| LoginTime | UTC login pertama hari itu — tidak pernah diupdate ke yang lebih baru |
| ExpectedTimeOut | LoginTime + 9 jam |
| ShutdownTime | UTC shutdown/logout terakhir yang valid |
| ShutdownType | Format: `EventId - Label` (mis. `6006 - Shutdown Completed (Shutdown Initiated)`) |

**Index yang dibutuhkan di SharePoint:** `Username`, `ComputerName`, `WorkDate` (masing-masing as primary column)

---

## 14. Summary List Logic

### 14.1 UpsertDailySummaryLoginAsync

```
1. Cek SummaryCache → cache hit? → return (skip query)
2. FindSummaryItemWithRetryAsync (retry 3x: 3s, 6s, 12s delay)
3. Row ada?
   → pilih canonical row (LoginTime paling awal)
   → hapus duplikat row jika ada (Event ID 3006)
   → update LoginTime jika incoming lebih awal
   → tulis ke SummaryCache
   → return
4. Row tidak ada setelah semua retry → create new row
   → tulis ke SummaryCache
```

**FindSummaryItemWithRetryAsync** dibutuhkan karena Graph API eventual consistency — row yang baru di-insert mungkin belum muncul di query berikutnya dalam beberapa detik.

### 14.2 TryUpdateDailySummaryShutdownAsync

```
1. FindSummaryItemForShutdownAsync
   - Cek SummaryCache untuk today key
   - Cache hit? → FindSummaryItemAsync (1 attempt)
     - Gagal? → FindSummaryItemWithRetryAsync (retry penuh)
   - Cache miss? → FindSummaryItemWithRetryAsync langsung
   - Fallback: cek yesterday key (untuk overnight session, max 20 jam)
2. Row tidak ada → SKIP (log 3011)
3. IsValidShutdownCandidate? → validasi timing
4. Priority check → hanya overwrite jika priority lebih tinggi
5. isNewSession check → jika shutdownTime > currentShutdown → reset priority (sesi baru)
6. PATCH ShutdownTime + ShutdownType
```

### 14.3 IsValidShutdownCandidate

| Rule | Kondisi | Hasil |
|------|---------|-------|
| 1074 Restart | `eventType` mengandung "restart"/"reboot" | ❌ skip |
| Sebelum login | `shutdownTime < loginTime` | ❌ skip |
| Session guardrail | `shutdownTime > loginTime + 20 jam` | ❌ skip |

---

## 15. Shutdown Priority

Priority menentukan event mana yang boleh overwrite `ShutdownTime` di Summary. Higher wins.

| Priority | Event ID | Kondisi | Label Tersimpan |
|----------|----------|---------|-----------------|
| 5 | 6006 | Ada paired 1074 shutdown (bukan restart) | `6006 - Shutdown Completed (Shutdown Initiated)` |
| 4 | 1074 | Shutdown/power-off (bukan restart) | `1074 - Shutdown Initiated` |
| 2 | 4647 | User logout eksplisit | `4647 - User Logout` |
| 1 | 6008 | Unexpected shutdown (power loss) | `6008 - Unexpected Shutdown` |
| 1 | 41 | System crash / kernel panic | `41 - System Crash` |
| 0 | 1074 | Restart initiated | ❌ tidak ditulis ke Summary |
| 0 | 6006 | Tidak ada paired 1074 (unconfirmed) | ❌ tidak ditulis ke Summary |
| 0 | 42 | Sleep | ❌ tidak ditulis ke Summary |

**1074 ↔ 6006 pairing window:** 60 detik. Jika dalam 60 detik setelah 1074 ada 6006, keduanya dipasangkan.

**Shutdown Group & Priority:**

4647, 1074, dan 6006 selalu dalam satu rangkaian — baik saat shutdown maupun restart. Yang membedakan keduanya adalah 1074:

- 1074 shutdown → `ShutdownGroupIsRestart = false` → priority system berlaku → 6006 menang (priority 5)
- 1074 restart → `ShutdownGroupIsRestart = true` → seluruh group skip summary, termasuk 4647

Ini berarti 4647 **tidak pernah berdiri sendiri** sebagai penanda shutdown/logout — nilainya hanya valid jika group-nya bukan restart.

| Skenario | Hasil di Summary |
|---------|-----------------|
| Shutdown normal: 4647 + 1074 + 6006 | `6006 - Shutdown Completed (Shutdown Initiated)` ✅ |
| Fast Startup: 4647 + 1074 (tanpa 6006) | `1074 - Shutdown Initiated` ✅ |
| Restart: 4647 + 1074(restart) + 6006(unconfirmed) | ShutdownTime tidak berubah ✅ |
| Power loss / crash: 6008 atau 41 | `6008 - Unexpected Shutdown` / `41 - System Crash` ✅ |

**isNewSession rule:**

Jika `incoming shutdownTime > existing shutdownTime` di SharePoint, dianggap sesi baru — priority existing diabaikan dan shutdown terbaru selalu menang. Contoh: user shutdown jam 09:00 (6006, priority 5), login lagi jam 13:00, shutdown lagi jam 17:00 (4647) → 17:00 > 09:00 → new session → 4647 jam 17:00 ditulis ✅.

---

## 16. Summary Cache

File: `summary-cache.json`

### 16.1 Tujuan

Mencegah duplikat row di SummaryListId **lintas service restart**. Setelah restart, queue kosong sehingga `IsSummaryEligible` tidak bisa mendeteksi bahwa row untuk `user+computer+workDate` hari ini sudah ada. Cache ini menjawab pertanyaan itu secara lokal tanpa query SharePoint.

### 16.2 Format

```json
{
  "keys": [
    "ON-083\\annafi\\2026-03-13",
  ]
}
```

Key format: `ComputerName\Username\yyyy-MM-dd`

### 16.3 Write Policy

- Ditulis setelah `UpsertDailySummaryLoginAsync` berhasil confirm atau create row
- Idempotent — aman dipanggil berkali-kali untuk key yang sama
- Atomic write dengan `.bak` file

### 16.4 Cleanup

Entry lebih dari 7 hari otomatis dihapus oleh `CleanupOldEntriesAsync`, dipanggil bersamaan dengan cleanup SharePoint di `CleanupOldRecordsTask`.

---

## 17. Cleanup Task

| Parameter | Value |
|-----------|-------|
| Jadwal | 03:00 setiap hari (local time) |
| Retention | 6 bulan |
| Target lists | ListId (filter: `EventTime`), SummaryListId (filter: `WorkDate`) |
| SummaryCache | Entry > 7 hari dihapus |
| Random delay | 0–5 menit (seed: `MachineName.GetHashCode()`) |
| Missed cleanup | Jika service start setelah jam 03:00 → cleanup langsung dijalankan |

### 17.1 Behavior di 36 Device

- Tidak ada koordinasi antar device
- Setiap device cleanup **semua** data lama (tidak dibatasi per ComputerName)
- Kalau 2 device cleanup bersamaan dan coba hapus item yang sama → device kedua dapat HTTP 404 → diabaikan (bukan error)
- Tidak ada data corrupt, tidak ada race condition

---

## 18. DateTime & Timezone

**Semua DateTime di sistem menggunakan UTC.**

| Komponen | Format | Keterangan |
|---------|--------|------------|
| Windows Event Log (internal) | UTC | `SystemTime` di XML event |
| `entry.TimeGenerated` | Local | Di-convert ke UTC segera: `.ToUniversalTime()` |
| Checkpoint files | UTC string dengan Z suffix | `DateTime.UtcNow.ToString("O")` |
| SharePoint fields (LoginTime, ShutdownTime, EventTime) | UTC dengan Z suffix | `"yyyy-MM-ddTHH:mm:ssZ"` |
| WorkDate | `yyyy-MM-dd` (local date) | Tidak di-convert ke UTC — agar tanggal sesuai hari kerja setempat |
| SummaryCache keys | `yyyy-MM-dd` (local date) | Sama dengan WorkDate |

**SharePoint Regional Settings** harus diset ke **UTC+7 (Bangkok/Hanoi/Jakarta)** agar display di SharePoint menampilkan waktu yang benar. System tetap menyimpan UTC — SharePoint yang convert untuk tampilan.

**ParseFieldDateTime:** SharePoint mengembalikan UTC (Z suffix). Di-parse dengan `DateTimeStyles.RoundtripKind` lalu tetap sebagai UTC untuk comparison yang konsisten dengan `eventTime` yang juga UTC.

---

## 19. Username Resolution (System Events)

### 19.1 Event 1074 (Shutdown/Restart Initiated)

1. Parse username dari message 1074.
2. Jika username termasuk system trigger (exact list atau keyword contains), lakukan fallback ke **first Event 4624** (earliest timestamp) untuk **device + workDate yang sama** dari:
   - in-memory first-logon index, lalu
   - pending queue files (`queue\\pending\\*.json`).
3. Jika fallback berhasil:
   - `Username` diisi resolved user,
   - metadata queue diisi `ResolvedUsername`, `OriginalUsername`, `IsFallback=true`, `FallbackSource=FirstLogon4624`.
4. Jika tidak ada 4624 yang cocok → event 1074 di-drop dan alasan ditulis ke Application Event Log.

### 19.2 Event 6005 (Fallback Login saat Security log unavailable/cleared)

6005 fallback hanya dipakai jika konteks menunjukkan Security log unavailable/cleared **dan** tidak ada 4624 untuk device+workDate.

Urutan resolusi username:
1. Most recent 4624 dari in-memory/queue pending untuk device+workDate.
2. Jika tidak ada, query SharePoint berdasarkan device.
3. Jika tetap tidak ada dan jaringan sedang unavailable:
   - event 6005 tetap dipersist ke queue dengan `Status=UNCONFIRMED`,
   - `FallbackSource=Event6005_Pending`,
   - `PendingUsernameResolution=true` untuk dicoba ulang pada siklus dispatch berikutnya.

Jika resolve berhasil:
- `FallbackSource` = `Event6005_PreviousLog` atau `Event6005_SharePoint`
- Summary login row dibuat/diupdate sebagai `UNCONFIRMED` (ClockOut tetap kosong sampai shutdown valid masuk).

---

## 20. Multi-Device Behavior

Service dirancang untuk berjalan di banyak device secara bersamaan tanpa koordinasi:

| Aspek | Behavior |
|-------|---------|
| Raw list writes | Concurrent insert dari device berbeda — SharePoint handle ini natively |
| Summary list writes | Tiap device upsert row-nya sendiri (`ComputerName\Username\WorkDate` unik per device) |
| SummaryCache | Lokal per device — tidak di-share |
| Cleanup | Siapapun yang cleanup pertama, hapus semua data lama semua device. Device lain yang cleanup belakangan tidak ketemu data lama → nothing to delete → aman |
| Cleanup 404 | HTTP 404 saat delete diabaikan (item sudah dihapus device lain) |
| Token | Masing-masing device fetch token sendiri (App Registration shared) |
