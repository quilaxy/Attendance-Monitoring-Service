using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

namespace EventLogOutEmployeeService;

public class Program
{
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Attendance-Monitoring-Service");

    private static void Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        try
        {
            if (!Environment.UserInteractive)
            {
                RunService();
                return;
            }

            bool runAsService = args.Any(arg =>
                string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase));

            if (runAsService)
            {
                RunService();
                return;
            }

            RunConsole(args);
        }
        catch (Exception ex)
        {
            WriteCrash("[Program.Main] Fatal exception", ex.ToString());
            SafeWriteEventLog("Application",
                $"[FATAL] Program.Main crashed: {ex}",
                EventLogEntryType.Error, 9995);
            throw;
        }
    }

    private static void RunService()
    {
        ServiceBase.Run(new ServiceBase[]
        {
            new LoginLogoutMonitorService()
        });
    }

    private static void RunConsole(string[] args)
    {
        var service = new LoginLogoutMonitorService();

        Console.WriteLine("Running in console mode (development/debug).");
        Console.WriteLine("Press Ctrl+C to stop.");

        service.StartForConsole(args);

        using ManualResetEvent stopEvent = new(false);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopEvent.Set();
        };

        stopEvent.WaitOne();
        service.StopForConsole();
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        string details = e.ExceptionObject?.ToString() ?? "(exception object null)";
        WriteCrash($"[Program.cs] UnhandledException isTerminating={e.IsTerminating}", details);

        SafeWriteEventLog("Application",
            $"[CRASH] Program unhandled exception (isTerminating={e.IsTerminating}): {details}",
            EventLogEntryType.Error, 9994);
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        WriteCrash("[Program.cs] UnobservedTaskException", e.Exception.ToString());

        SafeWriteEventLog("Application",
            $"[CRASH] Program unobserved task exception: {e.Exception}",
            EventLogEntryType.Error, 9993);

        e.SetObserved();
    }

    private static void WriteCrash(string title, string details)
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            string crashLogPath = Path.Combine(DataDirectory, "crash.log");
            string content = $"[{DateTime.Now:O}] {title}\n{details}\n\n";
            File.AppendAllText(crashLogPath, content);
        }
        catch
        {
            // Avoid recursive crash on crash logger itself.
        }
    }

    private static void SafeWriteEventLog(string source, string message, EventLogEntryType type, int eventId)
    {
        try
        {
            EventLog.WriteEntry(source, message, type, eventId);
        }
        catch
        {
            // EventLog service can be unavailable during shutdown.
        }
    }
}
