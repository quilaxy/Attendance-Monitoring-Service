using System;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace EventLogOutEmployeeService;

public class Program
{
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Attendance-Monitoring-Service");

    private static void Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        if (!Environment.UserInteractive)
        {
            ServiceBase.Run(new ServiceBase[]
            {
                new LoginLogoutMonitorService()
            });
            return;
        }

        bool runAsService = args.Any(arg =>
            string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase));

        if (runAsService)
        {
            ServiceBase.Run(new ServiceBase[]
            {
                new LoginLogoutMonitorService()
            });
            return;
        }

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
        try
        {
            Directory.CreateDirectory(DataDirectory);
            string crashLogPath = Path.Combine(DataDirectory, "crash.log");
            string content = $"[{DateTime.Now:O}] [Program.cs] isTerminating={e.IsTerminating}\n" +
                             $"{e.ExceptionObject}\n\n";
            File.AppendAllText(crashLogPath, content);
        }
        catch 
        {
            
        }
    }
}
