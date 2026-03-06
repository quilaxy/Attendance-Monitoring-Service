using System;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace EventLogOutEmployeeService;

public class Program
{
    private static void Main(string[] args)
    {
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
}
