using System.ServiceProcess;
namespace EventLogOutEmployeeService;
public class Program
{
  private static void Main(string[] args)
  {
    ServiceBase.Run(new ServiceBase[1]
    {
      (ServiceBase) new LoginLogoutMonitorService()
    });
  }
}