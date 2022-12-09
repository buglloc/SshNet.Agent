using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Renci.SshNet;

namespace SshNet.Agent.Sample
{
    class Program
    {
        const string sshHost = "blah-blah";
        const string sshUser = "blah-blah";

        static void Main(string[] args)
        {
            try
            {
                var agent = new SshAgent();
                Console.WriteLine("list agent keys");
                var keys = agent.RequestIdentities();
                foreach (var key in keys)
                {
                    Console.WriteLine(key.ToString());
                }

                Console.WriteLine($"connecting to {sshUser}@{sshHost}");
                try
                {
                    using var client = new SshClient(sshHost, sshUser, keys.ToArray<IPrivateKeyFile>());
                    client.Connect();
                    client.Disconnect();
                    Console.WriteLine("worked!");
                    Console.WriteLine();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    Console.ReadLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            Console.WriteLine("Done");
            Console.ReadLine();
            }

        private static Stream GetKey(string keyname)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.Agent.Sample.TestKeys.{keyname}");
        }
    }
}