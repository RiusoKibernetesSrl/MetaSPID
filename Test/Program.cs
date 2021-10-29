using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {

            MetaSPID.Metadata.MetadataInfo info = new MetaSPID.Metadata.MetadataInfo();
            info.assertion_consumer_service_url = "https://sspidSP.spProvider.it/login";
            info.logout_service_url = "https://spidSP.spProvider.it/login";
            info.url_ente = "https://spidSP.spProvider.it";
            info.codiceIPA = "C_000";
            info.denominazione_ente = "Comune di Roma";
            info.ENTITY_ID = "https://spidSP.spProvider.it";
            info.emailAddress = "info@cmnroma.it";
            info.nomeServizi = "Accesso ai servizi";
            MetaSPID.Manager manager = new MetaSPID.Manager();
            var obj = manager.Crea(info);
            System.IO.File.WriteAllBytes("c:\\temp\\certificato.pfx", obj.x509Byte);
            System.IO.File.WriteAllText("c:\\temp\\PasswordCertificato.txt", obj.passwordCertificato);
            System.IO.File.WriteAllText("c:\\temp\\metadata.xml", obj.metadata.OuterXml);

        }
    }
}
