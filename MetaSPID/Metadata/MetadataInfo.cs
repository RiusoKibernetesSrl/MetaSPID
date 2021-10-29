using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MetaSPID.Metadata
{
    public class MetadataInfo
    {

        public string ENTITY_ID { get; set; }
        public string denominazione_ente { get; set; }
        public string url_ente { get; set; }
        public string logout_service_url { get; set; }
        public string assertion_consumer_service_url { get; set; }
        public string codiceIPA { get; set; }
        public string emailAddress { get; set; }
        public string nomeServizi { get; set; }
    }
}
