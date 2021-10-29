using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace MetaSPID.Metadata
{
    public class CreateMetadata
    {
        private X509Certificate2 cert;
        private string keyCertificate;
        private string ID;
        private XmlDocument doc;
        private MetadataInfo info;
  
        public CreateMetadata(X509Certificate2 cert, MetadataInfo info)
        {
            this.cert = cert;
            doc = new XmlDocument();
            doc.PreserveWhitespace = false;
            ID = "_" + Guid.NewGuid().ToString();
            keyCertificate = getX509CertificateString();
            this.info = info;
        }


        public XmlDocument getMetadata()
        {
            string metadata = "<md:EntityDescriptor entityID=\"" + info.ENTITY_ID + "\" ID=\"" + ID + "\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchemainstance\" xmlns:spid=\"https://spid.gov.it/saml-extensions\">" +
                                "<md:SPSSODescriptor protocolSupportEnumeration =\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAssertionsSigned=\"true\" AuthnRequestsSigned=\"true\">" +
                                  "<md:KeyDescriptor use=\"signing\">" +
                                    "<ds:KeyInfo>" +
                                        "<ds:X509Data>" +
                                            "<ds:X509Certificate>" + keyCertificate + "</ds:X509Certificate>" +
                                    "</ds:X509Data>" +
                                    "</ds:KeyInfo>" +
                                  "</md:KeyDescriptor>" +
                                  "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location =\"" + info.logout_service_url + "\"/>" +
                                  "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>" +
                                  "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + info.assertion_consumer_service_url + "\" index=\"0\" isDefault=\"true\"/>" +
                                  "<md:AttributeConsumingService index =\"0\">" +
                                    "<md:ServiceName xml:lang =\"it\">"+info.nomeServizi +"</md:ServiceName>" +
                                    "<md:RequestedAttribute Name =\"spidCode\"/>" +
                                    "<md:RequestedAttribute Name =\"familyName\"/>" +
                                    "<md:RequestedAttribute Name =\"name\"/>" +
                                    "<md:RequestedAttribute Name =\"companyName\"/>" +
                                    "<md:RequestedAttribute Name =\"fiscalNumber\"/>" +
                                    "<md:RequestedAttribute Name =\"ivaCode\"/>" +
                                    "<md:RequestedAttribute Name =\"email\"/>" +
                                    "<md:RequestedAttribute Name =\"gender\"/>" +
                                    "<md:RequestedAttribute Name =\"placeOfBirth\"/>" +
                                    "<md:RequestedAttribute Name =\"countyOfBirth\"/>" +
                                    "<md:RequestedAttribute Name =\"dateOfBirth\"/>" +
                                  "</md:AttributeConsumingService>" +
                                  "<md:AttributeConsumingService index=\"99\">"+
                                    "<md:ServiceName xml:lang=\"it\">eIDAS Natural Person Minimum Attribute Set</md:ServiceName>"+
                                    "<md:RequestedAttribute Name =\"dateOfBirth\"/>"+        
                                    "<md:RequestedAttribute Name =\"familyName\"/>"+
                                    "<md:RequestedAttribute Name =\"name\"/> "+
                                    "<md:RequestedAttribute Name =\"spidCode\"/> "+
                                  "</md:AttributeConsumingService > " +
                                  "<md:AttributeConsumingService index=\"100\">"+
                                    "<md:ServiceName xml:lang=\"it\">eIDAS Natural Person Full Attribute Set</md:ServiceName>"+
                                    "<md:RequestedAttribute Name =\"address\"/>"+
                                    "<md:RequestedAttribute Name =\"dateOfBirth\"/>"+
                                    "<md:RequestedAttribute Name =\"familyName\"/>"+
                                    "<md:RequestedAttribute Name =\"gender\"/>"+
                                    "<md:RequestedAttribute Name =\"name\"/>"+
                                    "<md:RequestedAttribute Name =\"placeOfBirth\"/>"+
                                    "<md:RequestedAttribute Name =\"spidCode\"/>"+
                                  "</md:AttributeConsumingService>" +
                                 "</md:SPSSODescriptor>" +
                                  "<md:Organization>" +
                                       "<md:OrganizationName xml:lang =\"it\">" + info.denominazione_ente + "</md:OrganizationName>" +
                                       "<md:OrganizationDisplayName xml:lang=\"it\">" + info.denominazione_ente + "</md:OrganizationDisplayName>" +
                                       "<md:OrganizationURL xml:lang =\"it\">" + info.url_ente + "</md:OrganizationURL>" +
                                 "</md:Organization>" +
                                      "<md:ContactPerson contactType =\"other\">" +
                                    "<md:Extensions>" +
                                      "<spid:IPACode>" + info.codiceIPA + "</spid:IPACode>" +
                                      "<spid:Public/>" +
                                    "</md:Extensions>" +
                                    "<md:EmailAddress >" + info.emailAddress + "</md:EmailAddress>" +
                                  "</md:ContactPerson>" +
                               "</md:EntityDescriptor>";

            doc.LoadXml(metadata);
            XmlElement signature = SignDoc(doc, cert, ID);
            return metadataXmlSigned(signature, doc);
        }



        private XmlDocument metadataXmlSigned(XmlElement signature, XmlDocument doc)
        {
            doc.DocumentElement.PrependChild(signature);
            doc.PreserveWhitespace = true;
            return doc;
        }



        private XmlElement SignDoc(XmlDocument doc, X509Certificate2 cert2, string referencevalue)
        {
            CryptoConfig.AddAlgorithm(typeof(RsaPkCs1Sha256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            var exportedKeyMaterial = cert2.PrivateKey.ToXmlString(true);
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.PersistKeyInCsp = false;
            key.FromXmlString(exportedKeyMaterial);
            SignedXmlWithID sig = new SignedXmlWithID(doc);
            sig.SigningKey = key;
            sig.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            sig.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            Reference reference = new Reference();
            reference.Uri = String.Empty;
            reference.Uri = "#" + referencevalue;
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            XmlDsigExcC14NTransform env2 = new XmlDsigExcC14NTransform();
            reference.AddTransform(env);
            reference.AddTransform(env2);
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            sig.AddReference(reference);
            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyData = new KeyInfoX509Data(cert2);
            keyInfo.AddClause(keyData);
            sig.KeyInfo = keyInfo;
            sig.ComputeSignature();
            XmlElement xmlDigitalSignature = sig.GetXml();
            return xmlDigitalSignature;
        }

        private string getX509CertificateString()
        {
            byte[] bt = cert.GetRawCertData();
            String n = Convert.ToBase64String(bt);
            return n;
        }
    }

}
