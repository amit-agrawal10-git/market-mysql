package com.market.analytics.kra;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This is a simple example of generating an Enveloping XML
 * Signature using the JSR 105 API. The signature in this case references a
 * local URI that points to an Object element.
 * The resulting signature will look like (certificate and
 * signature values will be different):
 *
 */
    public class KRASOAPGenerationTest implements Serializable {



    //
    // Synopis: java GenEnveloping [output]
    //
    //   where "output" is the name of a file that will contain the
    //   generated signature. If not specified, standard output will be used.
    //
    public static void generate(String digestMethod) throws Exception {

        // First, create the DOM XMLSignatureFactory that will be used to
        // generate the XMLSignature
        String providerName = System.getProperty
                ("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
       /* XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                (Provider) Class.forName(providerName).newInstance());*/
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Next, create a Reference to a same-document URI that is an Object
        // element and specify the SHA1 digest algorithm
        Reference ref = fac.newReference(
                "#Object_1",
                fac.newDigestMethod(digestMethod, null),
                Collections.singletonList
                        (fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                                (TransformParameterSpec) null)), "http://www.w3.org/2000/09/xmldsig#Object", "Reference_1");

        // Next, create the referenced Object
        Document doc = getMessageBody();

        XMLObject obj = fac.newXMLObject
                (Collections.singletonList(new DOMStructure(doc.getDocumentElement())), "Object_1", null, null);

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
                (fac.newCanonicalizationMethod
                                (CanonicalizationMethod.INCLUSIVE,
                                        (C14NMethodParameterSpec) null),
                        fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                        Collections.singletonList(ref));

         KeyStore.PrivateKeyEntry keyEntry = getPrivateKey();
         X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
       // x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);

        // Create a KeyValue containing the PublicKey
        KeyValue kv = kif.newKeyValue(cert.getPublicKey());
        List list = new ArrayList();
        list.add(kv);
        list.add(xd);
        KeyInfo ki = kif.newKeyInfo(list);

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki,
                Collections.singletonList(obj), null, "SignatureValue_1");

        SOAPMessage soapMessage = MessageFactory.newInstance().createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        SOAPEnvelope soapEnvelope = soapPart.getEnvelope();

        SOAPBody soapBody = soapEnvelope.getBody();


        // Create a DOMSignContext and specify the DSA PrivateKey for signing
        // and the document location of the XMLSignature
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), soapBody);

      //  doc.normalizeDocument();
        // Lastly, generate the enveloping signature using the PrivateKey
        signature.sign(dsc);

        Source source = soapPart.getContent();
        org.w3c.dom.Node xroot =
                ((DOMSource)source).getNode();

        // output the resulting document
        OutputStream
            os = new FileOutputStream("src/working/KRASOAPOutput.xml");

        //SerializationUtils.deserialize(SerializationUtils.serialize())
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(xroot), new StreamResult(os));

    }

    public static KeyStore.PrivateKeyEntry getPrivateKey() throws Exception{
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("myKeystore.p12"), "MY_PASSWORD".toCharArray());
        Key key = (PrivateKey) ks.getKey("KEYSTORE_ENTRY", "MY_PASSWORD".toCharArray());
        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry
                        ("KEYSTORE_ENTRY", new KeyStore.PasswordProtection("MY_PASSWORD".toCharArray()));
        return keyEntry;
    }

    public static Document getMessageBody() throws Exception{
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element mb = doc.createElementNS(XMLSignature.XMLNS,"messagebody");
        doc.appendChild(mb);

        Element messageType = doc.createElementNS(XMLSignature.XMLNS,"message_type");
        messageType.appendChild(doc.createTextNode("1"));
        mb.appendChild(messageType);

        Element provider_1 = doc.createElementNS(XMLSignature.XMLNS,"provider_1");
        provider_1.appendChild(doc.createTextNode("900"));
        mb.appendChild(provider_1);

        Element provider_2 = doc.createElementNS(XMLSignature.XMLNS,"provider_2");
        provider_2.appendChild(doc.createTextNode("916"));
        mb.appendChild(provider_2);

        Element provider_3 = doc.createElementNS(XMLSignature.XMLNS,"provider_3");
        provider_3.appendChild(doc.createTextNode("900"));
        mb.appendChild(provider_3);

        Element startr = doc.createElementNS(XMLSignature.XMLNS,"startr");
        startr.appendChild(doc.createTextNode("12054030"));
        mb.appendChild(startr);

        Element stopr = doc.createElementNS(XMLSignature.XMLNS,"stopr");
        stopr.appendChild(doc.createTextNode("12054030"));
        mb.appendChild(stopr);

        Element validd = doc.createElementNS(XMLSignature.XMLNS,"validd");
        validd.appendChild(doc.createTextNode("2018-10-10 20:00:00"));
        mb.appendChild(validd);

        Element tr_id = doc.createElementNS(XMLSignature.XMLNS,"tr_id");
        tr_id.appendChild(doc.createTextNode("TR_1538959634859"));
        mb.appendChild(tr_id);

        Element user_dn = doc.createElementNS(XMLSignature.XMLNS,"user_dn");
        user_dn.appendChild(doc.createTextNode("O=Nemzeti Media- es Hirkozlesi Hatosag, C=HU"));
        mb.appendChild(user_dn);

        Element equip = doc.createElementNS(XMLSignature.XMLNS,"equip");
        equip.appendChild(doc.createTextNode("090"));
        mb.appendChild(equip);

        return doc;
    }
}
