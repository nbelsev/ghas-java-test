/**
 * Investigating proposed fixes for XXE in javax.xml.validation.Validator.validate() as detected by GHAS code scanning.
 *
 * OWASP suggested fix: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#validator
 *
 * Alternative fix involves disabling external entities on the XMLReader used by the Validator, but may lead to a FP
 * in GHAS.
 */
package nbelsev.test.xxe;

import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import static javax.xml.XMLConstants.*;

public class XXEDemo {
	public static final String DISALLOW_DOCTYPE_DECL = "http://apache.org/xml/features/disallow-doctype-decl";
	public static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
	public static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
	
	private static SAXParserFactory securedParserFactory;
	
	/**
	 * Vulnerable validation implementation.
	 */
	public static boolean validateXml(String xsdPath, String xmlPath) throws Exception {
		SchemaFactory factory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		Schema schema = factory.newSchema(new StreamSource(ClassLoader.getSystemResourceAsStream(xsdPath)));
		Validator validator = schema.newValidator();
		
		validator.validate(new StreamSource(ClassLoader.getSystemResourceAsStream(xmlPath))); //Vulnerable to XXE
		
		return true;
	}

	/**
	 * Secure validation directly based on OWASP guidance.
	 */
	public static boolean secureValidateXmlOWASP(String xsdPath, String xmlPath) throws Exception {
		SchemaFactory factory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		factory.setProperty(ACCESS_EXTERNAL_DTD, "");
		factory.setProperty(ACCESS_EXTERNAL_SCHEMA, "");
		
		Schema schema = factory.newSchema(new File(xsdPath));
		
		Validator validator = schema.newValidator();
		validator.setProperty(ACCESS_EXTERNAL_DTD, "");
		validator.setProperty(ACCESS_EXTERNAL_SCHEMA, "");
		
		validator.validate(new StreamSource(new File(xmlPath))); //Not vulnerable to XXE
		
		return true;
	}
	
	/**
	 * Helper for alternative fix - create a secure SAXParserFactory.
	 */
	public static SAXParserFactory createSecuredParserFactory() throws Exception {
		SAXParserFactory parserFactory = SAXParserFactory.newInstance();
		parserFactory.setNamespaceAware(true);
		parserFactory.setFeature(DISALLOW_DOCTYPE_DECL, true);
		parserFactory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		parserFactory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		parserFactory.setFeature(FEATURE_SECURE_PROCESSING, true);
		return parserFactory;
	}
	
	/**
	 * Helper for alternative fix - create a secure XMLReader.
	 */
	public static XMLReader createSecureReader(SAXParserFactory parserFactory) throws Exception {
		XMLReader reader = parserFactory.newSAXParser().getXMLReader();
		reader.setFeature(DISALLOW_DOCTYPE_DECL, true);
		reader.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		reader.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		reader.setFeature(FEATURE_SECURE_PROCESSING, true);
		reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		return reader;
	}
	
	/**
	 * Helper for alternative fix - create schema for validation.
	 */
	public static Schema createSchema(InputStream schemaSource) throws Exception {
		XMLReader securedReader = createSecureReader(securedParserFactory);
		SAXSource src = new SAXSource(securedReader, new InputSource(schemaSource));
		
		SchemaFactory schemaFactory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		schemaFactory.setFeature(DISALLOW_DOCTYPE_DECL, true);
		schemaFactory.setFeature(FEATURE_SECURE_PROCESSING, true);
		
		return schemaFactory.newSchema(src);
	}
	
	/**
	 * Alternative fix.
	 */
	public static boolean secureValidateXml(String xsdPath, String xmlPath) throws Exception {
		//Fix step 1 - Create secure schema
		Schema schema = createSchema(new FileInputStream(xsdPath));
		
		//Fix step 2 - Create secure SAXParserFactory and XMLReader
		SAXParserFactory parserFactory = createSecuredParserFactory(); //NB: Why does their fix call this again instead of using the existing one?
		XMLReader securedReader = createSecureReader(parserFactory);
		
		//Fix step 3 - Create filtered SAXSource using above secure reader
		NamespaceFilter filter = new NamespaceFilter(securedReader, "");
		SAXSource src = new SAXSource(filter, new InputSource(xmlPath));
		
		//Fix step 4 - Validate
		Validator securedValidator = schema.newValidator();
		securedValidator.validate(src);
		
		return true;
	}
	
	/**
	 * Load and print XML to verify results.
	 */
	public static void loadAndPrintXml(String xmlPath) throws Exception {
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
		
		SAXParser saxParser = saxParserFactory.newSAXParser();
		PersonXMLHandler handler = new PersonXMLHandler();
		
		saxParser.parse(new StreamSource(ClassLoader.getSystemResourceAsStream(xmlPath)).getInputStream(), handler);
		
		System.out.println("[+] Person name=" + handler.name + ", age=" + handler.age + ", valid=" + handler.valid);
	}
	
	/**
	 * Test validation mechanisms.
	 */
	public static void main(String[] args) throws Exception {
		String xsdPath = "";
		String xmlPath = "";
		
		//Get XSD/XML paths from command line
		if(args.length == 3) {
			xsdPath = args[1];
			xmlPath = args[2];
		} else {
			xsdPath = "GoodSchema.xsd";
			xmlPath = "GoodXml.xml";
		}
		
		//Setup
		securedParserFactory = createSecuredParserFactory();
		
		//Parse and validate XML docs
//		System.out.println("OWASP validation result 1: " + secureValidateXmlOWASP(xsdPath, xmlPath));
//		System.out.println("Secure validation result 1: " + secureValidateXml(xsdPath, xmlPath));
		System.out.println("Validation result 1: " + validateXml(xsdPath, xmlPath));
		loadAndPrintXml(xmlPath);
		
//		System.out.println("OWASP validation result 1: " + secureValidateXmlOWASP("GoodSchema.xsd", "GoodXml.xml"));
//		System.out.println("Secure validation result 1: " + secureValidateXml("GoodSchema.xsd", "GoodXml.xml"));
//		System.out.println("Validation result 1: " + validateXml("GoodSchema.xsd", "GoodXml.xml"));
//		loadAndPrintXml("GoodXml.xml");

//		System.out.println("OWASP validation result 2: " + secureValidateXmlOWASP("GoodSchema.xsd", "BadXml.xml")); //Exception due to billion laughs XXE payload
//		System.out.println("Secure validation result 2: " + secureValidateXml("GoodSchema.xsd", "BadXml.xml"));
//		System.out.println("Validation result 2: " + validateXml("GoodSchema.xsd", "BadXml.xml")); //XXE
//		loadAndPrintXml("BadXml.xml");
	}
}
