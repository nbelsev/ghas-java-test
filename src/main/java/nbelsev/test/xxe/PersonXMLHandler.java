package nbelsev.test.xxe;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class PersonXMLHandler extends DefaultHandler {
	public String name;
	public int age;
	public boolean valid;
	
	private StringBuilder dataBuffer;
	
	public PersonXMLHandler() {
		super();
		name = "";
		age = -1;
		dataBuffer = null;
	}
	
	@Override
	public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
		if(qName.equals("name") || qName.equals("age")) {
			dataBuffer = new StringBuilder();
		}
	}
	
	@Override
	public void endElement(String uri, String localName, String qName) throws SAXException {
		if(qName.equals("name")) {
			name = dataBuffer.toString();
		} else if(qName.equals("age")) {
			age = Integer.parseInt(dataBuffer.toString());
		}
	}
	
	@Override
	public void characters(char[] ch, int start, int length) throws SAXException {
		if(dataBuffer != null) {
			dataBuffer.append(ch, start, length);
		}
	}
}
