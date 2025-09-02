package nbelsev.test.xxe;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLFilterImpl;

public class NamespaceFilter extends XMLFilterImpl {
	private String requiredNamespace;
	
	public NamespaceFilter(XMLReader parent, String requiredNamespace) {
		super(parent);
		this.requiredNamespace = requiredNamespace;
	}
	
	@Override
	public void startElement(String uri, String localName, String qName, Attributes atts) throws SAXException {
		if(!uri.equals(requiredNamespace)) {
			uri = requiredNamespace;
		}
		
		super.startElement(uri, localName, qName, atts);
	}
}
