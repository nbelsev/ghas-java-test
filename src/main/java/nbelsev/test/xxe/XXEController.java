package nbelsev.test.xxe;

import java.sql.*;

import java.sql.Connection;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class XXEController {
	private static Connection connection;
	
	@GetMapping("/")
	@ResponseBody
	public String testXml(@RequestParam(name = "xml", required = false) String xmlPath,
						  @RequestParam(name = "xsd", required = false) String xsdPath) {
		String out;
		
		//if(XXEDemo.validateXml(xmlPath, xsdPath)) {
		//if(XXEDemo.secureValidateXmlOWASP(xmlPath, xsdPath)) {
		if(XXEDemo.secureValidateXml(xmlPath, xsdPath)) {
			out = "Validation result: success!";
		} else {
			out = "Validation result: failed.";
		}
		
		return out;
	}
}
