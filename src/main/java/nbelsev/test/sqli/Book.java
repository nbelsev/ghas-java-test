/**
 * Based on: https://github.com/advanced-security-demo/demo-java
 *
 * This sample should generate an SQLI finding in GHAS code scanning.
 */
package nbelsev.test.sqli;

public class Book {
	public String name;
	public String author;
	
	public Boolean read = false;
	
	public Book(String name, String author) {
		this.name = name;
		this.author = author;
	}
	
	public Book(String name, String author, Boolean read) {
		this.name = name;
		this.author = author;
		this.read = read;
	}
}
