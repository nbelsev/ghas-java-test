/**
 * Based on: https://github.com/advanced-security-demo/demo-java
 *
 * This sample should generate an SQLI finding in GHAS code scanning.
 */
package nbelsev.test.sqli;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import nbelsev.test.sqli.Application;
import nbelsev.test.sqli.Book;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {
	
	private static Connection connection;
	
	@GetMapping("/")
	@ResponseBody
	public List<Book> getBooks(@RequestParam(name = "name", required = false) String bookname,
							   @RequestParam(name = "author", required = false) String bookauthor,
							   @RequestParam(name = "read", required = false) Boolean bookread) {
		List<Book> books = new ArrayList<Book>();
		
		Statement statement = null;
		
		try {
			// Init connection to DB
			connection = DriverManager.getConnection(Application.connectionString);
			
			statement = connection.createStatement();
			String query = null;
			
			if (bookname != null) {
				// Filter by book name
				query = "SELECT * FROM Books WHERE name LIKE '%" + bookname + "%'";
			} else if (bookauthor != null) {
				// Filter by book author
				query = "SELECT * FROM Books WHERE author LIKE '%" + bookauthor + "%'";
			} else if (bookread != null) {
				// Filter by if the book has been read or not
				Integer read = bookread ? 1 : 0;
				query = "SELECT * FROM Books WHERE read = '" + read.toString() + "'";
			} else {
				// All books
				query = "SELECT * FROM Books";
			}
			
			ResultSet results = statement.executeQuery(query);
			
			while (results.next()) {
				Book book = new Book(results.getString("name"), results.getString("author"), (results.getInt("read") == 1));
				
				books.add(book);
			}
			
		} catch (SQLException error) {
			error.printStackTrace();
		} finally {
			try {
				if (connection != null) {
					connection.close();
				}
				if (statement != null) {
					statement.close();
				}
			} catch (SQLException error) {
				error.printStackTrace();
			}
		}
		return books;
	}
}
