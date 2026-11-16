using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

namespace VulnerableShopAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private const string ConnectionString = "Data Source=shop.db";

        // 1. TRUE POSITIVE: Vulnerable to SQL Injection via string concatenation
        [HttpGet("search-vulnerable")]
        public IActionResult SearchVulnerable([FromQuery] string query)
        {
            var products = new List<object>();

            using var connection = new SqliteConnection(ConnectionString);
            connection.Open();

            var command = connection.CreateCommand();
            // Intentionally insecure SQL query construction
            command.CommandText = "SELECT Id, Name, Price FROM Products WHERE Name LIKE '%" + query + "%'";

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                products.Add(new
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Price = reader.GetDouble(2)
                });
            }

            return Ok(products);
        }

        // 2. FALSE POSITIVE TRAP: Safe parameterized query containing raw SQL keywords
        [HttpGet("search-safe")]
        public IActionResult SearchSafe([FromQuery] string query)
        {
            var products = new List<object>();

            using var connection = new SqliteConnection(ConnectionString);
            connection.Open();

            var command = connection.CreateCommand();
            // Secure parameterized query
            command.CommandText = "SELECT Id, Name, Price FROM Products WHERE Name LIKE @searchTerm";
            command.Parameters.AddWithValue("@searchTerm", "%" + query + "%");

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                products.Add(new
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Price = reader.GetDouble(2)
                });
            }

            return Ok(products);
        }
    }
}