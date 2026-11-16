using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

//activating controllers and swagger for API documentation and testing
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

//init
InitializeDatabase();

//called necessary middleware for swagger and authorization
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthorization();
app.MapControllers();

app.Run();

static void InitializeDatabase()
{
    using var connection = new SqliteConnection("Data Source=shop.db");
    connection.Open();

    var command = connection.CreateCommand();
    command.CommandText = @"
        CREATE TABLE IF NOT EXISTS Products (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT NOT NULL,
            Price REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Password TEXT NOT NULL,
            SecretNote TEXT NOT NULL
        );

        DELETE FROM Products;
        DELETE FROM Users;

        INSERT INTO Products (Name, Price) VALUES ('Gaming Laptop', 45000);
        INSERT INTO Products (Name, Price) VALUES ('Mechanical Keyboard', 3200);
        INSERT INTO Products (Name, Price) VALUES ('Wireless Mouse', 1500);

        INSERT INTO Users (Username, Password, SecretNote) VALUES ('admin', 'SuperSecretAdminPass123!', 'FLAG{SQL_INJECTION_SUCCESS}');
        INSERT INTO Users (Username, Password, SecretNote) VALUES ('eren', '123456', 'Normal kullanici notu');
    ";
    command.ExecuteNonQuery();
}