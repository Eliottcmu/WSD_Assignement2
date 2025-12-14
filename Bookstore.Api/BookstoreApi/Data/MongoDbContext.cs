using Bookstore.Api.Models;
using MongoDB.Driver;

namespace Bookstore.Api.Data
{
    public class MongoDbContext
    {
        public IMongoDatabase Database { get; }

        public MongoDbContext(IConfiguration config)
        {
            var connectionString = config["MongoDb:ConnectionString"];
            var databaseName = config["MongoDb:DatabaseName"];

            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentNullException(
                    nameof(connectionString),
                    "MongoDB connection string is missing"
                );

            if (string.IsNullOrEmpty(databaseName))
                throw new ArgumentNullException(
                    nameof(databaseName),
                    "MongoDB database name is missing"
                );

            var client = new MongoClient(connectionString);
            Database = client.GetDatabase(databaseName);
        }

        public IMongoCollection<User> Users => Database.GetCollection<User>("Users");
        public IMongoCollection<Order> Orders => Database.GetCollection<Order>("Orders");
        public IMongoCollection<OrderItem> OrderItems =>
            Database.GetCollection<OrderItem>("OrderItems");
    }
}
