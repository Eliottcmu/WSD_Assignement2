using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class SellerService
    {
        private readonly IMongoCollection<Seller> _sellers;

        protected SellerService() { } // For testing

        public SellerService(IConfiguration config)
        {
            var client = new MongoClient(config["MongoDb:ConnectionString"]);
            var db = client.GetDatabase(config["MongoDb:DatabaseName"]);
            _sellers = db.GetCollection<Seller>("Sellers");
        }

        public virtual async Task<(List<Seller> items, int total)> GetPagedAsync(
            int page,
            int pageSize,
            string? keyword = null
        )
        {
            var filter = FilterDefinition<Seller>.Empty;

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                filter = Builders<Seller>.Filter.Or(
                    Builders<Seller>.Filter.Regex(
                        x => x.BusinessName,
                        new BsonRegularExpression(keyword, "i")
                    ),
                    Builders<Seller>.Filter.Regex(
                        x => x.BusinessNumber,
                        new BsonRegularExpression(keyword, "i")
                    ),
                    Builders<Seller>.Filter.Regex(
                        x => x.PayoutHolder,
                        new BsonRegularExpression(keyword, "i")
                    )
                );
            }

            var total = (int)await _sellers.CountDocumentsAsync(filter);

            var items = await _sellers
                .Find(filter)
                .SortByDescending(x => x.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();

            return (items, total);
        }

        public virtual async Task<Seller?> GetByIdAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return null;

            return await _sellers.Find(x => x.SellerId == id).FirstOrDefaultAsync();
        }

        public virtual async Task<Seller> CreateAsync(Seller s)
        {
            s.CreatedAt = DateTime.UtcNow;
            s.UpdatedAt = DateTime.UtcNow;
            await _sellers.InsertOneAsync(s);
            return s;
        }

        public virtual async Task<bool> UpdateAsync(string id, Seller updated)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            updated.UpdatedAt = DateTime.UtcNow;

            var result = await _sellers.ReplaceOneAsync(x => x.SellerId == id, updated);
            return result.ModifiedCount > 0;
        }

        public virtual async Task<bool> DeleteAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            var result = await _sellers.DeleteOneAsync(x => x.SellerId == id);
            return result.DeletedCount > 0;
        }

        public virtual async Task<bool> ExistsAsync(string id)
        {
            var count = await _sellers.CountDocumentsAsync(x => x.SellerId == id);
            return count > 0;
        }
    }
}
