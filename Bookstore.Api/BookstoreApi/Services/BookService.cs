using Bookstore.Api.Models;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class BookService
    {
        private readonly IMongoCollection<Book> _books;

        protected BookService() { } // For testing

        public BookService(IConfiguration config)
        {
            var client = new MongoClient(config["MongoDb:ConnectionString"]);
            var database = client.GetDatabase(config["MongoDb:DatabaseName"]);
            _books = database.GetCollection<Book>("Books");
        }

        public virtual async Task<(List<Book> items, int total)> GetPagedAsync(
            int page,
            int pageSize,
            string? keyword = null
        )
        {
            var filter = FilterDefinition<Book>.Empty;

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                filter = Builders<Book>.Filter.Or(
                    Builders<Book>.Filter.Regex(
                        x => x.Title,
                        new BsonRegularExpression(keyword, "i")
                    ),
                    Builders<Book>.Filter.AnyIn(x => x.Authors, new[] { keyword }),
                    Builders<Book>.Filter.AnyIn(x => x.Categories, new[] { keyword }),
                    Builders<Book>.Filter.Regex(
                        x => x.Publisher,
                        new BsonRegularExpression(keyword, "i")
                    ),
                    Builders<Book>.Filter.Regex(
                        x => x.Summary,
                        new BsonRegularExpression(keyword, "i")
                    ),
                    Builders<Book>.Filter.Regex(
                        x => x.Isbn,
                        new BsonRegularExpression(keyword, "i")
                    )
                );
            }

            var total = (int)await _books.CountDocumentsAsync(filter);

            var items = await _books
                .Find(filter)
                .SortByDescending(x => x.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();

            return (items, total);
        }

        public virtual async Task<Book?> GetByIdAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return null;

            return await _books.Find(x => x.BookId == id).FirstOrDefaultAsync();
        }

        public virtual async Task<Book> CreateAsync(Book book)
        {
            book.CreatedAt = DateTime.UtcNow;
            book.UpdatedAt = DateTime.UtcNow;

            await _books.InsertOneAsync(book);
            return book;
        }

        public virtual async Task<bool> UpdateAsync(string id, Book updated)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            updated.UpdatedAt = DateTime.UtcNow;

            var result = await _books.ReplaceOneAsync(x => x.BookId == id, updated);
            return result.ModifiedCount > 0;
        }

        public virtual async Task<bool> DeleteAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            var result = await _books.DeleteOneAsync(x => x.BookId == id);
            return result.DeletedCount > 0;
        }

        public virtual async Task<bool> ExistsAsync(string id)
        {
            var count = await _books.CountDocumentsAsync(x => x.BookId == id);
            return count > 0;
        }
    }
}
