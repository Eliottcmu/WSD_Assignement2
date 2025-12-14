using Bookstore.Api.Data;
using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class UserService
    {
        protected UserService() { } // For testing

        private readonly IMongoCollection<User> _users;

        public UserService(MongoDbContext dbContext)
        {
            _users = dbContext.Database.GetCollection<User>("Users");
        }

        public async Task<List<User>> GetAllAsync() => await _users.Find(_ => true).ToListAsync();

        public async Task<User?> GetByIdAsync(string id) =>
            await _users.Find(u => u.UserId == id).FirstOrDefaultAsync();

        public virtual async Task<User?> GetByEmailAsync(string email) =>
            await _users.Find(u => u.Email == email).FirstOrDefaultAsync();

        public async Task<User> CreateAsync(User user)
        {
            user.CreatedAt = DateTime.UtcNow;
            user.UpdatedAt = DateTime.UtcNow;
            await _users.InsertOneAsync(user);
            return user;
        }

        public async Task<bool> UpdateAsync(string id, User updatedUser)
        {
            updatedUser.UpdatedAt = DateTime.UtcNow;

            var result = await _users.ReplaceOneAsync(
                filter: u => u.UserId == id,
                replacement: updatedUser
            );

            return result.IsAcknowledged && result.ModifiedCount > 0;
        }

        public async Task<bool> DeleteAsync(string id)
        {
            var result = await _users.DeleteOneAsync(u => u.UserId == id);
            return result.IsAcknowledged && result.DeletedCount > 0;
        }

        public async Task<bool> EmailExistsAsync(string email)
        {
            var count = await _users.CountDocumentsAsync(u => u.Email == email);
            return count > 0;
        }
    }
}
