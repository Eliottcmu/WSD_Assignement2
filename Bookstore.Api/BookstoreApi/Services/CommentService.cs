using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class CommentService
    {
        private readonly IMongoCollection<Comment> _comments;

        public CommentService(IConfiguration config)
        {
            var client = new MongoClient(config["MongoDb:ConnectionString"]);
            var database = client.GetDatabase(config["MongoDb:DatabaseName"]);
            _comments = database.GetCollection<Comment>("Comments");
        }

        public async Task<List<Comment>> GetByReviewAsync(string reviewid, int page, int pageSize)
        {
            return await _comments
                .Find(c => c.ReviewId == reviewid)
                .SortByDescending(c => c.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();
        }

        public async Task<Comment?> GetByIdAsync(string id)
        {
            return await _comments.Find(c => c.CommentId == id).FirstOrDefaultAsync();
        }

        public async Task<Comment> CreateAsync(Comment comment)
        {
            await _comments.InsertOneAsync(comment);
            return comment;
        }

        public async Task<bool> DeleteAsync(string id)
        {
            var result = await _comments.DeleteOneAsync(c => c.CommentId == id);
            return result.DeletedCount > 0;
        }

        public async Task<bool> LikeAsync(string commentId, string userId)
        {
            if (!ObjectId.TryParse(userId, out var objUserId))
                return false;

            var update = Builders<Comment>.Update.AddToSet(c => c.Likes, objUserId);

            var result = await _comments.UpdateOneAsync(c => c.CommentId == commentId, update);

            return result.ModifiedCount > 0;
        }

        public async Task<bool> UnlikeAsync(string commentId, string userId)
        {
            if (!ObjectId.TryParse(userId, out var objUserId))
                return false;

            var update = Builders<Comment>.Update.Pull(c => c.Likes, objUserId);

            var result = await _comments.UpdateOneAsync(c => c.CommentId == commentId, update);

            return result.ModifiedCount > 0;
        }

        public async Task<bool> UpdateAsync(string commentId, Comment comment)
        {
            comment.UpdatedAt = DateTime.UtcNow;
            comment.CommentId = commentId;

            var result = await _comments.ReplaceOneAsync(c => c.CommentId == commentId, comment);

            return result.MatchedCount > 0 && result.ModifiedCount > 0;
        }

        public async Task<long> CountByReviewAsync(string reviewid)
        {
            return await _comments.CountDocumentsAsync(c => c.ReviewId == reviewid);
        }
    }
}
