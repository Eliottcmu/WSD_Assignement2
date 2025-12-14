using Bookstore.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Bookstore.Api.Services
{
    public class ReviewService
    {
        private readonly IMongoCollection<Review> _reviews;
        private readonly IMemoryCache _cache;

        private const string TOP_REVIEWS_CACHE_KEY = "top_reviews";
        private const int TOP_COUNT = 10;

        public ReviewService(IConfiguration config, IMemoryCache cache)
        {
            var client = new MongoClient(config["MongoDb:ConnectionString"]);
            var database = client.GetDatabase(config["MongoDb:DatabaseName"]);
            _reviews = database.GetCollection<Review>("Reviews");
            _cache = cache;
        }

        public async Task<(List<Review> items, int total)> GetPagedAsync(
            string? bookId,
            int page,
            int pageSize
        )
        {
            var filter = FilterDefinition<Review>.Empty;

            if (!string.IsNullOrWhiteSpace(bookId) && ObjectId.TryParse(bookId, out _))
                filter = Builders<Review>.Filter.Eq(x => x.BookId, bookId);

            var total = (int)await _reviews.CountDocumentsAsync(filter);

            var items = await _reviews
                .Find(filter)
                .SortByDescending(r => r.CreatedAt)
                .SortByDescending(r => r.LikesCount)
                .Skip((page - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();

            return (items, total);
        }

        public async Task<Review?> GetByIdAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return null;
            return await _reviews.Find(r => r.ReviewId == id).FirstOrDefaultAsync();
        }

        public async Task<Review> CreateAsync(Review review)
        {
            await _reviews.InsertOneAsync(review);
            _cache.Remove(TOP_REVIEWS_CACHE_KEY); // invalidate
            return review;
        }

        public async Task<bool> UpdateAsync(string id, Review updated)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            var result = await _reviews.ReplaceOneAsync(r => r.ReviewId == id, updated);

            if (result.ModifiedCount > 0)
                _cache.Remove(TOP_REVIEWS_CACHE_KEY);

            return result.ModifiedCount > 0;
        }

        public async Task<bool> DeleteAsync(string id)
        {
            if (!ObjectId.TryParse(id, out _))
                return false;

            var result = await _reviews.DeleteOneAsync(r => r.ReviewId == id);

            if (result.DeletedCount > 0)
                _cache.Remove(TOP_REVIEWS_CACHE_KEY);

            return result.DeletedCount > 0;
        }

        public async Task<bool> ToggleLikeAsync(string reviewid, string userId)
        {
            if (!ObjectId.TryParse(reviewid, out _))
                return false;

            var review = await GetByIdAsync(reviewid);
            if (review == null)
                return false;

            var userHasLiked = review.Likes.Contains(userId); //list de strings

            var update = userHasLiked
                ? Builders<Review>.Update.Pull(r => r.Likes, userId).Inc(r => r.LikesCount, -1)
                : Builders<Review>.Update.AddToSet(r => r.Likes, userId).Inc(r => r.LikesCount, 1);

            await _reviews.UpdateOneAsync(r => r.ReviewId == reviewid, update);
            _cache.Remove(TOP_REVIEWS_CACHE_KEY);

            return true;
        }

        public async Task<List<Review>> GetTopReviewsAsync()
        {
            if (!_cache.TryGetValue(TOP_REVIEWS_CACHE_KEY, out List<Review>? topReviews))
            {
                topReviews = await _reviews
                    .Find(FilterDefinition<Review>.Empty)
                    .SortByDescending(r => r.LikesCount)
                    .ThenByDescending(r => r.CreatedAt)
                    .Limit(TOP_COUNT)
                    .ToListAsync();

                var options = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(500),
                };

                _cache.Set(TOP_REVIEWS_CACHE_KEY, topReviews, options);
            }

            return topReviews!;
        }
    }
}
