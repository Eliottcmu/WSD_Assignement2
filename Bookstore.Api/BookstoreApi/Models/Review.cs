using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public class Review
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? ReviewId { get; set; }

        [BsonElement("book_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public required string BookId { get; set; }

        [BsonElement("user_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public required string UserId { get; set; }

        [BsonElement("content")]
        public required string Content { get; set; }

        [BsonElement("rating")]
        public int Rating { get; set; }

        [BsonElement("likes")]
        public List<string> Likes { get; set; } = new();

        [BsonElement("like_count")]
        public int? LikesCount { get; set; }

        [BsonElement("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("updated_at")]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
