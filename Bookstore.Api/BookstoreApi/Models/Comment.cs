using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public class Comment
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? CommentId { get; set; }

        [BsonElement("reviewid")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? ReviewId { get; set; }

        [BsonElement("userId")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? UserId { get; set; }

        [BsonElement("content")]
        public string? Content { get; set; }

        [BsonElement("likes")]
        [BsonRepresentation(BsonType.ObjectId)]
        public List<ObjectId> Likes { get; set; } = new();

        [BsonElement("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("updatedAt")]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
