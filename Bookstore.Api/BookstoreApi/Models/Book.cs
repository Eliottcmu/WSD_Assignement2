using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public class Book
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? BookId { get; set; }

        [BsonElement("seller_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? SellerId { get; set; }

        [BsonElement("title")]
        public required string Title { get; set; }

        [BsonElement("authors")]
        public required List<string> Authors { get; set; } = new();

        [BsonElement("categories")]
        public required List<string> Categories { get; set; } = new();

        [BsonElement("publisher")]
        public string? Publisher { get; set; }

        [BsonElement("summary")]
        public string? Summary { get; set; }

        [BsonElement("isbn")]
        public string? Isbn { get; set; }

        [BsonElement("price")]
        public decimal Price { get; set; }

        [BsonElement("publication_date")]
        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime? PublicationDate { get; set; }

        [BsonElement("stock")]
        public int Stock { get; set; } = 0;

        [BsonElement("review_count")]
        public int ReviewCount { get; set; } = 0;

        [BsonElement("average_rating")]
        public double AverageRating { get; set; } = 0.0;

        [BsonElement("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("updated_at")]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
