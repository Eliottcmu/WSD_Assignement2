using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public class OrderItem
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? OrderItemId { get; set; } = default!;

        [BsonRepresentation(BsonType.ObjectId)]
        public string? OrderId { get; set; } = default!;

        [BsonRepresentation(BsonType.ObjectId)]
        public string? BookId { get; set; } = default!;

        public int Quantity { get; set; }
        public decimal Price { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
