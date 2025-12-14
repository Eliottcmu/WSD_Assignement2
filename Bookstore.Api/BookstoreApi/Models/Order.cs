using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public enum OrderStatus
    {
        CREATED,
        PAID,
        SHIPPED,
        CANCELLED,
    }

    public class Order
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? OrderId { get; set; } = default!;

        [BsonRepresentation(BsonType.ObjectId)]
        public string? UserId { get; set; } = default!;

        [BsonRepresentation(BsonType.ObjectId)]
        public string? CouponId { get; set; }

        public decimal TotalAmount { get; set; }
        public OrderStatus Status { get; set; } = OrderStatus.CREATED;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
