using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public class Seller
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? SellerId { get; set; }

        [BsonElement("user_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public required string UserId { get; set; }

        [BsonElement("business_name")]
        public required string BusinessName { get; set; }

        [BsonElement("business_number")]
        public required string BusinessNumber { get; set; }

        [BsonElement("payout_bank")]
        public required string PayoutBank { get; set; }

        [BsonElement("payout_account")]
        public required string PayoutAccount { get; set; }

        [BsonElement("payout_holder")]
        public required string PayoutHolder { get; set; }

        [BsonElement("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("updated_at")]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
