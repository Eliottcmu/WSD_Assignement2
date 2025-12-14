using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Bookstore.Api.Models
{
    public enum Gender
    {
        MALE,
        FEMALE,
        OTHER,
    }

    public class User
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? UserId { get; set; } = default!;

        [BsonElement("name")]
        public required string Name { get; set; }

        [BsonElement("email")]
        public required string Email { get; set; }

        [BsonElement("password")]
        public required string Password { get; set; }

        [BsonElement("birth_date")]
        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime? BirthDate { get; set; }

        [BsonElement("gender")]
        [BsonRepresentation(BsonType.String)]
        public Gender? Gender { get; set; }

        [BsonElement("address")]
        public string? Address { get; set; }

        [BsonElement("phone_number")]
        public string? PhoneNumber { get; set; }

        [BsonElement("profile_image")]
        public string? ProfileImage { get; set; }

        [BsonElement("review_count")]
        public int ReviewCount { get; set; } = 0;

        [BsonElement("is_admin")]
        public bool IsAdmin { get; set; } = false;

        [BsonElement("created_at")]
        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("updated_at")]
        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        [BsonElement("refresh_token")]
        public string? RefreshToken { get; set; }

        [BsonElement("refresh_token_expiry")]
        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime? RefreshTokenExpiry { get; set; }
    }
}
