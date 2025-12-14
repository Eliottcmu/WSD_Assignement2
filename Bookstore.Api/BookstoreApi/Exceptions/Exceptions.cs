namespace Bookstore.Api.Exceptions
{
    public class BadRequestException : Exception
    {
        public BadRequestException(string message)
            : base(message) { }
    }

    public class UnauthorizedException : Exception
    {
        public UnauthorizedException(string message)
            : base(message) { }
    }

    public class ForbiddenException : Exception
    {
        public ForbiddenException(string message)
            : base(message) { }
    }

    public class ConflictException : Exception
    {
        public ConflictException(string message)
            : base(message) { }
    }

    public class NotFoundException : Exception
    {
        public NotFoundException(string message)
            : base(message) { }
    }

    public class DatabaseException : Exception
    {
        public DatabaseException(string message)
            : base(message) { }
    }

    public class TokenExpiredException : Exception
    {
        public TokenExpiredException(string message)
            : base(message) { }
    }
}
