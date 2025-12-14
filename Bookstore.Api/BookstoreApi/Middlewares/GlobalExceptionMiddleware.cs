using System.Net;
using System.Text.Json;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Middleware;

namespace Bookstore.Api.Middleware
{
    public class ApiErrorResponse
    {
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString("o");
        public string Path { get; set; } = default!;
        public int Status { get; set; }
        public string Code { get; set; } = default!;
        public string Message { get; set; } = default!;
        public object? Details { get; set; }
    }

    public static class ErrorCodes
    {
        public const string BAD_REQUEST = "BAD_REQUEST";
        public const string VALIDATION_FAILED = "VALIDATION_FAILED";
        public const string INVALID_QUERY_PARAM = "INVALID_QUERY_PARAM";
        public const string UNAUTHORIZED = "UNAUTHORIZED";
        public const string TOKEN_EXPIRED = "TOKEN_EXPIRED";
        public const string FORBIDDEN = "FORBIDDEN";
        public const string RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND";
        public const string USER_NOT_FOUND = "USER_NOT_FOUND";
        public const string DUPLICATE_RESOURCE = "DUPLICATE_RESOURCE";
        public const string STATE_CONFLICT = "STATE_CONFLICT";
        public const string UNPROCESSABLE_ENTITY = "UNPROCESSABLE_ENTITY";
        public const string TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS";
        public const string INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR";
        public const string DATABASE_ERROR = "DATABASE_ERROR";
        public const string UNKNOWN_ERROR = "UNKNOWN_ERROR";
    }

    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionMiddleware> _logger;

        public GlobalExceptionMiddleware(
            RequestDelegate next,
            ILogger<GlobalExceptionMiddleware> logger
        )
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);

                // Catch 401 or 403 responses not thrown as exceptions
                if (
                    !context.Response.HasStarted
                    && (
                        context.Response.StatusCode == StatusCodes.Status401Unauthorized
                        || context.Response.StatusCode == StatusCodes.Status403Forbidden
                    )
                )
                {
                    await RewriteAuthErrorAsync(context);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred.");
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task RewriteAuthErrorAsync(HttpContext context)
        {
            var code =
                context.Response.StatusCode == StatusCodes.Status401Unauthorized
                    ? ErrorCodes.UNAUTHORIZED
                    : ErrorCodes.FORBIDDEN;

            var message =
                context.Response.StatusCode == StatusCodes.Status401Unauthorized
                    ? "Unauthorized access."
                    : "Access forbidden.";

            var response = new ApiErrorResponse
            {
                Status = context.Response.StatusCode,
                Code = code,
                Message = message,
                Path = context.Request.Path,
            };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }

        private static Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var response = new ApiErrorResponse { Path = context.Request.Path };

            switch (exception)
            {
                case BadRequestException ex:
                    response.Status = (int)HttpStatusCode.BadRequest;
                    response.Code = ErrorCodes.BAD_REQUEST;
                    response.Message = ex.Message;
                    break;

                case UnauthorizedException ex:
                    response.Status = (int)HttpStatusCode.Unauthorized;
                    response.Code = ErrorCodes.UNAUTHORIZED;
                    response.Message = ex.Message;
                    break;

                case TokenExpiredException ex:
                    response.Status = (int)HttpStatusCode.Unauthorized;
                    response.Code = ErrorCodes.TOKEN_EXPIRED;
                    response.Message = ex.Message;
                    break;

                case ForbiddenException ex:
                    response.Status = (int)HttpStatusCode.Forbidden;
                    response.Code = ErrorCodes.FORBIDDEN;
                    response.Message = ex.Message;
                    break;

                case ConflictException ex:
                    response.Status = (int)HttpStatusCode.Conflict;
                    response.Code = ErrorCodes.STATE_CONFLICT;
                    response.Message = ex.Message;
                    break;

                case NotFoundException ex:
                    response.Status = (int)HttpStatusCode.NotFound;
                    response.Code = ErrorCodes.RESOURCE_NOT_FOUND;
                    response.Message = ex.Message;
                    break;

                case DatabaseException ex:
                    response.Status = (int)HttpStatusCode.InternalServerError;
                    response.Code = ErrorCodes.DATABASE_ERROR;
                    response.Message = ex.Message;
                    break;

                default:
                    response.Status = (int)HttpStatusCode.InternalServerError;
                    response.Code = ErrorCodes.INTERNAL_SERVER_ERROR;
                    response.Message = "Internal server error";
                    response.Details = new { exception.Message };
                    break;
            }

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = response.Status;

            return context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}
