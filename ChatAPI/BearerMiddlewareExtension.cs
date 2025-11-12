namespace ChatAPI
{
    public static class BearerMiddlewareExtension
    {
        public static IApplicationBuilder UseBearerMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<BearerMiddleware>();
        }
    }
}
