namespace Aiursoft.S360.Services;

public static class UtcExpiry
{
    // datetime-local values have no offset. The UI explicitly asks for UTC, so treat
    // those wall-clock fields as UTC rather than as the server's local time zone.
    public static DateTime Normalize(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };
}
