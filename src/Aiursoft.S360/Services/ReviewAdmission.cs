namespace Aiursoft.S360.Services;

/// <summary>Bounds review-driven work across all client addresses in this server process.</summary>
public sealed class ReviewAdmission : IDisposable
{
    private readonly object _gate = new();
    private DateTime _nextAudit;
    public SemaphoreSlim AnonymousReviews { get; } = new(4, 4);

    public bool TryQueueAudit()
    {
        lock (_gate)
        {
            if (DateTime.UtcNow < _nextAudit) return false;
            _nextAudit = DateTime.UtcNow.AddMinutes(5);
            return true;
        }
    }

    public void Dispose()
    {
        AnonymousReviews.Dispose();
    }
}
