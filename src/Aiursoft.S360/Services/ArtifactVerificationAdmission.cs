namespace Aiursoft.S360.Services;

/// <summary>Bounds review-driven work across all client addresses in this server process.</summary>
public sealed class ArtifactVerificationAdmission : IDisposable
{
    private readonly object _gate = new();
    private DateTime _window = DateTime.UtcNow;
    private DateTime _nextAudit;
    private int _admitted;
    private int _anonymousAdmitted;
    public SemaphoreSlim AnonymousReviews { get; } = new(4, 4);

    public bool TryAdmit(bool anonymous)
    {
        lock (_gate)
        {
            if (DateTime.UtcNow - _window >= TimeSpan.FromMinutes(1))
            {
                _window = DateTime.UtcNow;
                _admitted = _anonymousAdmitted = 0;
            }
            if (_admitted >= 100 || anonymous && _anonymousAdmitted >= 20) return false;
            _admitted++;
            if (anonymous) _anonymousAdmitted++;
            return true;
        }
    }

    public bool TryQueueAudit()
    {
        lock (_gate)
        {
            if (DateTime.UtcNow < _nextAudit) return false;
            _nextAudit = DateTime.UtcNow.AddMinutes(5);
            return true;
        }
    }

    public void Dispose() => AnonymousReviews.Dispose();
}
