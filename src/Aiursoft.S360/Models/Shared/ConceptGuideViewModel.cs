namespace Aiursoft.S360.Models.Shared;

public record ConceptGuideViewModel(
    string Title,
    string Icon,
    IReadOnlyList<ConceptTerm> Terms,
    string? Tip = null);

public record ConceptTerm(string Name, string Explanation);
