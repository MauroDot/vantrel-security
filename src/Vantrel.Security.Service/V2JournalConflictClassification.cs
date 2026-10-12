using Vantrel.Security.Core;

namespace Vantrel.Security.Service;

/// <summary>
/// A fail-closed classification of two separately observed journal stores. A future admission
/// layer must obtain coherent observations under its operation boundary before using this result.
/// This class neither opens either store nor authorizes an update or startup.
/// </summary>
internal enum V1V2JournalPresence
{
    NoTransaction,
    HistoricalTransaction,
    V2Transaction,
    ConflictOrUnavailable
}

internal static class V1V2JournalConflictClassifier
{
    internal static V1V2JournalPresence Classify(JournalReadResult historical, V2JournalReadResult v2)
    {
        ArgumentNullException.ThrowIfNull(historical);
        ArgumentNullException.ThrowIfNull(v2);

        if (!ValidObservation(historical) || !ValidObservation(v2))
            return V1V2JournalPresence.ConflictOrUnavailable;

        var historicalPresent = historical.State == JournalReadState.Present;
        var v2Present = v2.State == V2JournalReadState.Present;
        return (historicalPresent, v2Present) switch
        {
            (false, false) => V1V2JournalPresence.NoTransaction,
            (true, false) => V1V2JournalPresence.HistoricalTransaction,
            (false, true) => V1V2JournalPresence.V2Transaction,
            _ => V1V2JournalPresence.ConflictOrUnavailable
        };
    }

    private static bool ValidObservation(JournalReadResult result) => result.State switch
    {
        JournalReadState.Present => result.Journal is not null &&
            result.Failure == UpdateTransactionJournalParseFailure.None,
        JournalReadState.Absent => result.Journal is null &&
            result.Failure == UpdateTransactionJournalParseFailure.Unavailable,
        _ => false
    };

    private static bool ValidObservation(V2JournalReadResult result) => result.State switch
    {
        V2JournalReadState.Present => result.Journal is not null &&
            result.Failure == UpdateTransactionJournalParseFailure.None,
        V2JournalReadState.Absent => result.Journal is null &&
            result.Failure == UpdateTransactionJournalParseFailure.Unavailable,
        _ => false
    };
}
