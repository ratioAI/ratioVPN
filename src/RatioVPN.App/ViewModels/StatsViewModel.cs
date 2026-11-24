using System;
using System.Collections.Generic;
using System.Linq;
using RatioVPN.Core;
using RatioVPN.Core.Stats;

namespace RatioVPN.App;

/// <summary>Eine Zeile im Zuverlässigkeits-Ranking.</summary>
public sealed record RankItem(string Tunnel, int Failures, double Fraction)
{
    public string FailuresText => Failures == 1 ? "1 Ausfall" : $"{Failures} Ausfälle";
}

/// <summary>Daten der Statistik-Seite (aus dem StatsStore, alle 60 s bzw. beim Öffnen neu).</summary>
public sealed class StatsViewModel : ObservableObject
{
    private readonly StatsStore? _store;

    public StatsViewModel(StatsStore? store) => _store = store;

    public bool IsAvailable => _store != null;

    private IReadOnlyList<double> _failureValues = Array.Empty<double>(), _trafficValues = Array.Empty<double>();
    private IReadOnlyList<string> _failureLabels = Array.Empty<string>(), _trafficLabels = Array.Empty<string>();
    private IReadOnlyList<RankItem> _ranking = Array.Empty<RankItem>();
    private string _failures30 = "0", _switches30 = "0", _kicks30 = "0", _internet30 = "0", _traffic14 = "0 B", _since = "";

    public IReadOnlyList<double> FailureValues { get => _failureValues; private set => Set(ref _failureValues, value); }
    public IReadOnlyList<string> FailureLabels { get => _failureLabels; private set => Set(ref _failureLabels, value); }
    public IReadOnlyList<double> TrafficValues { get => _trafficValues; private set => Set(ref _trafficValues, value); }
    public IReadOnlyList<string> TrafficLabels { get => _trafficLabels; private set => Set(ref _trafficLabels, value); }
    public IReadOnlyList<RankItem> Ranking { get => _ranking; private set => Set(ref _ranking, value); }
    public string Failures30 { get => _failures30; private set => Set(ref _failures30, value); }
    public string Switches30 { get => _switches30; private set => Set(ref _switches30, value); }
    public string Kicks30 { get => _kicks30; private set => Set(ref _kicks30, value); }
    public string InternetDowns30 { get => _internet30; private set => Set(ref _internet30, value); }
    public string Traffic14 { get => _traffic14; private set => Set(ref _traffic14, value); }
    public string Since { get => _since; private set => Set(ref _since, value); }

    public void Refresh()
    {
        if (_store == null) return;
        var month = TimeSpan.FromDays(30);
        var perDay = _store.FailuresPerDay(30);
        FailureValues = perDay.Select(d => (double)d.Count).ToList();
        FailureLabels = perDay.Select(d => d.Day.ToString("dd.MM.")).ToList();
        Failures30 = perDay.Sum(d => d.Count).ToString();
        Switches30 = _store.Count(AutoPilotEventKind.Switched, month).ToString();
        Kicks30 = _store.Count(AutoPilotEventKind.Kicked, month).ToString();
        InternetDowns30 = _store.Count(AutoPilotEventKind.InternetDown, month).ToString();

        var rank = _store.FailuresPerTunnel(TimeSpan.FromDays(7)).Take(8).ToList();
        int max = Math.Max(1, rank.Count == 0 ? 1 : rank.Max(r => r.Failures));
        Ranking = rank.Select(r => new RankItem(r.Tunnel, r.Failures, (double)r.Failures / max)).ToList();

        var traffic = _store.TrafficPerDay(14);
        TrafficValues = traffic.Select(t => (double)t.Bytes).ToList();
        TrafficLabels = traffic.Select(t => t.Day.ToString("dd.MM.")).ToList();
        Traffic14 = CockpitViewModel.FormatBytes(traffic.Sum(t => t.Bytes));

        var first = _store.Events.Select(e => e.Time).DefaultIfEmpty(DateTime.Now).Min();
        Since = $"Aufgezeichnet seit {first:dd.MM.yyyy}";
    }
}
