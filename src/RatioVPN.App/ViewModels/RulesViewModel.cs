using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using RatioVPN.Core;
using RatioVPN.Core.Settings;

namespace RatioVPN.App;

/// <summary>Eine Automatik-Regel im Editor. Jede Änderung wird sofort gespeichert.</summary>
public sealed class RuleItem : ObservableObject
{
    private readonly RulesViewModel _owner;
    public AutoRuleEntry Entry { get; }

    public RuleItem(RulesViewModel owner, AutoRuleEntry entry)
    {
        _owner = owner;
        Entry = entry;
        _ruleProblem = owner.ProblemFor(entry) ?? ""; // z. B. ungültiges Muster aus der Übernahme – sofort zeigen
    }

    public string Name
    {
        get => Entry.Name;
        set { var v = (value ?? "").Trim(); if (v.Length == 0 || v == Entry.Name) return; Entry.Name = v; Changed(); }
    }

    public bool Enabled
    {
        get => Entry.Enabled;
        set { if (Entry.Enabled == value) return; Entry.Enabled = value; Changed(); }
    }

    public string ExeNames
    {
        get => Entry.ExeNames;
        set { var v = (value ?? "").Trim(); if (v == Entry.ExeNames) return; Entry.ExeNames = v; Changed(); Raise(nameof(KindText)); }
    }

    /// <summary>Fehler der letzten Eingabe (wurde nicht übernommen).</summary>
    private string _inputError = "";
    /// <summary>Problem des gespeicherten Musters (ungültig oder zu aufwendig) laut Automatik.</summary>
    private string _ruleProblem;
    public string PatternError => _inputError.Length > 0 ? _inputError : _ruleProblem;

    private void SetInputError(string text)
    {
        if (text == _inputError) return;
        _inputError = text;
        Raise(nameof(PatternError));
    }

    internal void SetRuleProblem(string? problem)
    {
        problem ??= "";
        if (problem == _ruleProblem) return;
        _ruleProblem = problem;
        Raise(nameof(PatternError));
    }

    public string TitlePattern
    {
        get => Entry.TitlePattern;
        set
        {
            var v = value ?? "";
            if (v == Entry.TitlePattern) { SetInputError(""); return; }
            if (AutoRuleEntry.CheckPattern(v) != null)
            {
                SetInputError("Ungültiges Muster – wird nicht übernommen.");
                Raise();
                return;
            }
            SetInputError("");
            Entry.TitlePattern = v;
            SetRuleProblem(_owner.ProblemFor(Entry));
            Changed();
            Raise(nameof(KindText));
        }
    }

    public AutoRuleMode Mode
    {
        get => Entry.Mode;
        set { if (Entry.Mode == value) return; Entry.Mode = value; Changed(); }
    }

    public bool WatchTraffic
    {
        get => Entry.WatchTraffic;
        set { if (Entry.WatchTraffic == value) return; Entry.WatchTraffic = value; Changed(); }
    }

    /// <summary>Wie die Regel erkennt: über Fenstertitel oder über den Prozess (auch ohne Fenster).</summary>
    public string KindText => string.IsNullOrWhiteSpace(Entry.TitlePattern)
        ? (Entry.ExeList().Count == 0 ? "passt auf nichts" : "Prozess-Erkennung")
        : "Fenster-Erkennung";

    private string _matchText = "";
    public string MatchText { get => _matchText; set => Set(ref _matchText, value); }
    private bool _hasMatches;
    public bool HasMatches { get => _hasMatches; set => Set(ref _hasMatches, value); }

    private void Changed() => _owner.Save();
}

/// <summary>Editor für die Automatik-Regeln.</summary>
public sealed class RulesViewModel : ObservableObject
{
    private readonly MainViewModel _vm;

    public ObservableCollection<RuleItem> Rules { get; } = new();
    /// <summary>Programmdateien gerade offener Fenster (Vorlage „aus laufendem Programm“).</summary>
    public ObservableCollection<string> RunningExes { get; } = new();

    public ICommand AddRuleCommand { get; }
    public ICommand RemoveRuleCommand { get; }
    public ICommand MoveUpCommand { get; }
    public ICommand MoveDownCommand { get; }

    public RulesViewModel(MainViewModel vm)
    {
        _vm = vm;
        AddRuleCommand = new RelayCommand(_ => Add(new AutoRuleEntry { Name = "Neue Regel", Mode = AutoRuleMode.Separate }));
        RemoveRuleCommand = new RelayCommand(p => Remove(p as RuleItem));
        MoveUpCommand = new RelayCommand(p => Move(p as RuleItem, -1));
        MoveDownCommand = new RelayCommand(p => Move(p as RuleItem, +1));
        Rebuild();
    }

    private List<AutoRuleEntry> Entries => _vm.Controller.Settings.AutoRules ??= new List<AutoRuleEntry>();

    public void Rebuild()
    {
        Rules.Clear();
        foreach (var e in Entries) Rules.Add(new RuleItem(this, e));
    }

    internal void Save() => _vm.Controller.SaveSettings();

    internal string? ProblemFor(AutoRuleEntry e) => _vm.AutoPilot.PatternProblem(e);

    /// <summary>Gewählte Vorlage aus „laufendem Programm“: legt eine Prozessregel für diese Programmdatei an.</summary>
    public string? SelectedRunningExe
    {
        get => null;
        set
        {
            if (string.IsNullOrEmpty(value)) return;
            // Gemeinsam: viele Programme (Browser, Discord) laufen als mehrere Prozesse – getrennt würde jeder
            // eine eigene Verbindung verbrauchen und der Rest würde blockiert.
            Add(new AutoRuleEntry { Name = Path.GetFileNameWithoutExtension(value), ExeNames = value, Mode = AutoRuleMode.Shared });
            Raise();
        }
    }

    private void Add(AutoRuleEntry e)
    {
        Entries.Add(e);
        Rules.Add(new RuleItem(this, e));
        Save();
    }

    private void Remove(RuleItem? r)
    {
        if (r == null) return;
        var answer = MessageBox.Show($"Regel „{r.Name}“ löschen?\nProgramme, die nur durch diese Regel eine Verbindung hatten, behalten sie bis zum Neustart.",
            "Ratio VPN", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;
        Entries.Remove(r.Entry);
        Rules.Remove(r);
        Save();
    }

    private void Move(RuleItem? r, int delta)
    {
        if (r == null) return;
        int i = Rules.IndexOf(r), j = i + delta;
        if (i < 0 || j < 0 || j >= Rules.Count) return;
        Rules.Move(i, j);
        Entries.RemoveAt(i);
        Entries.Insert(j, r.Entry);
        Save();
    }

    /// <summary>Live-Treffer je Regel und Liste laufender Programme (nach jedem Scan).</summary>
    public void Refresh(SystemSnapshot? snapshot)
    {
        if (snapshot == null) return;
        var ap = _vm.AutoPilot;
        var counts = new Dictionary<string, (int Windows, int Processes)>();
        var seen = new HashSet<int>();
        foreach (var w in snapshot.Windows)
        {
            if (!seen.Add(w.Pid)) continue;
            if (ap.RuleFor(w.Pid, w.ExePath, w.Title) is { } r)
                counts[r.Id] = (counts.GetValueOrDefault(r.Id).Windows + 1, counts.GetValueOrDefault(r.Id).Processes);
        }
        foreach (var p in snapshot.Processes)
        {
            if (!seen.Add(p.Pid)) continue;
            if (ap.RuleFor(p.Pid, p.ExePath, null) is { } r)
                counts[r.Id] = (counts.GetValueOrDefault(r.Id).Windows, counts.GetValueOrDefault(r.Id).Processes + 1);
        }
        foreach (var item in Rules)
        {
            item.SetRuleProblem(ap.PatternProblem(item.Entry)); // z. B. „zu aufwendig“ erst nach dem ersten Scan bekannt
            var (w, p) = counts.GetValueOrDefault(item.Entry.Id);
            int n = w + p;
            item.HasMatches = n > 0;
            item.MatchText = !item.Enabled ? "ausgeschaltet"
                : n == 0 ? "passt gerade auf nichts"
                : w > 0 && p == 0 ? $"passt gerade auf {w} offene{(w == 1 ? "s Fenster" : " Fenster")}"
                : $"passt gerade auf {n} laufende{(n == 1 ? "n Prozess" : " Prozesse")}";
        }

        var exes = snapshot.Windows.Select(w => Path.GetFileName(w.ExePath)).Where(e => !string.IsNullOrEmpty(e))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(e => e, StringComparer.OrdinalIgnoreCase).ToList();
        if (!exes.SequenceEqual(RunningExes))
        {
            RunningExes.Clear();
            foreach (var e in exes) RunningExes.Add(e);
        }
    }
}
