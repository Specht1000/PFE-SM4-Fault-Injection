function results = analyze_dfa(varargin)
%ANALYZE_DFA Three reproducible MATLAB analyses of simulated AES/SM4 faults.
% From the project root: addpath('matlab'); analyze_dfa
% Default: export 32 Python trials, validate CSV data, plot and save figures.
% Example: analyze_dfa('Trials',64,'Visible',false)
% Existing data: analyze_dfa('GenerateData',false,'DataFolder','path/to/data')
%
% Outputs: propagation, byte heatmaps and candidate convergence, as PNG/PDF/FIG;
% statistics CSV files, a MAT workspace and a plain-text interpretation report.
% No additional MATLAB toolboxes are required. Python uses the standard library.
%
% Scope matters: AES has 128-bit states; SM4 A/B/L/X35 are 32-bit scalar words.
% SM4 output is 128 bits. These are different fault models, not a security ranking.
% Error bars/bands are mean +/- ONE STANDARD DEVIATION, not confidence intervals.
% log2(candidate count) is a search-space measure, not measured Shannon entropy.

base = fileparts(mfilename('fullpath'));
root = fileparts(base);
p = inputParser;
addParameter(p, 'Trials', 32, @(x) isnumeric(x) && isscalar(x) && x >= 2 && fix(x) == x);
addParameter(p, 'Observations', 8, @(x) isnumeric(x) && isscalar(x) && x >= 1 && x <= 255 && fix(x) == x);
addParameter(p, 'Seed', 2026, @(x) isnumeric(x) && isscalar(x) && x >= 0 && fix(x) == x);
addParameter(p, 'GenerateData', true, @(x) islogical(x) && isscalar(x));
addParameter(p, 'Visible', true, @(x) islogical(x) && isscalar(x));
addParameter(p, 'DataFolder', fullfile(base, 'results', 'data'), @(x) ischar(x) || isstring(x));
addParameter(p, 'OutputFolder', fullfile(base, 'results'), @(x) ischar(x) || isstring(x));
addParameter(p, 'Python', 'python', @(x) ischar(x) || isstring(x));
parse(p, varargin{:});
cfg = p.Results;
dataFolder = char(cfg.DataFolder);
outputFolder = char(cfg.OutputFolder);
if ~isfolder(outputFolder), mkdir(outputFolder); end

if cfg.GenerateData
    args = {char(cfg.Python), fullfile(root, 'src', 'export_matlab.py'), dataFolder};
    for k = 1:numel(args)
        assert(~contains(args{k}, '"') && ~contains(args{k}, newline), 'DFA:Path', 'Paths cannot contain quotes or newlines.');
    end
    command = sprintf('"%s" "%s" --output "%s" --trials %d --observations %d --seed %.0f', args{1}, args{2}, args{3}, cfg.Trials, cfg.Observations, cfg.Seed);
    fprintf('Generating software campaign...\n');
    [status, message] = system(command);
    fprintf('%s\n', message);
    assert(status == 0, 'DFA:Python', 'Python export failed. Check Python or pass the Python executable through the Python option.');
end

metadata = jsondecode(fileread(fullfile(dataFolder, 'manifest.json')));
assert(strcmp(metadata.status, 'complete') && metadata.schema_version == 1, 'DFA:Manifest', 'Dataset is incomplete or has an unsupported schema.');
prop = read_data(fullfile(dataFolder, 'propagation.csv'));
cand = read_data(fullfile(dataFolder, 'candidates.csv'));
recovery = read_data(fullfile(dataFolder, 'recovery.csv'));
assert(height(prop) == 13 * metadata.trials, 'DFA:Rows', 'Unexpected propagation row count.');
assert(height(cand) == 8 * metadata.trials * (metadata.observations_per_group + 1), 'DFA:Rows', 'Unexpected candidate row count.');
assert(height(recovery) == 2 * metadata.trials, 'DFA:Rows', 'Unexpected recovery row count.');

% Independently recompute each XOR and Hamming distance in MATLAB.
deltaNames = compose('delta_%02d', 0:15);
rawDeltas = prop{:, cellstr(deltaNames)};
assert(all(isfinite(rawDeltas(:)) & rawDeltas(:) >= 0 & rawDeltas(:) <= 255 & rawDeltas(:) == fix(rawDeltas(:))), 'DFA:Bytes', 'Delta entries must be bytes.');
deltas = uint8(rawDeltas);
for row = 1:height(prop)
    count = prop.valid_bytes(row);
    assert(ismember(count, [4 16]), 'DFA:Scope', 'Invalid scope width.');
    clean = hex_bytes(prop.correct_hex(row));
    faulty = hex_bytes(prop.faulty_hex(row));
    assert(numel(clean) == count && numel(faulty) == count, 'DFA:Width', 'Hex width does not match scope.');
    assert(isequal(bitxor(clean, faulty), deltas(row, 1:count)), 'DFA:XOR', 'An exported XOR does not match the raw states.');
    assert(all(deltas(row, count+1:end) == 0), 'DFA:Padding', 'Inactive bytes must be zero in CSV storage.');
end
weights = zeros(size(deltas));
for bit = 1:8
    weights = weights + double(bitget(deltas, bit));
end
assert(all(sum(weights, 2) == prop.changed_bits), 'DFA:HD', 'Hamming distances do not match MATLAB recomputation.');
assert(all(sum(deltas ~= 0, 2) == prop.changed_bytes), 'DFA:HD', 'Changed-byte counts are invalid.');
assert(all(cand.candidate_count >= 1) && all(cand.true_key_survives == 1), 'DFA:Candidates', 'Candidate checks failed.');

algorithms = ["AES", "SM4"];
colors = [0.12 0.44 0.78; 0.80 0.23 0.20; 0.15 0.60 0.40; 0.60 0.32 0.72];
visibility = 'off';
if cfg.Visible, visibility = 'on'; end
fig1 = figure('Name', 'Fault propagation', 'Color', 'w', 'Visible', visibility, 'Position', [80 80 1400 850]);
tiledlayout(fig1, 2, 2, 'TileSpacing', 'compact', 'Padding', 'compact');
propStats = table;
for a = 1:2
    selected = prop.algorithm == algorithms(a);
    subset = prop(selected, :);
    stages = unique(subset.stage);
    labels = strings(1, numel(stages));
    bitMean = zeros(size(stages)); bitStd = bitMean;
    byteMean = bitMean; byteStd = bitMean; width = bitMean;
    for k = 1:numel(stages)
        rows = subset.stage == stages(k);
        assert(sum(rows) == metadata.trials, 'DFA:Trials', 'Each stage must have every trial.');
        labels(k) = subset.label(find(rows, 1));
        bitMean(k) = mean(subset.changed_bits(rows)); bitStd(k) = std(subset.changed_bits(rows));
        byteMean(k) = mean(subset.changed_bytes(rows)); byteStd(k) = std(subset.changed_bytes(rows));
        width(k) = subset.valid_bytes(find(rows, 1));
    end
    nexttile(a);
    errorbar(stages, bitMean, bitStd, '-o', 'Color', colors(a, :), 'LineWidth', 1.8, 'MarkerFaceColor', colors(a, :));
    format_stage_axes(stages, labels);
    ylabel('Changed bits (Hamming distance)');
    ylim([0 8 * max(width)]);
    title(algorithms(a) + " / mean +/- 1 SD");
    nexttile(a + 2);
    errorbar(stages, byteMean, byteStd, '-s', 'Color', colors(a, :), 'LineWidth', 1.8);
    format_stage_axes(stages, labels);
    ylabel('Changed bytes');
    ylim([0 max(width)]);
    title(algorithms(a) + " / affected bytes");
    blockStats = table(repmat(algorithms(a), numel(stages), 1), stages, labels', width, bitMean, bitStd, byteMean, byteStd, 'VariableNames', {'Algorithm','Stage','Label','ScopeBytes','MeanChangedBits','StdChangedBits','MeanChangedBytes','StdChangedBytes'});
    propStats = [propStats; blockStats]; %#ok<AGROW>
end
sgtitle('Model-specific fault trajectories / SM4 scalar steps are 32 bits, output is 128 bits');
save_plot(fig1, outputFolder, '01_fault_propagation');

fig2 = figure('Name', 'Affected-byte heatmaps', 'Color', 'w', 'Visible', visibility, 'Position', [100 100 1400 650]);
tiledlayout(fig2, 1, 2, 'TileSpacing', 'compact', 'Padding', 'compact');
heatmaps = struct;
for a = 1:2
    rows = prop.algorithm == algorithms(a);
    subset = prop(rows, :);
    ds = deltas(rows, :);
    stages = unique(subset.stage);
    rates = nan(numel(stages), 16);
    labels = strings(numel(stages), 1);
    for k = 1:numel(stages)
        selected = subset.stage == stages(k);
        count = subset.valid_bytes(find(selected, 1));
        rates(k, 1:count) = mean(ds(selected, 1:count) ~= 0, 1);
        labels(k) = subset.label(find(selected, 1));
    end
    nexttile(a);
    im = imagesc(0:15, 1:numel(stages), rates, [0 1]);
    im.AlphaData = ~isnan(rates);
    set(gca, 'Color', [0.85 0.85 0.85], 'YTick', 1:numel(stages), 'YTickLabel', labels, 'XTick', 0:15, 'TickLabelInterpreter', 'none');
    colormap(gca, [linspace(1, 0.70, 256)' linspace(1, 0.05, 256)' linspace(1, 0.05, 256)']);
    cb = colorbar; cb.Label.String = 'Fraction of trials with a changed byte';
    xlabel('Byte index / MSB-first, AES column-major');
    title(algorithms(a));
    heatmaps.(algorithms(a)) = rates;
end
sgtitle('Fault diffusion / gray = outside the scalar scope, not an unaffected state byte');
save_plot(fig2, outputFolder, '02_affected_byte_heatmaps');

fig3 = figure('Name', 'Candidate convergence', 'Color', 'w', 'Visible', visibility, 'Position', [120 120 1400 700]);
tiledlayout(fig3, 1, 2, 'TileSpacing', 'compact', 'Padding', 'compact');
candidateStats = table;
successStats = table;
for a = 1:2
    nexttile(a); hold on;
    x = 0:metadata.observations_per_group;
    targetWidth = 32;
    targetLabel = "K10 quartet (32 bits)";
    if a == 2, targetWidth = 8; targetLabel = "rk31 byte (8 bits)"; end
    uniqueFlags = false(metadata.trials, 4, numel(x));
    for group = 0:3
        values = zeros(metadata.trials, numel(x));
        for trial = 1:metadata.trials
            selected = cand(cand.algorithm == algorithms(a) & cand.group == group & cand.trial == trial, :);
            selected = sortrows(selected, 'observation');
            assert(isequal(selected.observation', x), 'DFA:Sequence', 'Missing candidate observations.');
            assert(selected.candidate_count(1) == 2^targetWidth && all(diff(selected.candidate_count) <= 0), 'DFA:Monotonic', 'Candidate sequence is invalid.');
            values(trial, :) = log2(selected.candidate_count');
            uniqueFlags(trial, group+1, :) = reshape(selected.candidate_count == 1, 1, 1, []);
        end
        mu = mean(values, 1); sd = std(values, 0, 1);
        patch([x fliplr(x)], [max(0, mu-sd) fliplr(min(targetWidth, mu+sd))], colors(group+1, :), 'FaceAlpha', 0.10, 'EdgeColor', 'none', 'HandleVisibility', 'off');
        plot(x, mu, '-o', 'Color', colors(group+1, :), 'LineWidth', 1.6, 'DisplayName', sprintf('Group %d', group));
        rows = table(repmat(algorithms(a), numel(x), 1), repmat(group, numel(x), 1), x', mu', sd', 'VariableNames', {'Algorithm','Group','Observations','MeanLog2Candidates','StdLog2Candidates'});
        candidateStats = [candidateStats; rows]; %#ok<AGROW>
    end
    success = reshape(mean(all(uniqueFlags, 2), 1), [], 1);
    finalRecovery = recovery(recovery.algorithm == algorithms(a), :);
    assert(abs(success(end) - mean(finalRecovery.all_groups_unique)) < 1e-12, 'DFA:Success', 'Recovery status does not match candidate histories.');
    successStats = [successStats; table(repmat(algorithms(a), numel(x), 1), x', success, 'VariableNames', {'Algorithm','ObservationsPerGroup','FractionAllGroupsUnique'})]; %#ok<AGROW>
    grid on; xlabel('Fault observations per group'); ylabel('log_2(candidate count) / not entropy');
    ylim([0 targetWidth]); xlim([0 max(x)]);
    title(algorithms(a) + " / " + targetLabel);
    legend('Location', 'northeast');
end
sgtitle('Mean +/- 1 SD across trials / a uniquely recovered group remains at one candidate');
save_plot(fig3, outputFolder, '03_candidate_convergence');

results = struct('metadata', metadata, 'propagationStatistics', propStats, 'candidateStatistics', candidateStats, 'successStatistics', successStats, 'heatmaps', heatmaps, 'recovery', recovery);
writetable(propStats, fullfile(outputFolder, 'propagation_statistics.csv'));
writetable(candidateStats, fullfile(outputFolder, 'candidate_statistics.csv'));
writetable(successStats, fullfile(outputFolder, 'recovery_success_by_budget.csv'));
save(fullfile(outputFolder, 'analysis.mat'), 'results', 'prop', 'cand');
write_report(outputFolder, metadata, propStats, successStats);
if ~cfg.Visible, close([fig1 fig2 fig3]); end
fprintf('MATLAB XOR / Hamming-distance and candidate checks: PASS\n');
fprintf('Figures, statistics and report: %s\n', outputFolder);
end


function data = read_data(path)
opts = detectImportOptions(path, 'TextType', 'string');
textNames = intersect({'algorithm','label','scope','correct_hex','faulty_hex','plaintext_hex','target'}, opts.VariableNames);
opts = setvartype(opts, textNames, 'string');
data = readtable(path, opts);
end


function bytes = hex_bytes(value)
text = char(value);
assert(mod(numel(text), 2) == 0, 'DFA:Hex', 'Hex strings must have an even length.');
bytes = uint8(hex2dec(reshape(text, 2, [])'))';
end


function format_stage_axes(stages, labels)
grid on;
xticks(stages); xticklabels(labels); xtickangle(35);
set(gca, 'TickLabelInterpreter', 'none');
xlim([min(stages)-0.3 max(stages)+0.3]);
end


function save_plot(fig, folder, name)
exportgraphics(fig, fullfile(folder, [name '.png']), 'Resolution', 200);
exportgraphics(fig, fullfile(folder, [name '.pdf']), 'ContentType', 'vector');
savefig(fig, fullfile(folder, [name '.fig']));
end


function write_report(folder, meta, prop, success)
fid = fopen(fullfile(folder, 'interpretation.txt'), 'w');
assert(fid >= 0, 'DFA:Report', 'Could not create interpretation report.');
cleanup = onCleanup(@() fclose(fid));
fprintf(fid, 'AES / SM4 FAULT ANALYSIS\nSoftware simulation, seed %d, %d trials, fixed configured keys.\n\n', meta.seed, meta.trials);
fprintf(fid, '1. Propagation: mean +/- one sample standard deviation. These are not confidence intervals.\n');
fprintf(fid, '   Trials vary plaintext, nonzero XOR mask and fault coordinate. The first trial is a reproducible example.\n');
fprintf(fid, '   AES: unknown byte fault before round-9 MixColumns; whole state is 128 bits.\n');
fprintf(fid, '   SM4: known byte fault on last-round S-box input. A/B/L/X35 scopes are 32 bits.\n');
fprintf(fid, '   A 128-bit ciphertext scope follows the 32-bit scopes. Its byte indices are output positions.\n\n');
fprintf(fid, '2. Heatmaps: changed-byte frequency over trials; red=frequent, white=unchanged.\n');
fprintf(fid, '   Gray is outside the selected scalar scope, not a zero-probability state byte.\n\n');
fprintf(fid, '3. Candidates: log2(count), not Shannon entropy or a security-level estimate.\n');
fprintf(fid, '   AES counts 32-bit key quartets; SM4 counts 8-bit subkey-byte candidates.\n');
fprintf(fid, '   Observation budget is per group; querying all four groups generally needs more total faults.\n');
fprintf(fid, '   After uniqueness, one candidate is carried forward without further target queries.\n');
fprintf(fid, '   SM4 recovery target is rk31 only. No reference subkeys are used in this analysis.\n\n');
for algorithm = ["AES", "SM4"]
    stages = prop(prop.Algorithm == algorithm, :);
    last = stages(end, :);
    rates = success(success.Algorithm == algorithm, :);
    fprintf(fid, '%s: final output changed bits %.3f +/- %.3f; all target groups unique at max budget %.1f%%.\n', algorithm, last.MeanChangedBits, last.StdChangedBits, 100*rates.FractionAllGroupsUnique(end));
end
fprintf(fid, '\nThese unequal models cannot establish which cipher is more secure. No physical glitch success, analog consumption or CPA is inferred.\n');
end
