#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const scanHistory = process.argv.includes('--history');
const findings = [];

const skippedDirectories = new Set([
	'.git',
	'.expo',
	'Pods',
	'build',
	'dist',
	'node_modules',
]);

// Split high-confidence indicators so this defensive scanner does not itself
// contain a copy-pastable malware signature.
const indicators = {
	legacyShuffle: ['rmcej', '%otb%'].join(''),
	legacyDecoder: ['_', '$', '_1e42'].join(''),
	rotatedShuffle: ['Cot', '%3t=', 'shtP'].join(''),
	propagationScript: ['temp', '_auto', '_push.bat'].join(''),
	interactiveScript: ['temp', '_interactive', '_push.bat'].join(''),
	branchInventory: ['branch', '_structure.json'].join(''),
	orchestrator: ['config', '.bat'].join(''),
	remoteBootstrap: ['default-configuration', '.vercel.app/settings'].join(''),
	ethereumRpc: ['eth_', 'getBlockByNumber'].join(''),
	tronApi: ['tron', 'grid'].join(''),
	aptosApi: ['aptos', 'labs'].join(''),
	hiddenChild: ['windows', 'Hide'].join(''),
};

const maliciousDependencies = [
	['tailwindcss', '-style-animate'].join(''),
	['tailwind', '-mainanimation'].join(''),
	['tailwind', '-autoanimation'].join(''),
	['tailwind', '-animationbased'].join(''),
	['tailwindcss', '-typography-style'].join(''),
	['tailwindcss', '-style-modify'].join(''),
	['tailwindcss', '-animate-style'].join(''),
];

const propagationNames = new Set([
	indicators.propagationScript,
	indicators.interactiveScript,
	indicators.branchInventory,
	indicators.orchestrator,
]);

function report(kind, file, detail) {
	findings.push({ kind, file, detail });
}

function isLikelyText(buffer) {
	const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
	return !sample.includes(0);
}

function hasValidFontHeader(buffer, extension) {
	if (buffer.length < 4) return false;
	const ascii = buffer.subarray(0, 4).toString('ascii');
	if (extension === '.woff2') return ascii === 'wOF2';
	if (extension === '.woff') return ascii === 'wOFF';
	if (extension === '.otf') return ascii === 'OTTO';
	if (extension === '.ttf') {
		return (
			ascii === 'OTTO' ||
			ascii === 'ttcf' ||
			(buffer[0] === 0 && buffer[1] === 1 && buffer[2] === 0 && buffer[3] === 0)
		);
	}
	return true;
}

function scanTextFile(relativePath, text) {
	const basename = relativePath.split('/').at(-1);
	if (propagationNames.has(basename)) {
		report('propagation-artifact', relativePath, 'known propagation filename');
	}

	const strongSignatures = [
		indicators.legacyShuffle,
		indicators.legacyDecoder,
		indicators.rotatedShuffle,
		indicators.remoteBootstrap,
	];
	for (const signature of strongSignatures) {
		if (text.includes(signature)) {
			report('loader-signature', relativePath, 'high-confidence PolinRider marker');
			break;
		}
	}

	const ethereumLoader =
		text.includes(indicators.ethereumRpc) &&
		text.includes('blockscout') &&
		text.includes('child_process');
	const blockchainLoader =
		text.includes(indicators.tronApi) &&
		text.includes(indicators.aptosApi) &&
		text.includes(indicators.hiddenChild);
	if (ethereumLoader || blockchainLoader) {
		report('loader-behavior', relativePath, 'blockchain-backed Node loader behavior');
	}

	const isEditorTask = /(^|\/)\.(vscode|cursor)\/tasks\.json$/u.test(relativePath);
	if (
		isEditorTask &&
		text.includes('folderOpen') &&
		(/node[^\n]{0,240}\.(woff2|woff|ttf|otf)/iu.test(text) ||
			/(curl|wget)[^\n]{0,240}(bash|sh)/iu.test(text))
	) {
		report('editor-autorun', relativePath, 'folder-open task executes a payload');
	}

	if (relativePath.endsWith('.gitignore')) {
		for (const name of propagationNames) {
			if (text.split(/\r?\n/u).some((line) => line.trim() === name)) {
				report('hidden-propagation-artifact', relativePath, `ignored IOC: ${name}`);
			}
		}
	}

	if (/((^|\/)package\.json|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml))$/u.test(relativePath)) {
		for (const dependency of maliciousDependencies) {
			if (text.includes(dependency)) {
				report('malicious-dependency', relativePath, dependency);
			}
		}
	}

	if (/\.config\.(c?js|mjs|ts)$/u.test(relativePath)) {
		const suspiciousLongLine = text
			.split(/\r?\n/u)
			.some(
				(line) =>
					line.length > 1200 &&
					/(eval\s*\(|child_process|windows\s*Hide|global\s*[.[])/u.test(line),
			);
		if (suspiciousLongLine) {
			report('off-screen-config-payload', relativePath, 'very long executable config line');
		}
	}
}

function walk(directory) {
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		if (entry.isDirectory() && skippedDirectories.has(entry.name)) continue;
		const absolutePath = join(directory, entry.name);
		if (entry.isDirectory()) {
			walk(absolutePath);
			continue;
		}
		if (!entry.isFile()) continue;

		const relativePath = relative(repoRoot, absolutePath).split('\\').join('/');
		const metadata = statSync(absolutePath);
		if (metadata.size > 20 * 1024 * 1024) continue;
		const buffer = readFileSync(absolutePath);
		const extension = extname(entry.name).toLowerCase();

		if (['.woff2', '.woff', '.ttf', '.otf'].includes(extension)) {
			if (!hasValidFontHeader(buffer, extension) && isLikelyText(buffer)) {
				report('fake-font', relativePath, 'font extension with a non-font text header');
			}
		}

		if (isLikelyText(buffer)) {
			scanTextFile(relativePath, buffer.toString('utf8'));
		}
	}
}

function scanGitHistory() {
	const revisions = spawnSync('git', ['rev-list', '--all'], {
		cwd: repoRoot,
		encoding: 'utf8',
	});
	if (revisions.status !== 0) {
		report('history-scan-error', '.git', revisions.stderr.trim() || 'git rev-list failed');
		return;
	}

	const historyIndicators = [
		indicators.legacyShuffle,
		indicators.legacyDecoder,
		indicators.rotatedShuffle,
		indicators.propagationScript,
		indicators.interactiveScript,
		indicators.branchInventory,
		indicators.remoteBootstrap,
		...maliciousDependencies,
	];
	const historyPathspecs = [
		'.',
		...[...skippedDirectories]
			.filter((directory) => directory !== '.git')
			.flatMap((directory) => [
				`:(exclude,glob)${directory}/**`,
				`:(exclude,glob)**/${directory}/**`,
			]),
	];
	const fixedStringPatterns = historyIndicators.flatMap((indicator) => [
		'-e',
		indicator,
	]);
	const commits = [...new Set(revisions.stdout.trim().split(/\s+/u).filter(Boolean))];
	let infectedCommitCount = 0;

	for (const commit of commits) {
		const grep = spawnSync(
			'git',
			[
				'grep', '-I', '-l', '-F', ...fixedStringPatterns, commit, '--',
				...historyPathspecs,
			],
			{
				cwd: repoRoot,
				encoding: 'utf8',
				maxBuffer: 8 * 1024 * 1024,
			},
		);
		if (grep.status === 0 && grep.stdout.trim()) {
			infectedCommitCount += 1;
			if (infectedCommitCount <= 20) {
				const paths = grep.stdout
					.trim()
					.split(/\r?\n/u)
					.map((line) => line.replace(`${commit}:`, ''))
					.join(', ');
				report('infected-history', commit.slice(0, 12), paths);
			}
		}
	}

	if (infectedCommitCount > 20) {
		report(
			'infected-history',
			'.git',
			`${infectedCommitCount - 20} additional infected commits omitted`,
		);
	}
}

walk(repoRoot);
if (scanHistory) scanGitHistory();

if (findings.length > 0) {
	console.error(`PolinRider security scan: FAILED (${findings.length} finding(s))`);
	for (const finding of findings) {
		console.error(`- [${finding.kind}] ${finding.file}: ${finding.detail}`);
	}
	process.exit(1);
}

console.log(
	`PolinRider security scan: PASS (worktree${scanHistory ? ' + reachable Git history' : ''})`,
);
