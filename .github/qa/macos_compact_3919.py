"""Install exact compact releases with both shipped helpers on Apple Silicon."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile
PREVIOUS = '3.9.17'
LEGACY = '3.9.14'
VERSION = '3.9.19'
BASE = {'size': 522603658, 'sha256': 'ea5c0ced573dad63585e4feb64b80b539618cc718d2eee660be2b6622b82f6f8'}
LEGACY_BASE = {'size': 522554008, 'sha256': '3cf2e71cf4b50440e3ddf41c72fa03da20e3bd2c5f24b82764562f5293f860c7'}
APP = 'SortAI.app'
EXE = 'Contents/MacOS/SortAI'
HELPER = 'Contents/Frameworks/resources/updater/SortAIUpdater'
APP_ID = 'org.sortai.photo'
PLATFORM = 'macos-arm64'
CDN_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
INPUTS = 'SORTAI_MAC_COMPACT_QA_3919'
FEED = 'SORTAI_MAC_QA_FEED_3919'
LABELS = {'target', 'compact', 'base'}

def require(value, reason):
    if not value:
        raise RuntimeError(reason)

class NoRedirect(HTTPRedirectHandler):

    def redirect_request(self, *args, **kwargs):
        return None

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def describe(path):
    return {'size': path.stat().st_size, 'sha256': digest(path)}

def download(root, name, asset):
    require(set(asset) == {'url', 'size', 'sha256'} and type(asset['size']) is int and (0 < asset['size'] <= 2 * 1024 ** 3) and re.fullmatch('[a-f0-9]{64}', asset['sha256']), 'Invalid QA input size or digest.')
    url = urlsplit(asset['url'])
    require(url.scheme == 'https' and url.hostname in CDN_HOSTS and (url.port in (None, 443)) and (url.username is None) and (url.password is None) and (not url.fragment), 'Invalid anonymous release storage URL.')
    request = Request(asset['url'], headers={'User-Agent': 'SortAI-Mac-Compact-QA', 'Accept-Encoding': 'identity'})
    opener = build_opener(NoRedirect())
    size = 0
    checksum = hashlib.sha256()
    with opener.open(request, timeout=60) as response, (root / f'{name}.zip').open('xb') as output:
        require(response.status == 200 and response.headers.get('Content-Encoding') in (None, 'identity'), 'Unexpected release storage response.')
        for block in iter(lambda: response.read(1024 ** 2), b''):
            size += len(block)
            require(size <= asset['size'], 'QA input exceeded its signed size.')
            checksum.update(block)
            output.write(block)
    require(size == asset['size'] and checksum.hexdigest() == asset['sha256'], 'QA input checksum mismatch.')
    print(f'Verified {name} ZIP ({size} bytes).', flush=True)
    return {'size': size, 'sha256': checksum.hexdigest()}

def fetch(root):
    raw = os.environ.pop(INPUTS, '').encode('utf8')
    require(0 < len(raw) <= 48 * 1024, 'Missing or oversized compact QA input secret.')
    config = json.loads(raw)
    require(set(config) == {'files'} and set(config['files']) == LABELS, 'Expected exactly three QA inputs.')
    require({k: config['files']['base'][k] for k in BASE} == BASE, 'Wrong exact .17 base.')
    root.mkdir(mode=448)
    feed = os.environ.pop(FEED, '').encode('utf8')
    require(0 < len(feed) <= 48 * 1024, 'Missing or oversized candidate feed.')
    (root / 'stable.json').write_bytes(feed)
    with ThreadPoolExecutor(max_workers=3) as pool:
        tasks = {name: pool.submit(download, root, name, asset) for name, asset in config['files'].items()}
        metadata = {name: task.result() for name, task in tasks.items()}
    (root / 'verified.json').write_text(json.dumps(metadata), encoding='utf8')

def command(*arguments, cwd, env, timeout=180):
    result = subprocess.run([str(arg) for arg in arguments], cwd=cwd, env=env, capture_output=True, timeout=timeout)
    require(result.returncode == 0, f'{Path(arguments[0]).name} returned exit status {result.returncode}.')
    return result.stdout

def verify_app(app, expected, *, cwd, env, signed=True):
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info['CFBundleIdentifier'] == APP_ID and info['CFBundleShortVersionString'] == info['CFBundleVersion'] == expected, 'Unexpected app identity or bundle version.')
    require(command('/usr/bin/lipo', '-archs', app / EXE, cwd=cwd, env=env).split() == [b'arm64'], 'Application executable is not native arm64.')
    if signed:
        command('/usr/bin/codesign', '--verify', '--deep', '--strict', app, cwd=cwd, env=env)
    require(command(app / EXE, '--version', cwd=cwd, env=env).decode().strip() == expected, 'Application executable reports an unexpected version.')

def tree(root, include_dirs=False):
    entries = {}
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            entries[name] = ('link', os.readlink(path))
        elif stat.S_ISREG(mode):
            entries[name] = ('file', stat.S_IMODE(mode), digest(path))
        elif stat.S_ISDIR(mode):
            if include_dirs:
                entries[name] = ('directory', stat.S_IMODE(mode))
        else:
            raise RuntimeError('Unexpected type in the native app or data fixture.')
    return entries

def archived_tree(path):
    entries = {}
    with ZipFile(path) as archive:
        for entry in archive.infolist():
            parts = PurePosixPath(entry.filename).parts
            require(parts and parts[0] == APP and ('..' not in parts), 'Unexpected application ZIP path.')
            if len(parts) == 1:
                require(entry.is_dir(), 'Unexpected application ZIP root.')
                continue
            name = '/'.join(parts[1:])
            mode = entry.external_attr >> 16
            require(name not in entries, 'Duplicate application ZIP path.')
            if entry.is_dir():
                entries[name] = ('directory', stat.S_IMODE(mode))
                continue
            with archive.open(entry) as stream:
                if stat.S_ISLNK(mode):
                    entries[name] = ('link', stream.read(4096).decode('utf-8'))
                else:
                    require(stat.S_ISREG(mode), 'Unexpected application ZIP file type.')
                    entries[name] = ('file', stat.S_IMODE(mode), hashlib.file_digest(stream, 'sha256').hexdigest())
    return entries

def feed_descriptor(path, metadata):
    raw = path.read_bytes()
    envelope = json.loads(raw)
    payload = envelope['payload']
    require(envelope['schema'] == 1 and payload['app_id'] == APP_ID and (payload['channel'] == 'stable'), 'Unexpected signed candidate feed.')
    entry, = (v for v in payload['releases'] if v['version'] == VERSION)
    full = entry['artifacts'][PLATFORM]
    compact = full['compact'][PREVIOUS]
    require(full['archive_root'] == APP and {k: full[k] for k in ('size', 'sha256')} == metadata['target'], 'Wrong full target in QA feed.')
    require(compact['archive_root'] == 'SortAI-Compact' and {k: compact[k] for k in ('size', 'sha256')} == metadata['compact'], 'Wrong exact compact in QA feed.')
    return (envelope, payload['channel'], hashlib.sha256(raw).hexdigest())

def reused_file(bridge_zip, base_tree, target_tree):
    with ZipFile(bridge_zip) as bridge:
        prefix = f'{APP}/Contents/Resources/'
        manifest = json.loads(bridge.read(prefix + 'compact.json'))['payload']
        require(manifest['version'] == VERSION and {LEGACY, PREVIOUS} <= set(manifest['bases']), 'Bridge has the wrong base or target.')
        with ZipFile(io.BytesIO(bridge.read(prefix + 'compact.zip'))) as overlay:
            changed = set(overlay.namelist())
    candidates = [name for name, record in base_tree.items() if name.startswith('Contents/Resources/models/') and record[0] == 'file' and (record == target_tree.get(name)) and (name in manifest['target']) and (name not in changed)]
    require(candidates, 'No unchanged model was found for the reused-file fault fixture.')
    return sorted(candidates, key=lambda name: ('face_detection' not in name, name))[0]

def fixture_data(data):
    for name, contents in {'settings.json': b'{"synthetic":true}', 'catalog.sqlite3': b'qa catalog sentinel', 'face-db/synthetic.pkl': b'qa face database sentinel', 'downloads/fixture.jpg': b'qa original sentinel'}.items():
        path = data / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    return tree(data)

def verify_data(data, original):
    current = tree(data)
    require({name: current.get(name) for name in original} == original, 'Synthetic user data changed.')
    require(all((name in original or name in {'application.lock', 'update-result.json'} or name.startswith('updates/') for name in current)), 'Updater created unexpected files outside its reserved paths.')

def verify_cocoa_launch(app, case, env):
    data = case / 'cocoa-data'
    data.mkdir()
    receipt = data / 'update-result.json'
    receipt.write_text(json.dumps({'ok': True, 'version': VERSION}), encoding='utf-8')
    env = {**env, 'QT_QPA_PLATFORM': 'cocoa', 'SORT_AI_DATA_DIR': str(data)}
    process = subprocess.Popen([str(app / EXE), '--data-dir', str(data), '--no-auto-scan'], cwd=case, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and process.poll() is None and receipt.exists():
            time.sleep(0.2)
        require(process.poll() is None and (not receipt.exists()), 'The installed app did not process its Cocoa startup timer.')
        time.sleep(3)
        require(process.poll() is None, 'The installed app exited during its Cocoa startup.')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)

def run_case(root, label, package, metadata, feed, target_tree, reused=None):
    kind = 'compact' if label == 'compact' else 'legacy'
    fault = label if label in ('altered', 'missing') else None
    base_label, previous = ('base', PREVIOUS) if kind == 'compact' else ('legacy-base', LEGACY)
    envelope, channel, feed_sha = feed
    with TemporaryDirectory(prefix=f'{label}-', dir=root) as temporary:
        case = Path(temporary)
        install, data, home, tmp = (case / name for name in ('install', 'data', 'home', 'tmp'))
        for path in (install, data, home, tmp):
            path.mkdir()
        env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'DEVELOPER_DIR') if key in os.environ}
        env.update(QT_QPA_PLATFORM='offscreen', SORT_AI_DATA_DIR=str(data), HOME=str(home), TMPDIR=str(tmp), OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1')
        command('/usr/bin/ditto', '-x', '-k', root / f'{base_label}.zip', install, cwd=case, env=env)
        app = install / APP
        verify_app(app, previous, cwd=case, env=env)
        if fault:
            path = app / reused
            if fault == 'missing':
                path.unlink()
            else:
                with path.open('r+b') as output:
                    first = output.read(1)
                    require(first, 'The altered fixture needs a nonempty reused file.')
                    output.seek(0)
                    output.write(bytes([first[0] ^ 1]))
            verify_app(app, previous, cwd=case, env=env, signed=False)
        old_tree = tree(app, include_dirs=True)
        original = fixture_data(data)
        job_dir = data / 'updates/jobs/0123456789abcdef01234567'
        cache = data / 'updates/packages'
        job_dir.mkdir(parents=True)
        cache.mkdir()
        cached = cache / f"{metadata['sha256']}.zip"
        os.link(package, cached)
        helper = job_dir / 'SortAIUpdater'
        shutil.copy2(app / HELPER, helper)
        helper.chmod(448)
        require(command('/usr/bin/lipo', '-archs', helper, cwd=case, env=env).split() == [b'arm64'], 'The shipped update helper is not native arm64.')
        command('/usr/bin/codesign', '--verify', '--strict', helper, cwd=case, env=env)
        job = job_dir / 'job.json'
        job.write_text(json.dumps({'platform': PLATFORM, 'target': str(app), 'package': str(cached), 'data_dir': str(data), 'parent_pid': 0, 'channel': channel, 'envelope': envelope, 'compact': kind == 'compact', 'target_version': VERSION}), encoding='utf-8')
        result = subprocess.run([str(helper), '--job', str(job), '--no-relaunch'], cwd=job_dir, env=env, capture_output=True, timeout=360)
        receipt_file = data / 'update-result.json'
        receipt = json.loads(receipt_file.read_bytes()) if receipt_file.is_file() else {}
        backups = install / '.SortAI-update-backups'
        backup, = (path for path in backups.iterdir() if path.is_dir() and (not path.is_symlink()))
        journal = json.loads((backup / 'journal.json').read_bytes())
        require(journal['target'] == str(app) and journal['moved'] == journal['installed'] == [APP], 'The actual updater did not enter the expected transaction.')
        verify_data(data, original)
        if fault:
            require(result.returncode != 0 and receipt.get('ok') is False and (journal['status'] == 'rolled_back'), 'The incompatible reused file did not trigger rollback.')
            require(tree(app, include_dirs=True) == old_tree, 'Rollback did not restore the exact prior fixture app.')
            rejected = backup / '.rejected' / APP / EXE
            with ZipFile(package) as archive, archive.open(f'{APP}/{EXE}') as source:
                require(digest(rejected) == hashlib.file_digest(source, 'sha256').hexdigest(), 'The rejected installed payload was not the legacy bridge.')
            verify_app(app, previous, cwd=case, env=env, signed=False)
            return {'ok': True, 'restored_exact': True, 'archive_data_preserved': True, 'rollback_version': previous}
        require(result.returncode == 0 and receipt.get('ok') is True and (receipt.get('version') == VERSION) and (Path(receipt['backup']) == backup) and (journal['status'] == 'complete'), f'The {kind} shipped updater did not finish the exact upgrade.')
        verify_app(app, VERSION, cwd=case, env=env)
        smoke = case / 'reconstructed-selftest.json'
        command(app / EXE, '--self-test', '--data-dir', case / 'reconstructed-selftest-data', '--report', smoke, cwd=case, env=env, timeout=240)
        frozen = json.loads(smoke.read_bytes())
        require(frozen.get('ok') is True and frozen.get('frozen') is True and frozen.get('checks'), 'Reconstructed .17 app failed its frozen self-test.')
        require(tree(app, include_dirs=True) == target_tree, 'Installed app differs from the complete attested 3.9.16 ZIP.')
        verify_app(backup / APP, previous, cwd=case, env=env)
        require(tree(backup / APP, include_dirs=True) == old_tree, 'The retained rollback copy changed.')
        if kind == 'compact':
            verify_cocoa_launch(app, case, env)
        return {'ok': True, 'archive_sha256': metadata['sha256'], 'feed_sha256': feed_sha, 'archive_data_preserved': True, 'rollback_version': previous}

def test(root):
    require(not {INPUTS, FEED} & os.environ.keys(), 'QA secrets leaked into installer step.')
    metadata = json.loads((root / 'verified.json').read_bytes())
    require(set(metadata) == LABELS and metadata['base'] == BASE, 'Verified base changed.')
    for label in metadata:
        require(describe(root / f'{label}.zip') == metadata[label], 'QA ZIP changed after download.')
    target_tree = archived_tree(root / 'target.zip')
    feed = feed_descriptor(root / 'stable.json', metadata)
    result = {'ok': True, 'from': PREVIOUS, 'to': VERSION}
    print('Testing the genuine .17 shipped updater with only the signed .19 compact overlay.', flush=True)
    result['compact'] = run_case(root, 'compact', root / 'compact.zip', metadata['compact'], feed, target_tree)
    result['compact']['target_sha256'] = metadata['target']['sha256']
    result['native_app_cocoa'] = True
    result['native_frozen_selftest'] = True
    print(json.dumps(result, separators=(',', ':')), flush=True)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('fetch', 'test'))
    args = parser.parse_args()
    try:
        require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'Run this QA on Apple Silicon.')
        root = Path(os.environ['RUNNER_TEMP']).resolve(strict=True) / 'sortai-compact-3919-qa'
        (fetch if args.phase == 'fetch' else test)(root)
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit(f'Native compact QA failed ({type(error).__name__}).') from None