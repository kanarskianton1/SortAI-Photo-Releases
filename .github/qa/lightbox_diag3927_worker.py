from contextlib import contextmanager
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unicodedata
import urllib.parse
import urllib.request
import zipfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
REPOSITORY = 'kanarskianton1/SortAI-Photo-Releases'
REF = 'refs/heads/build-check/lightbox-diag3927'
VERSION = '3.9.27'
SECRET_NAME = 'SORTAI_LIGHTBOX_DIAG3927'
CDN_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
MAX_ENCRYPTED = 16777216
MAX_SOURCE = 128 * 1024 ** 2
CHUNK = 1024 ** 2
AAD = b'SORTAI_NATIVE_JOB_V1\n'
DIAGNOSTIC_PUBLIC = bytes.fromhex('79f655a57862f75de84220b33aa91e25acebfddca1f7312ac8c47836cbcd9a10')
DIAGNOSTIC_INFO = b'sortai-relay-diagnostic-v1'
DIAGNOSTIC_LIMIT = 2 * 1024 ** 2
DIAGNOSTIC_NAME = 'native-diagnostic.enc'

class RelayFailure(RuntimeError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, *args, **kwargs):
        return None

def require(condition):
    if not condition:
        raise ValueError('Relay validation failed.')

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def parse_object(raw, fields):
    data = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(data, dict) and data.keys() == fields)
    return data

def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None

def run_context():
    require(sys.platform == 'darwin' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and (os.environ.get('GITHUB_REF') == REF) and (os.environ.get('GITHUB_EVENT_NAME') == 'push'))
    run_id = os.environ.get('GITHUB_RUN_ID')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT')
    commit = os.environ.get('GITHUB_SHA')
    require(matches(run_id, '[1-9][0-9]{0,19}') and matches(attempt, '[1-9][0-9]{0,9}') and matches(commit, '[a-f0-9]{40}'))
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(temp.is_dir())
    return (temp, int(run_id), int(attempt), commit)

def decrypt(encrypted, decrypted, key):
    size = encrypted.stat().st_size
    require(28 < size <= MAX_ENCRYPTED)
    with encrypted.open('rb') as source:
        nonce = source.read(12)
        source.seek(-16, os.SEEK_END)
        tag = source.read(16)
        decipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decipher.authenticate_additional_data(AAD)
        source.seek(12)
        remaining = size - 28
        with decrypted.open('xb') as output:
            while remaining:
                block = source.read(min(remaining, CHUNK))
                require(bool(block))
                remaining -= len(block)
                output.write(decipher.update(block))
            output.write(decipher.finalize())

def member_type(entry):
    return stat.S_IFMT(entry.external_attr >> 16)

def extract_member(archive, entry, destination):
    require(not entry.is_dir() and member_type(entry) in (0, stat.S_IFREG) and (not entry.flag_bits & 1))
    with archive.open(entry) as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output, CHUNK)
    require(destination.stat().st_size == entry.file_size)

def extract_source(archive_path, destination, commit):
    destination.mkdir(mode=448)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 5000 and archive.comment == commit.encode('ascii') and (sum((entry.file_size for entry in entries)) <= MAX_SOURCE))
        seen = set()
        for entry in entries:
            name = entry.filename[:-1] if entry.is_dir() else entry.filename
            parts = name.split('/')
            require(all((part not in ('', '.', '..') and (not any((char in part for char in '\\:\x00'))) for part in parts)) and parts[0].casefold() not in ('.git', '.local-server', '.release-private', 'data', 'models'))
            identity = unicodedata.normalize('NFC', name).casefold()
            require(identity not in seen)
            seen.add(identity)
            target = destination.joinpath(*parts)
            if entry.is_dir():
                require(member_type(entry) in (0, stat.S_IFDIR) and entry.file_size == 0)
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                extract_member(archive, entry, target)
                if entry.external_attr >> 16 & 73:
                    target.chmod(448)
    require(all(((destination / name).is_file() for name in ('main.py', 'build_models.py', 'build_macos.py'))))

def run_private(arguments, cwd, environment, log):
    with log.open('ab') as output:
        subprocess.run(arguments, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, check=True)

def seal_diagnostic(log, destination):
    require(log.is_file() and (not log.is_symlink()))
    with log.open('rb') as source:
        size = source.seek(0, os.SEEK_END)
        source.seek(max(0, size - DIAGNOSTIC_LIMIT))
        tail = source.read(DIAGNOSTIC_LIMIT)
    require(bool(tail))
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(DIAGNOSTIC_PUBLIC))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=DIAGNOSTIC_INFO).derive(shared)
    nonce = os.urandom(12)
    data = ephemeral.public_key().public_bytes_raw() + nonce + AESGCM(key).encrypt(nonce, tail, None)
    with destination.open('xb') as output:
        output.write(data)

def file_digest(path):
    require(path.is_file() and (not path.is_symlink()))
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()
'Resolve the exact public encrypted-input mirror with the job token at runtime.'
import urllib.error
MIRROR_FILE = 'lightbox_diag3927_mirror.json'
MIRROR_VERIFIED = {}
LAST_FAILURE = {}

def phase(label, operation, *args):
    print(label, flush=True)
    try:
        return operation(*args)
    except Exception as error:
        if not isinstance(error, RelayFailure) or not LAST_FAILURE:
            status = getattr(error, 'code', None)
            LAST_FAILURE.clear()
            LAST_FAILURE.update(phase=label, error_type=type(error).__name__, http_status=status if type(status) is int else None)
        raise RelayFailure(label) from None

def mirror_descriptor():
    path = Path(__file__).with_name(MIRROR_FILE)
    require(path.is_file() and (not path.is_symlink()) and (0 < path.stat().st_size <= 8192))
    descriptor = parse_object(path.read_bytes(), {'schema', 'diagnostic_id', 'repository', 'release_id', 'asset_id', 'name', 'tag', 'target_commitish', 'bytes', 'sha256'})
    require(descriptor['schema'] == 1 and descriptor['diagnostic_id'] == 'lightbox-diag3927' and (descriptor['repository'] == REPOSITORY) and (descriptor['name'] == 'lightbox-input-aesgcm.bin') and (type(descriptor['release_id']) is int) and (descriptor['release_id'] > 0) and (type(descriptor['asset_id']) is int) and (descriptor['asset_id'] > 0) and (type(descriptor['bytes']) is int) and (28 < descriptor['bytes'] < 16 * 1024 ** 2) and matches(descriptor['sha256'], '[a-f0-9]{64}') and matches(descriptor['target_commitish'], '[a-f0-9]{40}') and matches(descriptor['tag'], 'lightbox-diag3927-cipher-mirror-[a-f0-9]{12}'))
    return descriptor

def read_mirror_release(token, descriptor):
    request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/releases/{descriptor['release_id']}", headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'SortAI-Lightbox-Diagnostic'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        raw = response.read(128 * 1024 + 1)
        require(response.status == 200 and len(raw) <= 128 * 1024)
    release = json.loads(raw, object_pairs_hook=unique_object)
    require(release.get('id') == descriptor['release_id'] and release.get('draft') is True and (release.get('prerelease') is True) and (release.get('published_at') is None) and (release.get('tag_name') == descriptor['tag']) and (release.get('target_commitish') == descriptor['target_commitish']) and (len(release.get('assets', [])) == 1))
    asset, = release['assets']
    require(asset.get('id') == descriptor['asset_id'] and asset.get('name') == descriptor['name'] and (asset.get('state') == 'uploaded') and (asset.get('size') == descriptor['bytes']) and (asset.get('digest') == 'sha256:' + descriptor['sha256']))

def download_mirror(token, descriptor, destination):
    request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{descriptor['asset_id']}", headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/octet-stream', 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'SortAI-Lightbox-Diagnostic'})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        with error:
            location = error.headers.get('Location', '')
        target = urllib.parse.urlsplit(location)
        require(target.scheme == 'https' and target.hostname in CDN_HOSTS and (target.port in (None, 443)) and (target.username is None) and (target.password is None) and bool(target.query) and (not target.fragment))
        anonymous = urllib.request.Request(location, headers={'Accept-Encoding': 'identity', 'User-Agent': 'SortAI-Lightbox-Diagnostic'})
        response = urllib.request.build_opener(NoRedirect()).open(anonymous, timeout=60)
    received = 0
    checksum = hashlib.sha256()
    with response:
        declared = response.headers.get('Content-Length')
        require(response.status == 200 and response.headers.get('Content-Encoding') in (None, 'identity') and (declared is None or (declared.isdecimal() and int(declared) == descriptor['bytes'])))
        with destination.open('xb') as output:
            for chunk in iter(lambda: response.read(CHUNK), b''):
                received += len(chunk)
                require(received <= descriptor['bytes'])
                checksum.update(chunk)
                output.write(chunk)
    require(received == descriptor['bytes'] and checksum.hexdigest() == descriptor['sha256'])

def receive(secret, destination):
    require(0 < len(secret) <= 16000)
    info = parse_object(secret, {'url', 'sha256', 'key'})
    require(matches(info['key'], '[a-fA-F0-9]{64}') and matches(info['sha256'], '[a-f0-9]{64}'))
    info.pop('url')
    descriptor = mirror_descriptor()
    require(info['sha256'] == descriptor['sha256'])
    token = os.environ.pop('GH_TOKEN', '')
    require(isinstance(token, str) and 0 < len(token) <= 4096)
    read_mirror_release(token, descriptor)
    download_mirror(token, descriptor, destination)
    del token
    MIRROR_VERIFIED.clear()
    MIRROR_VERIFIED.update(descriptor)
    return bytes.fromhex(info['key'])
'Diagnostic-only worker body appended to the reviewed encrypted transport.'
DIAGNOSTIC_ID = 'lightbox-diag3927'
PROBE_NAME = 'lightbox_probe3927.py'

def extract_diagnostic_job(bundle, scratch):
    limits = {'source.zip': MAX_SOURCE, 'job.json': 8192}
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        require(len(entries) == len(limits) and {entry.filename for entry in entries} == limits.keys())
        for entry in entries:
            require(0 < entry.file_size <= limits[entry.filename])
            extract_member(archive, entry, scratch / entry.filename)
    job = parse_object((scratch / 'job.json').read_bytes(), {'source_commit', 'version', 'diagnostic_id', 'probe_sha256', 'nonce'})
    require(job['version'] == VERSION and job['diagnostic_id'] == DIAGNOSTIC_ID and matches(job['source_commit'], '[a-f0-9]{40}') and matches(job['probe_sha256'], '[a-f0-9]{64}') and matches(job['nonce'], '[a-f0-9]{32}'))
    return job

def original_files(source):
    return {path.relative_to(source).as_posix(): file_digest(path) for path in sorted(source.rglob('*')) if path.is_file()}

def fingerprint(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def run_diagnostic(temp, run_id, attempt, workflow_commit):
    require(platform.machine() == 'arm64' and platform.mac_ver()[0].startswith('15.'))
    secret = os.environ.pop(SECRET_NAME, '')
    work = temp / f'sortai-lightbox-diag3927-{run_id}-{attempt}'
    work.mkdir(mode=448)
    with TemporaryDirectory(prefix='private-lightbox-diagnostic-', dir=work) as name:
        scratch = Path(name)
        log = scratch / 'diagnostic.log'
        log.touch(mode=384)
        log.write_text(json.dumps({'diagnostic_id': DIAGNOSTIC_ID, 'phase': 'startup', 'run_id': run_id, 'run_attempt': attempt, 'workflow_commit': workflow_commit}, separators=(',', ':')) + '\n', encoding='utf8')
        encrypted = scratch / 'job.enc'
        bundle = scratch / 'job.zip'
        source = scratch / 'source'
        try:
            key = phase('Download and verify exact encrypted diagnostic input', receive, secret, encrypted)
            del secret
            phase('Authenticate diagnostic input', decrypt, encrypted, bundle, key)
            del key
            encrypted.unlink()
            job = phase('Validate diagnostic-only job', extract_diagnostic_job, bundle, scratch)
            bundle.unlink()
            probe = Path(__file__).with_name(PROBE_NAME).resolve(strict=True)
            require(file_digest(probe) == job['probe_sha256'])
            phase('Verify and extract exact private source', extract_source, scratch / 'source.zip', source, job['source_commit'])
            source_archive_sha = file_digest(scratch / 'source.zip')
            (scratch / 'source.zip').unlink()
            before = original_files(source)
            for folder in ('home', 'tmp', 'data'):
                (scratch / folder).mkdir(mode=448)
            allowed = ('PATH', 'LANG', 'LC_ALL', 'DEVELOPER_DIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR')
            environment = {key: os.environ[key] for key in allowed if key in os.environ}
            environment.update(HOME=str(scratch / 'home'), TMPDIR=str(scratch / 'tmp'), PYTHONIOENCODING='utf8', PYTHONDONTWRITEBYTECODE='1', PYTHONFAULTHANDLER='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', BLIS_NUM_THREADS='1', SORT_AI_DATA_DIR=str(scratch / 'data'))
            phase('Prepare the same pinned Python environment', run_private, [sys.executable, '-m', 'venv', '.venv-macos'], source, environment, log)
            python = source / '.venv-macos/bin/python'
            phase('Install the same pinned diagnostic dependencies', run_private, [str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '-r', 'requirements-build.txt'], source, environment, log)
            results = []
            for backend in ('offscreen', 'cocoa'):
                report_path = scratch / (backend + '.json')
                command = [str(python), str(probe), '--backend', backend, '--output', str(report_path)]
                if backend == 'offscreen':
                    command.append('--prelude-discover')
                print('Run instrumented ' + backend + ' lightbox diagnostics', flush=True)
                with log.open('ab') as stream:
                    try:
                        completed = subprocess.run(command, cwd=source, env={**environment, 'QT_QPA_PLATFORM': backend}, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, timeout=360 if backend == 'offscreen' else 240)
                        code = completed.returncode
                        timed_out = False
                    except subprocess.TimeoutExpired:
                        code = None
                        timed_out = True
                entry = {'backend': backend, 'exit': code, 'timed_out': timed_out, 'report_exists': report_path.is_file()}
                if report_path.is_file():
                    require(not report_path.is_symlink() and report_path.stat().st_size <= 900000)
                    report = json.loads(report_path.read_bytes())
                    require(report.get('diagnostic_id') == DIAGNOSTIC_ID and report.get('actual_backend') == backend)
                    entry.update(tests=sum((value['tests'] for value in report['runs'])), failures=sum((value['failures'] for value in report['runs'])), errors=sum((value['errors'] for value in report['runs'])), report_sha256=file_digest(report_path))
                results.append(entry)
            after = {name: file_digest(source / name) for name in before}
            proof = {'ok': True, 'diagnostic_id': DIAGNOSTIC_ID, 'version': VERSION, 'source_commit': job['source_commit'], 'source_archive_sha256': source_archive_sha, 'probe_sha256': job['probe_sha256'], 'nonce': job['nonce'], 'ciphertext_mirror': dict(MIRROR_VERIFIED), 'run_id': run_id, 'run_attempt': attempt, 'workflow_commit': workflow_commit, 'source_tree_before': fingerprint(before), 'source_tree_after': fingerprint(after), 'source_unchanged': before == after, 'changed_source_paths': [name for name in before if before[name] != after[name]], 'results': results, 'deliverable_built': False, 'feed_published': False, 'cursor_control': False}
            with log.open('ab') as stream:
                stream.write(('\nLIGHTBOX_DIAGNOSTIC_BINDING ' + json.dumps(proof, separators=(',', ':')) + '\n').encode())
            require(before == after)
            print('Diagnostic reports captured; all private output remains encrypted.', flush=True)
        except BaseException as error:
            failure = dict(LAST_FAILURE) if LAST_FAILURE else {'phase': 'diagnostic-worker', 'error_type': type(error).__name__, 'http_status': None}
            with log.open('ab') as stream:
                stream.write(('LIGHTBOX_DIAGNOSTIC_STARTUP_FAILURE ' + json.dumps(failure, separators=(',', ':')) + '\n').encode())
            raise
        finally:
            original_failure = sys.exc_info()[0] is not None
            print('Seal the bounded diagnostic output', flush=True)
            try:
                seal_diagnostic(log, work / DIAGNOSTIC_NAME)
            except Exception as seal_error:
                print('::error::Diagnostic sealing failed: ' + type(seal_error).__name__, file=sys.stderr)
                if not original_failure:
                    raise RelayFailure('Seal the bounded diagnostic output') from None

def upload_diagnostic(temp, run_id, attempt, workflow_commit):
    work = temp / f'sortai-lightbox-diag3927-{run_id}-{attempt}'
    diagnostic = work / DIAGNOSTIC_NAME
    require(diagnostic.is_file() and (not diagnostic.is_symlink()) and (60 < diagnostic.stat().st_size <= DIAGNOSTIC_LIMIT + 60))
    tag = f'lightbox-diag3927-debug-{run_id}-attempt-{attempt}'
    environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'GH_TOKEN') if key in os.environ}
    phase('Upload only the encrypted diagnostic to its separate unpublished draft', run_private, ['gh', 'release', 'create', tag, str(diagnostic), '--repo', REPOSITORY, '--draft', '--prerelease', '--target', workflow_commit, '--title', f'Encrypted lightbox diagnostic {run_id}', '--notes', 'Sealed instrumented exact-source lightbox diagnostic; no application deliverables.'], work, environment, work / 'diagnostic-upload.log')

def main():
    commands = {'run': run_diagnostic, 'upload-diagnostic': upload_diagnostic}
    require(len(sys.argv) == 2 and sys.argv[1] in commands)
    temp, run_id, attempt, workflow_commit = run_context()
    commands[sys.argv[1]](temp, run_id, attempt, workflow_commit)
if __name__ == '__main__':
    try:
        main()
    except RelayFailure as error:
        print('::error::Diagnostic phase failed: ' + str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print('::error::Diagnostic validation failed; private details withheld.', file=sys.stderr)
        raise SystemExit(2) from None
