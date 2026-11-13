"""Receive an authenticated private build input on an ephemeral Apple Silicon host."""
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
REF = 'refs/heads/build-check/macos-arm64-3919'
VERSION = '3.9.19'
SECRET_NAME = 'SORTAI_NATIVE_COMPAT_3919'
STEM = f'SortAI-Photo-{VERSION}-macOS-arm64'
ARTIFACTS = tuple(STEM + suffix for suffix in ('.zip', '.zip.sha256', '.dmg', '.dmg.sha256', '-BUILD_REPORT.json'))
CDN_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
MAX_ENCRYPTED = 1024**3
MAX_SOURCE = 128 * 1024**2
CHUNK = 1024**2
AAD = b'SORTAI_NATIVE_JOB_V1\n'
DIAGNOSTIC_PUBLIC = bytes.fromhex('79f655a57862f75de84220b33aa91e25acebfddca1f7312ac8c47836cbcd9a10')
DIAGNOSTIC_INFO = b'sortai-relay-diagnostic-v1'
DIAGNOSTIC_LIMIT = 2 * 1024**2
DIAGNOSTIC_NAME = 'native-diagnostic.enc'


class RelayFailure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def require(condition):
    if not condition:
        raise ValueError('Relay validation failed.')


def phase(label, operation, *args):
    print(label, flush=True)
    try:
        return operation(*args)
    except Exception:
        # Exceptions may include signed URLs, archive entries or private paths.
        raise RelayFailure(label) from None


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
    require(sys.platform == 'darwin' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REF') == REF and os.environ.get('GITHUB_EVENT_NAME') == 'push')
    run_id = os.environ.get('GITHUB_RUN_ID')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT')
    commit = os.environ.get('GITHUB_SHA')
    require(matches(run_id, r'[1-9][0-9]{0,19}') and matches(attempt, r'[1-9][0-9]{0,9}')
            and matches(commit, r'[a-f0-9]{40}'))
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(temp.is_dir())
    return temp, int(run_id), int(attempt), commit


def receive(secret, destination):
    require(0 < len(secret) <= 16000)
    info = parse_object(secret, {'url', 'sha256', 'key'})
    require(matches(info['key'], r'[a-fA-F0-9]{64}'))
    fetch_asset(info, destination, MAX_ENCRYPTED)
    return bytes.fromhex(info['key'])


def fetch_asset(info, destination, limit):
    require(matches(info['sha256'], r'[a-f0-9]{64}') and isinstance(info['url'], str)
            and not any(ord(char) < 33 for char in info['url']))
    size = info.get('size')
    require(size is None or type(size) is int and 28 < size <= limit)
    target = urllib.parse.urlsplit(info['url'])
    require(target.scheme == 'https' and target.hostname in CDN_HOSTS and target.port in (None, 443)
            and target.username is None and target.password is None and bool(target.query) and not target.fragment)
    request = urllib.request.Request(info['url'], headers={'Accept-Encoding': 'identity', 'User-Agent': 'SortAI-Native-Relay'})
    received = 0
    digest = hashlib.sha256()
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        declared = response.headers.get('Content-Length')
        require(response.status == 200 and response.headers.get('Content-Encoding') in (None, 'identity')
                and (declared is None or declared.isdecimal() and 28 < int(declared) <= limit))
        with destination.open('xb') as output:
            while chunk := response.read(CHUNK):
                received += len(chunk)
                require(received <= limit)
                digest.update(chunk)
                output.write(chunk)
    require(28 < received and (declared is None or received == int(declared)) and (size is None or size == received)
            and digest.hexdigest() == info['sha256'])


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
    require(not entry.is_dir() and member_type(entry) in (0, stat.S_IFREG) and not entry.flag_bits & 1)
    with archive.open(entry) as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output, CHUNK)
    require(destination.stat().st_size == entry.file_size)


def extract_job(bundle, scratch):
    limits = {'source.zip': MAX_SOURCE, 'job.json': 8192}
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        require(len(entries) == len(limits) and {entry.filename for entry in entries} == limits.keys()
                and sum(entry.file_size for entry in entries) <= MAX_ENCRYPTED)
        for entry in entries:
            require(0 < entry.file_size <= limits[entry.filename])
            extract_member(archive, entry, scratch / entry.filename)
    job = parse_object((scratch / 'job.json').read_bytes(),
                       {'source_commit', 'version', 'cloud_url', 'cloud_server_id', 'models'})
    require(job['version'] == VERSION and matches(job['source_commit'], r'[a-f0-9]{40}')
            and matches(job['cloud_server_id'], r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}')
            and isinstance(job['cloud_url'], str) and 0 < len(job['cloud_url']) <= 2048
            and not any(ord(char) < 33 for char in job['cloud_url']))
    url = urllib.parse.urlsplit(job['cloud_url'])
    require(url.scheme == 'https' and bool(url.hostname) and url.username is None and url.password is None
            and not url.query and not url.fragment and url.path in ('', '/'))
    require(isinstance(job['models'], dict) and set(job['models']) == {'url', 'size', 'sha256'})
    return job


def extract_source(archive_path, destination, commit):
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 5000 and archive.comment == commit.encode('ascii')
                and sum(entry.file_size for entry in entries) <= MAX_SOURCE)
        seen = set()
        for entry in entries:
            name = entry.filename[:-1] if entry.is_dir() else entry.filename
            parts = name.split('/')
            require(all(part not in ('', '.', '..') and not any(char in part for char in '\\:\0') for part in parts)
                    and parts[0].casefold() not in ('.git', '.local-server', '.release-private', 'data', 'models'))
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
                if (entry.external_attr >> 16) & 0o111:
                    target.chmod(0o700)
    require(all((destination / name).is_file() for name in ('main.py', 'build_models.py', 'build_macos.py')))


def build_environment(job):
    names = ('PATH', 'HOME', 'TMPDIR', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'DEVELOPER_DIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR')
    environment = {name: os.environ[name] for name in names if name in os.environ}
    environment.update(QT_QPA_PLATFORM='offscreen', PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1',
                       SORTAI_CLOUD_URL=job['cloud_url'], SORTAI_CLOUD_SERVER_ID=job['cloud_server_id'])
    return environment


def run_private(arguments, cwd, environment, log):
    with log.open('ab') as output:
        subprocess.run(arguments, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                       stdout=output, stderr=subprocess.STDOUT, check=True)


def seal_diagnostic(log, destination):
    require(log.is_file() and not log.is_symlink())
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


@contextmanager
def keep_failure_diagnostic(log, destination):
    try:
        yield
    except Exception:
        if log.is_file():
            try:
                phase('Seal the withheld native diagnostic', seal_diagnostic, log, destination)
            except RelayFailure:
                print('::warning::Could not seal the native diagnostic. The private log was withheld.', file=sys.stderr)
        raise


def file_digest(path):
    require(path.is_file() and not path.is_symlink())
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verify_artifacts(directory):
    require({path.name for path in directory.glob(STEM + '*')} == set(ARTIFACTS))
    report_path = directory / (STEM + '-BUILD_REPORT.json')
    require(report_path.is_file() and not report_path.is_symlink() and 0 < report_path.stat().st_size <= 2 * 1024**2)
    report = json.loads(report_path.read_bytes())
    require(report.get('ok') is True and report.get('version') == VERSION and report.get('platform') == 'macos-arm64'
            and report['native_keychain'].get('ok') is True)
    for check in ('native_app', 'mounted_dmg'):
        self_test = report[check]['self_test']
        require(self_test.get('ok') is True and self_test.get('frozen') is True)
    for suffix in ('.zip', '.dmg'):
        artifact = directory / (STEM + suffix)
        digest = file_digest(artifact)
        sidecar = artifact.with_suffix(suffix + '.sha256')
        require(sidecar.is_file() and not sidecar.is_symlink() and sidecar.stat().st_size <= 1024
                and sidecar.read_text(encoding='ascii').split() == [digest, artifact.name]
                and report['artifacts'].get(artifact.name) == {'sha256': digest, 'bytes': artifact.stat().st_size})
    return report_path, report


def build(temp, run_id, attempt, workflow_commit):
    secret = os.environ.pop(SECRET_NAME, '')
    work = temp / f'sortai-relay-{run_id}-{attempt}'
    work.mkdir(mode=0o700)
    with TemporaryDirectory(prefix='private-native-build-', dir=work) as name:
        scratch = Path(name)
        encrypted = scratch / 'job.enc'
        bundle = scratch / 'job.zip'
        source = scratch / 'source'
        log = scratch / 'build.log'
        with keep_failure_diagnostic(log, work / DIAGNOSTIC_NAME):
            key = phase('Download and verify encrypted input', receive, secret, encrypted)
            del secret
            phase('Authenticate and decrypt input', decrypt, encrypted, bundle, key)
            del key
            encrypted.unlink()
            job = phase('Validate the build job', extract_job, bundle, scratch)
            bundle.unlink()
            phase('Verify and extract the source snapshot', extract_source, scratch / 'source.zip', source, job['source_commit'])
            (scratch / 'source.zip').unlink()
            environment = build_environment(job)
            phase('Fetch the previously verified model asset', fetch_asset, job.pop('models'), scratch / 'models.zip', 512 * 1024**2)
            phase('Verify and extract the approved model bundle', run_private,
                  [sys.executable, 'build_models.py', 'verify', '--archive', str(scratch / 'models.zip'), '--destination', 'models'],
                  source, environment, log)
            (scratch / 'models.zip').unlink()
            phase('Build and test the native application and mounted disk image', run_private,
                  [sys.executable, 'build_macos.py'], source, environment, log)
            output = source / 'dist/macos-arm64'
            report_path, report = phase('Validate the five native deliverables', verify_artifacts, output)
            host = platform.mac_ver()[0]
            require(host.startswith('15.') and platform.machine() == 'arm64')
            report.update(distribution_build={'host': host, 'architecture': 'arm64'},
                          relay_source_commit=job['source_commit'], relay_run_id=run_id, relay_run_attempt=attempt,
                          relay_workflow_commit=workflow_commit)
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            deliverables = scratch / 'deliverables'
            deliverables.mkdir(mode=0o700)
            for artifact in ARTIFACTS:
                (output / artifact).rename(deliverables / artifact)
            deliverables.rename(work / 'deliverables')


def upload(temp, run_id, attempt, workflow_commit):
    require(bool(os.environ.get('GH_TOKEN')) and SECRET_NAME not in os.environ)
    work = temp / f'sortai-relay-{run_id}-{attempt}'
    deliverables = work / 'deliverables'
    _, report = phase('Recheck artifact digests before draft upload', verify_artifacts, deliverables)
    require(report.get('relay_run_id') == run_id and report.get('relay_run_attempt') == attempt
            and report.get('relay_workflow_commit') == workflow_commit
            and matches(report.get('relay_source_commit'), r'[a-f0-9]{40}'))
    tag = f'relay-macos-{run_id}-attempt-{attempt}'
    log = work / 'upload.log'
    environment = {**os.environ, 'GH_PROMPT_DISABLED': '1'}
    phase('Create an unpublished prerelease draft', run_private,
          ['gh', 'release', 'create', tag, '--repo', REPOSITORY, '--draft', '--prerelease', '--target', workflow_commit,
           '--title', f'Verified Apple Silicon relay {run_id}', '--notes', 'Temporary verified native build delivery.'],
          work, environment, log)
    phase('Upload the five verified draft assets', run_private,
          ['gh', 'release', 'upload', tag, '--repo', REPOSITORY, *(str(deliverables / name) for name in ARTIFACTS)],
          work, environment, log)
    print('Native draft delivery complete.', flush=True)


def upload_diagnostic(temp, run_id, attempt, workflow_commit):
    require(bool(os.environ.get('GH_TOKEN')) and SECRET_NAME not in os.environ)
    work = temp / f'sortai-relay-{run_id}-{attempt}'
    diagnostic = work / DIAGNOSTIC_NAME
    if not diagnostic.exists():
        print('The failed stage did not produce a sealed native log.', flush=True)
        return
    require(diagnostic.is_file() and not diagnostic.is_symlink() and 60 < diagnostic.stat().st_size <= DIAGNOSTIC_LIMIT + 60)
    tag = f'relay-macos-debug-{run_id}-attempt-{attempt}'
    environment = {**os.environ, 'GH_PROMPT_DISABLED': '1'}
    phase('Upload only the sealed diagnostic to a separate unpublished draft', run_private,
          ['gh', 'release', 'create', tag, str(diagnostic), '--repo', REPOSITORY, '--draft', '--prerelease',
           '--target', workflow_commit, '--title', f'Encrypted native diagnostic {run_id}', '--notes', 'Sealed native build diagnostic.'],
          work, environment, work / 'diagnostic-upload.log')


def main():
    try:
        commands = {'build': build, 'upload': upload, 'upload-diagnostic': upload_diagnostic}
        require(len(sys.argv) == 2 and sys.argv[1] in commands)
        context = phase('Validate the public workflow identity', run_context)
        commands[sys.argv[1]](*context)
    except RelayFailure as error:
        print(f'::error::{error} failed. Private command output was withheld.', file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print('::error::Native relay validation failed. Private data was withheld.', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
