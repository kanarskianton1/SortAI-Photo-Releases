"""Fetch verified unpublished public-repository assets with a fresh job-token redirect.

This file is copied unchanged alongside the public native/QA worker. It contains
no credentials, source, signed URLs or application state.
"""
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = 'kanarskianton1/SortAI-Photo-Releases'
CDN_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com',
             'github-releases.githubusercontent.com'}
FIELDS = {'schema', 'kind', 'repository', 'release_id', 'asset_id', 'name', 'tag',
          'target_commitish', 'size', 'sha256'}
CHUNK = 1024**2


def require(condition, reason='Durable asset validation failed.'):
    if not condition:
        raise ValueError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_descriptor(value, *, kind=None, limit=2 * 1024**3):
    require(isinstance(value, dict) and set(value) == FIELDS)
    require(value['schema'] == 1 and type(value['schema']) is int
            and value['repository'] == REPOSITORY
            and value['kind'] in ('source', 'models', 'base', 'target', 'compact')
            and (kind is None or value['kind'] == kind))
    for field in ('release_id', 'asset_id'):
        require(type(value[field]) is int and value[field] > 0)
    require(type(value['size']) is int and 0 < value['size'] <= limit)
    require(isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256']))
    require(isinstance(value['target_commitish'], str) and re.fullmatch('[a-f0-9]{40}', value['target_commitish']))
    require(isinstance(value['name'], str) and 0 < len(value['name']) <= 200
            and not any(ord(char) < 33 or char in '/\\:' for char in value['name']))
    require(isinstance(value['tag'], str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}', value['tag']))
    return value


def make_descriptor(release, asset, kind):
    value = {'schema': 1, 'kind': kind, 'repository': REPOSITORY, 'release_id': release['id'],
             'asset_id': asset['id'], 'name': asset['name'], 'tag': release['tag_name'],
             'target_commitish': release['target_commitish'], 'size': asset['size'],
             'sha256': asset.get('digest', '').removeprefix('sha256:')}
    validate_descriptor(value, kind=kind)
    validate_release(release, value)
    return value


def validate_release(release, descriptor):
    validate_descriptor(descriptor)
    require(isinstance(release, dict) and release.get('id') == descriptor['release_id']
            and release.get('draft') is True and release.get('prerelease') is True
            and release.get('published_at') is None and release.get('tag_name') == descriptor['tag']
            and release.get('target_commitish') == descriptor['target_commitish'])
    assets = release.get('assets')
    require(isinstance(assets, list) and len(assets) <= 50)
    found = [asset for asset in assets if asset.get('id') == descriptor['asset_id']
             or asset.get('name') == descriptor['name']]
    require(len(found) == 1)
    asset = found[0]
    require(asset.get('id') == descriptor['asset_id'] and asset.get('name') == descriptor['name']
            and asset.get('state') == 'uploaded' and type(asset.get('size')) is int
            and asset['size'] == descriptor['size'] and asset.get('digest') == 'sha256:' + descriptor['sha256'])


def api_request(token, path, accept):
    require(isinstance(token, str) and 0 < len(token) <= 4096 and not any(ord(char) < 33 for char in token))
    return urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Authorization': 'Bearer ' + token, 'Accept': accept,
                 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'SortAI-Durable-Native-Input'})


def verify_remote(token, descriptor):
    validate_descriptor(descriptor)
    request = api_request(token, '/releases/' + str(descriptor['release_id']), 'application/vnd.github+json')
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        raw = response.read(256 * 1024 + 1)
        require(response.status == 200 and len(raw) <= 256 * 1024)
    release = json.loads(raw)
    validate_release(release, descriptor)
    return descriptor


def download(token, descriptor, destination, *, kind=None, limit=2 * 1024**3):
    validate_descriptor(descriptor, kind=kind, limit=limit)
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink())
    verify_remote(token, descriptor)
    request = api_request(token, '/releases/assets/' + str(descriptor['asset_id']), 'application/octet-stream')
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        with error:
            location = error.headers.get('Location', '')
        target = urllib.parse.urlsplit(location)
        require(target.scheme == 'https' and target.hostname in CDN_HOSTS and target.port in (None, 443)
                and target.username is None and target.password is None and bool(target.query) and not target.fragment)
        # New anonymous opener/request: Authorization never follows a redirect.
        anonymous = urllib.request.Request(location, headers={'Accept-Encoding': 'identity',
                          'User-Agent': 'SortAI-Durable-Native-Input'})
        response = urllib.request.build_opener(NoRedirect()).open(anonymous, timeout=60)
    size = 0
    checksum = hashlib.sha256()
    with response:
        declared = response.headers.get('Content-Length')
        require(response.status == 200 and response.headers.get('Content-Encoding') in (None, 'identity')
                and (declared is None or declared.isdecimal() and int(declared) == descriptor['size']))
        with destination.open('xb') as output:
            for block in iter(lambda: response.read(CHUNK), b''):
                size += len(block)
                require(size <= descriptor['size'])
                checksum.update(block)
                output.write(block)
    require(size == descriptor['size'] and checksum.hexdigest() == descriptor['sha256'])
    return {'size': size, 'sha256': checksum.hexdigest()}
