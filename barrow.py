import logging
import os
import os.path
import re
import shutil
import sys
import tempfile
import hashlib

from fnmatch import fnmatch
from urllib.request import urlretrieve
from urllib.parse import urlparse

import setuptools.archive_util


logger = logging.getLogger(__name__)


class UserError(Exception):
    pass


class ChecksumError(UserError):
    pass


class ProgressFilter(object):
    """Filter out contents from the extracted package."""

    def __init__(self, excludes, verbose=False):
        self.excludes = excludes or []
        self.excluded_count = 0

    def __call__(self, src, dst):
        for exclude in self.excludes:
            if fnmatch(src, exclude):
                if self.verbose:
                    logger.debug("Excluding %s" % src.rstrip('/'))
                self.excluded_count += 1
                return
        return dst


class Download(object):
    """Configurable download utility.
    Handles the download cache and offline mode.
    Download(options=None, cache=None, namespace=None,
             offline=False, fallback=False, hash_name=False, logger=None)
    options: mapping of buildout options (e.g. a ``buildout`` config section)
    cache: path to the download cache (excluding namespaces)
    namespace: namespace directory to use inside the cache
    offline: whether to operate in offline mode
    fallback: whether to use the cache as a fallback (try downloading first)
    hash_name: whether to use a hash of the URL as cache file name
    logger: an optional logger to receive download-related log messages
    """

    def __init__(self, download_cache=None, offline=False, fallback=False, hash_name=False):
        self.download_cache = download_cache
        self.offline = offline
        self.fallback = fallback
        self.hash_name = hash_name

    def __call__(self, url, md5sum=None, path=None):
        """Download a file according to the utility's configuration.
        url: URL to download
        md5sum: MD5 checksum to match
        path: where to place the downloaded file
        Returns the path to the downloaded file.
        """
        if self.download_cache:
            local_path, is_temp = self.download_cached(url, md5sum)
        else:
            local_path, is_temp = self.download(url, md5sum, path)

        return locate_at(local_path, path), is_temp

    def download_cached(self, url, md5sum=None):
        """Download a file from a URL using the cache.
        This method assumes that the cache has been configured. Optionally, it
        raises a ChecksumError if a cached copy of a file has an MD5 mismatch,
        but will not remove the copy in that case.
        """
        if not os.path.exists(os.path.dirname(self.download_cache)):
            raise UserError("The directory: %r to be used as a download cache doesn't exist." % self.download_cache)

        if not os.path.exists(self.download_cache):
            os.mkdir(self.download_cache)

        cache_key = self.filename(url)
        cached_path = os.path.join(self.download_cache, cache_key)

        logger.debug('Searching cache at %s' % self.download_cache)
        if os.path.exists(cached_path):
            is_temp = False
            if self.fallback:
                try:
                    _, is_temp = self.download(url, md5sum, cached_path)
                except ChecksumError:
                    raise
                except Exception:
                    pass

            if not check_md5sum(cached_path, md5sum):
                raise ChecksumError(
                    'MD5 checksum mismatch for cached download '
                    'from %r at %r' % (url, cached_path)
                )
            logger.debug('Using cache file %s' % cached_path)
        else:
            logger.debug('Cache miss; will cache %s as %s' % (url, cached_path))
            _, is_temp = self.download(url, md5sum, cached_path)

        return cached_path, is_temp

    def download(self, url, md5sum=None, path=None):
        """Download a file from a URL to a given or temporary path.
        An online resource is always downloaded to a temporary file and moved
        to the specified path only after the download is complete and the
        checksum (if given) matches. If path is None, the temporary file is
        returned and the client code is responsible for cleaning it up.
        """
        # Make sure the drive letter in windows-style file paths isn't
        # interpreted as a URL scheme.
        if re.match(r"^[A-Za-z]:\\", url):
            url = 'file:' + url

        parsed_url = urlparse(url, 'file')
        url_scheme, _, url_path = parsed_url[:3]
        if url_scheme == 'file':
            logger.debug('Using local resource %s' % url)
            if not check_md5sum(url_path, md5sum):
                raise ChecksumError(
                    'MD5 checksum mismatch for local resource at %r.' %
                    url_path)
            return locate_at(url_path, path), False

        if self.offline:
            raise UserError("Couldn't download %r in offline mode." % url)

        logger.info('Downloading %s' % url)
        handle, tmp_path = tempfile.mkstemp(prefix='buildout-')
        os.close(handle)
        try:
            tmp_path, headers = urlretrieve(url, tmp_path)
            if not check_md5sum(tmp_path, md5sum):
                raise ChecksumError(
                    'MD5 checksum mismatch downloading %r' % url)
        except IOError:
            e = sys.exc_info()[1]
            os.remove(tmp_path)
            raise UserError("Error downloading extends for URL " "%s: %s" % (url, e))
        except Exception:
            os.remove(tmp_path)
            raise

        if path:
            shutil.move(tmp_path, path)
            return path, False
        else:
            return tmp_path, True

    def filename(self, url):
        """Determine a file name from a URL according to the configuration.
        """
        if self.hash_name:
            return hashlib.sha1(url.encode()).hexdigest()
        else:
            return filename_from_url(url)


def filename_from_url(url):
    if re.match(r"^[A-Za-z]:\\", url):
        url = 'file:' + url
    parsed = urlparse(url, 'file')
    url_path = parsed[2]

    if parsed[0] == 'file':
        while True:
            url_path, name = os.path.split(url_path)
            if name:
                return name
            if not url_path:
                break
    else:
        for name in reversed(url_path.split('/')):
            if name:
                return name

    url_host, url_port = parsed[-2:]
    return '%s:%s' % (url_host, url_port)


def check_md5sum(path, md5sum):
    """Tell whether the MD5 checksum of the file at path matches.
    No checksum being given is considered a match.
    """
    if md5sum is None:
        return True

    checksum = hashlib.md5()
    with open(path, 'rb') as f:
        chunk = f.read(2**16)
        while chunk:
            checksum.update(chunk)
            chunk = f.read(2**16)

    return checksum.hexdigest() == md5sum


def realpath(path):
    return os.path.normcase(os.path.abspath(os.path.realpath(path)))


def remove(path):
    if os.path.exists(path):
        os.remove(path)


def locate_at(source, dest):
    if dest is None or realpath(dest) == realpath(source):
        return source

    if os.path.isdir(source):
        shutil.copytree(source, dest)
    else:
        try:
            os.link(source, dest)
        except (AttributeError, OSError):
            shutil.copyfile(source, dest)
    return dest


def calculate_base(extract_dir, strip):
    """
    recipe authors inheriting from this recipe can override this method to set a different base directory.
    """
    # Move the contents of the package in to the correct destination
    top_level_contents = os.listdir(extract_dir)
    if strip:
        if len(top_level_contents) != 1:
            logger.error(
                'Unable to strip top level directory because there are more than one element in the root of the '
                'package.'
            )
            raise UserError('Invalid package contents')
        base = os.path.join(extract_dir, top_level_contents[0])
    else:
        base = extract_dir
    return base


def extract_package(path, destination, *, strip, ignore_existing, excludes, verbose):
    extract_dir = tempfile.mkdtemp(prefix='barrow-')
    progress_filter = ProgressFilter(excludes, verbose=verbose)
    try:
        try:
            setuptools.archive_util.unpack_archive(path, extract_dir, progress_filter=progress_filter)
        except setuptools.archive_util.UnrecognizedFormat:
            logger.error('Unable to extract the package %s. Unknown format.', path)
            raise UserError('Package extraction error')
        if progress_filter.excluded_count > 0:
            logger.info("Excluding %s file(s) matching the exclusion pattern." % progress_filter.excluded_count)
        base = calculate_base(extract_dir, strip)

        logger.info('Extracting package to %s' % destination)
        for filename in os.listdir(base):
            dest = os.path.join(destination, filename)
            if os.path.exists(dest):
                if ignore_existing:
                    logger.info('Ignoring existing target: %s' % dest)
                    continue
                else:
                    logger.error(
                        'Target %s already exists. Either remove it or set ``ignore-existing = true`` '
                        'to ignore existing files and directories.', dest
                    )
                    raise UserError('File or directory already exists.')

            shutil.move(os.path.join(base, filename), dest)
    finally:
        shutil.rmtree(extract_dir)


def process_url(url, md5sum, destination, filename=None, mode=None, extract=None, download_cache=None, hash_name=False,
                strip=False, ignore_existing=False, excludes=None, verbose=False):
    download = Download(download_cache=download_cache, hash_name=hash_name)
    path, is_temp = download(url, md5sum=md5sum)

    try:
        if not filename:
            # Use the original filename of the downloaded file regardless
            # whether download filename hashing is enabled.
            # See http://github.com/hexagonit/hexagonit.recipe.download/issues#issue/2
            filename = filename_from_url(url)

        if extract is None:
            extract = filename.endswith(('.zip', '.tar.gz'))

        # Create destination directory
        if not os.path.isdir(destination):
            os.makedirs(destination)

        if extract:
            extract_package(
                path, destination,
                strip=strip,
                ignore_existing=ignore_existing,
                excludes=excludes,
                verbose=verbose,
            )
        else:
            # Copy the file to destination without extraction
            target_path = os.path.join(destination, filename)
            shutil.copy(path, target_path)
            if mode:
                os.chmod(target_path, int(mode, 8))

    finally:
        if is_temp:
            os.unlink(path)


def main():
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    destination = '/tmp/barrow/static'

    url = 'https://code.jquery.com/jquery-3.1.1.min.js'
    md5sum = None
    extract = None
    ignore_existing = True
    filename = None
    mode = None
    strip = False
    excludes = []
    verbose = False
    hash_name = False
    destination = '/tmp/barrow/static'
    download_cache = '/tmp/barrow/cache'

    url = 'https://github.com/twbs/bootstrap/releases/download/v3.3.1/bootstrap-3.3.1-dist.zip'
    strip = True
    destination = '/tmp/barrow/static/bootstrap'

    process_url(
        url, md5sum, destination,
        filename=filename,
        mode=mode,
        extract=extract,
        download_cache=download_cache,
        hash_name=hash_name,
        strip=strip,
        ignore_existing=ignore_existing,
        excludes=excludes,
        verbose=verbose,
    )


if __name__ == "__main__":
    main()
