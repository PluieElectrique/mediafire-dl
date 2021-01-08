import argparse
from collections import defaultdict
from datetime import datetime
import json
import logging
import os
import re
import sys
import signal

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm, trange


logger = logging.getLogger(__name__)

ASCII_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
FILENAME_FORBIDDEN = re.compile(r'[\\/:*?"<>|]')
LEADING_DASH_DOT = re.compile(r"_*[-.]")
TRAILING_DOTS = re.compile(r"\.+$")


def try_mkdir(path):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass


def sanitize_filename(filename, max_bytes=255):
    filename = ASCII_CONTROL.sub("", filename)
    # The forbidden characters are common enough that we replace them with an
    # underscore to show that a character was replaced.
    filename = FILENAME_FORBIDDEN.sub("_", filename)
    filename = filename.strip()
    # Prepend an underscore to files starting with a dot or dash--this prevents
    # the file from being hidden or being interpreted as a flag on Unix-likes.
    # We need _* to ensure that prepending an underscore doesn't conflict with
    # any existing files.
    if LEADING_DASH_DOT.match(filename):
        filename = "_" + filename
    # Limit the filename to max_bytes at most. We assume UTF-8.
    encoded = filename.encode()
    if len(encoded) > max_bytes:
        filename = encoded[:max_bytes].decode(errors="ignore")
        # Truncation might have exposed trailing spaces, so we strip again.
        filename = filename.strip()
    return filename


def get_clean_filename(qk, name):
    # Windows doesn't like files that end with a period
    name = TRAILING_DOTS.sub("_", name)
    root, ext = os.path.splitext(name)
    # We ignore the extension if it contains forbidden characters.
    if ASCII_CONTROL.search(ext) or FILENAME_FORBIDDEN.search(ext):
        root, ext = name, ""

    # Leave room for underscore, 15-character quickkey, extension, and ".json"
    sanitized = sanitize_filename(root, max_bytes=255 - 1 - 15 - len(ext) - 5)
    return f"{sanitized}_{qk}{ext}"


def get_clean_foldername(fk, name):
    # Leave room for underscore, 13-character folderkey, and ".json"
    sanitized = sanitize_filename(name, max_bytes=255 - 1 - 13 - 5)
    return f"{sanitized}_{fk}"


class MediafireError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class MediafireDownloader:
    MEDIAFIRE_API_BASE = "https://www.mediafire.com/api/1.5/"
    # Required for scraping custom folders
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
    QUICKKEY_RE = re.compile(r"[a-z0-9]{11}|[a-z0-9]{15}")
    DL_URL_RE = re.compile(r"https://download\d+\.mediafire\.com/")
    DL_URL_SCRAPE_RE = re.compile(
        r'aria-label="Download file"\n +href="([^"]+)"\n +id="downloadButton"'
    )
    UPLOAD_COUNTRY_SCRAPE_RE = re.compile(
        r'<div class="lazyload DLExtraInfo-sectionGraphic flag" data-lazyclass="flag-(..)">'
    )
    CUSTOM_FOLDER_SCRAPE_RE = re.compile(r'gs= false,afI= "([a-z0-9]{13})",afQ= 0')
    MAX_REDIRECTS = requests.models.DEFAULT_REDIRECT_LIMIT

    def __init__(self, retry_total, retry_backoff):
        self.s = requests.Session()
        retry = Retry(total=retry_total, backoff_factor=retry_backoff)
        adapter = HTTPAdapter(max_retries=retry)
        self.s.mount("http://", adapter)
        self.s.mount("https://", adapter)

    def mf_api(self, method, params):
        params["response_format"] = "json"
        r = self.s.post(self.MEDIAFIRE_API_BASE + method + ".php", params=params)
        try:
            resp = r.json()["response"]
        except Exception as exc:
            # -1 is not used by the actual API, so this error message will
            # always be printed
            raise MediafireError(
                -1,
                f"Failed to decode JSON: {exc}\n"
                f"method={repr(method)}, params={params}, r.text={repr(r.text)}",
            )

        if resp["result"] == "Success":
            return resp
        else:
            raise MediafireError(resp["error"], resp["message"])

    # We set a default chunk size just below the max of 500 to be safe
    def get_file_info(self, quickkeys, chunk_size=450):
        if not quickkeys:
            return [], []

        def _validate_quickkey(k):
            valid = self.QUICKKEY_RE.fullmatch(k)
            if not valid:
                logger.warning("f{k} is not a valid quickkey")
            return valid

        quickkeys = list(filter(_validate_quickkey, quickkeys))
        file_info = []
        skipped = []
        for i in trange(
            0,
            len(quickkeys),
            chunk_size,
            unit="req",
            desc="Get file info",
        ):
            chunk = quickkeys[i : i + chunk_size]
            try:
                resp = self.mf_api("file/get_info", {"quick_key": ",".join(chunk)})
                if len(chunk) == 1:
                    file_info.append(resp["file_info"])
                else:
                    # There is an "s" when there is more than one quickkey
                    file_info.extend(resp["file_infos"])
                skipped.extend(filter(None, resp.get("skipped", "").split(",")))
            except MediafireError as err:
                if err.code != 110:
                    logger.error(f"Failed to get info for quickkeys {chunk}: {err}")
                skipped.extend(chunk)

        return file_info, skipped

    # The API call fails if even one folderkey is invalid, so we only request
    # info about one folder at a time. We don't validate folderkey because it
    # seems like custom folderkeys can be any string. We don't support the
    # `details` parameter because `get_content` is far more useful.
    def get_folder_info(self, folderkey):
        try:
            return self.mf_api("folder/get_info", params={"folder_key": folderkey})[
                "folder_info"
            ]
        except MediafireError as err:
            if err.args != 112:
                logger.error(f"Failed to get info for folder {folderkey}: {err}")

    def get_folder_contents(
        self, folderkey, content_type="folders", owner_name=None, chunk_size=1000
    ):
        if content_type not in ["folders", "files"]:
            raise ValueError("content_type must be 'folders' or 'files'")
        elif not (100 <= chunk_size <= 1000):
            raise ValueError("chunk_size must be between 100 and 1000, inclusive")

        params = {
            "folder_key": folderkey,
            "chunk_size": chunk_size,
            "content_type": content_type,
        }
        contents = []
        chunk = 1
        while True:
            params["chunk"] = chunk
            try:
                resp = self.mf_api("folder/get_content", params=params)
            except MediafireError:
                logger.error(f"Failed to get chunk {chunk} of folder {folderkey}")
                return contents
            chunk += 1

            content = resp["folder_content"]
            if owner_name:
                for c in content[content_type]:
                    # `get_content` does not return owner_name, so we hackily
                    # add it in
                    c["owner_name"] = owner_name

            contents.extend(content[content_type])
            if content["more_chunks"] == "no":
                break

        return contents

    # Download the file at the given URL (can be any URL, not just a Mediafire
    # file) to the given path
    def download_from_url(self, url, path, file_size=None, chunk_size=16384):
        if file_size is None:
            # /conv/ links might redirect to ?size_id=[some number]
            head = self.s.head(url, allow_redirects=True)
            # XXX: If file_size is provided, this is probably a file that we
            # know exists (the API doesn't return anything for skipped files
            # and we don't try to download deleted files). If not, this is
            # probably a conv link, so it might not exist. This is tight
            # coupling, but I can't think of a better way right now.
            head.raise_for_status()
            if "Content-Length" in head.headers:
                file_size = int(head.headers.get("Content-Length"))
            else:
                logger.error(f"No Content-Length found for {head.url}: {head.headers}")
                return

        start_byte = os.path.getsize(path) if os.path.exists(path) else 0

        if file_size == 0:
            logger.warning(f"Skipping file with size of zero: {url}")
            return
        elif file_size < start_byte:
            logger.warning(
                f"Size on disk ({start_byte}) exceeds reported file size ({file_size}): {url}"
            )
            return
        elif file_size == start_byte:
            logger.debug(f"Already downloaded {url}")
            return

        desc = os.path.basename(path)
        if len(desc) > 60:
            desc = desc[:28] + "<..>" + desc[-28:]
        elif len(desc) < 60:
            desc = f"{desc:<60}"

        try:
            with open(path, "ab") as f, self.s.get(
                url, headers={"Range": f"bytes={start_byte}-"}, stream=True
            ) as r, tqdm(
                initial=start_byte,
                total=file_size,
                desc=desc,
                unit="B",
                unit_scale=True,
            ) as pbar:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    # NOTE: This is necessary to filter out "keep-alive" chunks?
                    # But the requests docs don't mention this at all.
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
        except Exception as exc:
            logger.error(f"Failed to download {url}, skipping: {exc}")

    def scrape_download_page(self, url):
        r = self.s.get(url, allow_redirects=False)
        redirects = 0
        while r.next:
            redirects += 1
            if redirects > self.MAX_REDIRECTS:
                raise Exception("Exceeded {self.MAX_REDIRECTS} redirects")

            location = r.headers["Location"]
            # Some quickkeys redirect to a direct download
            if self.DL_URL_RE.match(location):
                return location, None

            r = self.s.send(r.next, allow_redirects=False)

        download_url = self.DL_URL_SCRAPE_RE.search(r.text)
        # The URL will be missing if the file no longer exists, was removed for
        # violating TOS, etc.
        if download_url:
            upload_country = self.UPLOAD_COUNTRY_SCRAPE_RE.search(r.text)
            upload_country = upload_country.group(1) if upload_country else None
            return download_url.group(1), upload_country
        else:
            return None, None

    def scrape_custom_folder(self, name):
        # Without a user agent, the <script> containing the folderkey will be
        # replaced by an "upgrade browser" popup
        r = self.s.get(
            "https://www.mediafire.com/" + name, headers={"User-Agent": self.USER_AGENT}
        )
        folderkey = self.CUSTOM_FOLDER_SCRAPE_RE.search(r.text)
        if folderkey:
            return folderkey.group(1)
        elif r.url == "https://www.mediafire.com/error.php?errno=370":
            logger.warning(f"Direct linking disabled for custom folder: {name}")
        else:
            logger.warning(f"Invalid custom folder: {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download files, folders, and metadata from Mediafire"
    )
    parser.add_argument(
        "input",
        help="Input JSON with file keys, folder keys, custom folder names, and conv links",
    )
    parser.add_argument("out_dir", help="Output directory")
    parser.add_argument(
        "--retry-total",
        help="Number of times to retry a request (default: %(default)s)",
        metavar="N",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--retry-backoff",
        help="Retry after 0 sec, T sec, T^2 sec, etc. (default: %(default)s)",
        metavar="T",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--log-file",
        help="Log warnings/errors to file (default: log messages are printed)",
        metavar="FILE",
    )
    parser.add_argument(
        "--metadata-only", help="Only get metadata", action="store_true"
    )
    parser.add_argument(
        "--indent", help="JSON indent (default: %(default)s)", type=int, default=None
    )
    args = parser.parse_args()

    if args.log_file:
        logging.basicConfig(filename=args.log_file)

    with open(args.input) as f:
        input_keys = json.load(f)

    os.makedirs(args.out_dir, exist_ok=True)
    mfdl = MediafireDownloader(args.retry_total, args.retry_backoff)

    # File, folders, and conv links which don't return an API response/don't exist
    skipped = []
    # Files which have a "delete_date"
    deleted = []

    def write_summary_json():
        # Not UTC or ISO 8601, but it's readable and filename-safe
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        summary_path = os.path.join(args.out_dir, f"mfdl_summary_{now}.json")
        with open(summary_path, "w") as f:
            json.dump(
                {
                    "skipped": skipped,
                    "deleted": deleted,
                },
                f,
                indent=args.indent,
            )
        print(f"Summary JSON written to: {summary_path}")

    def write_summary_handler(signal, frame):
        print("Exiting early...")
        write_summary_json()
        sys.exit(1)

    signal.signal(signal.SIGINT, write_summary_handler)

    for url in tqdm(input_keys.get("conv", []), desc="Get conv links", unit=""):
        try:
            path = os.path.join(args.out_dir, url.split("/")[-1])
            mfdl.download_from_url(url, path)
        except requests.exceptions.HTTPError as err:
            logger.warning(f"Failed to download conv URL: {err}")
            skipped.append(url)

    folders = defaultdict(lambda: {"is_child": False, "children": []})
    folderkeys_seen = set()
    folderkeys_queue = set(input_keys.get("folder", []))

    for custom_name in tqdm(
        input_keys.get("custom_folder", []), desc="Get custom folder key"
    ):
        fk = mfdl.scrape_custom_folder(custom_name)
        if fk:
            folderkeys_queue.add(fk)
        else:
            skipped.append(custom_name)

    pbar = tqdm(desc="Get folder info", unit="")
    while folderkeys_queue:
        fk = folderkeys_queue.pop()
        folderkeys_seen.add(fk)

        if fk in folders:
            folder = folders[fk]
        else:
            info = mfdl.get_folder_info(fk)
            if info:
                folder = folders[fk]
                folder["info"] = info
            else:
                skipped.append(fk)
                continue

        if int(folder["info"]["folder_count"]) > 0:
            child_folders = mfdl.get_folder_contents(
                fk, content_type="folders", owner_name=folder["info"]["owner_name"]
            )
            folder["children"].extend(c["folderkey"] for c in child_folders)

            for child_info in child_folders:
                cfk = child_info["folderkey"]
                folders[cfk].update(info=child_info, is_child=True)
                if (cfk not in folderkeys_seen) and (cfk not in folderkeys_queue):
                    folderkeys_queue.add(cfk)

        pbar.update(1)

    pbar.close()

    quickkeys_seen = set()

    def process_file(info, path):
        try:
            qk = info["quickkey"]
            quickkeys_seen.add(qk)

            name = get_clean_filename(qk, info["filename"])

            if "delete_date" in info:
                deleted.append(qk)
            elif not args.metadata_only:
                normal_download = info["links"]["normal_download"]
                download_url, upload_country = mfdl.scrape_download_page(
                    normal_download
                )
                if not download_url:
                    logger.warning(f"No download URL found for {normal_download}")
                    return

                mfdl.download_from_url(
                    download_url,
                    os.path.join(path, name),
                    file_size=int(info["size"]),
                )
                if upload_country:
                    info["upload_country"] = upload_country

            with open(os.path.join(path, name + ".json"), "w") as f:
                json.dump(info, f, indent=args.indent)
        except Exception as exc:
            # It's ugly to wrap everything in a try block, but it's more
            # important to not crash whenever possible
            logger.error(
                f"Failed to process file: info={info}, path={repr(path)}: {exc}"
            )

    def process_folder(fk, path, pbar):
        folder = folders[fk]
        info = folder["info"]
        try:
            name = get_clean_foldername(fk, info["name"])
            folder_path = os.path.join(path, name)
            try_mkdir(folder_path)

            with open(os.path.join(path, name + ".json"), "w") as f:
                json.dump(info, f, indent=args.indent)

            if int(info["file_count"]) > 0:
                for child_info in mfdl.get_folder_contents(
                    fk, content_type="files", owner_name=info["owner_name"]
                ):
                    process_file(child_info, folder_path)

            for cfk in folder["children"]:
                process_folder(cfk, folder_path, pbar)

            pbar.update(1)
        except Exception as exc:
            # It's ugly to wrap everything in a try block, but it's more
            # important to not crash whenever possible
            logger.error(
                f"Failed to process folder: info={info}, path={repr(path)}: {exc}"
            )

    with tqdm(desc="Process folders", total=len(folders), unit="") as pbar:
        for fk, folder in folders.items():
            if not folder["is_child"]:
                path = os.path.join(
                    args.out_dir, sanitize_filename(folder["info"]["owner_name"])
                )
                try_mkdir(path)
                process_folder(fk, path, pbar)

    quickkeys = list(set(input_keys.get("file", [])) - quickkeys_seen)
    file_infos, file_skipped = mfdl.get_file_info(quickkeys)
    skipped.extend(file_skipped)
    for file_info in file_infos:
        path = os.path.join(args.out_dir, sanitize_filename(file_info["owner_name"]))
        try_mkdir(path)
        process_file(file_info, path)

    write_summary_json()
