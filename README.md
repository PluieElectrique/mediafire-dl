# mediafire-dl

Download files, folders, and metadata from Mediafire.

## Setup

Requires Python 3. (Tested on 3.9.1.)

Install `requests` and `tqdm`, e.g. with `pip install -r requirements.txt`.

## Usage

Put your file keys (quickkeys), folder keys, and custom folders in a JSON file like so:
```json
{
    "file": [
        "[quickkey 1]",
        "[quickkey 2]"
    ],
    "folder": [
        "[folderkey 1]",
        "[folderkey 2]"
    ],
    "custom_folder": [
        "[name 1]",
        "[name 2]"
    ]
}
```
(You can leave out any of the categories if you don't have any keys for that category.)

Run the tool with:
```
python mediafire_dl.py [--metadata-only] [--indent INDENT] input out_dir
```
Where `input` is the JSON file from above, and `out_dir` is where you want to save everything. Pass `--metadata-only` to only fetch metadata or `--indent` to change the JSON indent.

The structure of the output directory will look like this:
```
out_dir/
  mfdl_summary_[TIMESTAMP].json
  some owner/
    examplefile_[QUICKKEY].txt
    examplefile_[QUICKKEY].txt.json
    a folder_[FOLDERKEY]/
      otherfile_[QUICKKEY].pdf
      otherfile_[QUICKKEY].pdf.json
      ...
    some folder_[FOLDERKEY].json
    ...
  another owner/
    ...
```
The `mfdl_summary_[TIMESTAMP].json` file contains the skipped file/folder keys (for which the API returned nothing) and the deleted file keys (for which the API returned data, but the actual file is gone).

## Notes

* When resuming a download job, already downloaded files will not be redownloaded and partially downloaded files will be resumed. However, all metadata will be redownloaded.
* Folder avatars are not saved.
* Upload countries are not included if `--metadata-only` is passed, as doing so requires scraping the file download page.
* The API does not provide a unique ID for owners. So, if two owners have the same name, their files will share the same directory. (At the very least, there’s no chance of files/folders overwriting each other because all file/folder names include their unique key.)

## Legal

This program is licensed under the MIT License. See the `LICENSE` file for more information.
