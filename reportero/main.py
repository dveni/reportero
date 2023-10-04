import datetime
import enum
import json
import logging
from pathlib import Path


class Extension(enum.Enum):
    h5 = ".h5"
    txt = ".txt"


def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def find_file_by_extension(path: Path, extension: Extension) -> Path | None:
    files = [elem for elem in path.iterdir() if extension.value == elem.suffix]
    if len(files) > 1:
        logging.warning(
            f"More that one file with the extension {extension.value} was found in {path}, using first occurrence only.")
    if len(files) == 0:
        logging.warning(f"No target file was found in path {path}!")
        return None
    return files[0]


def get_file_statistics(file: Path) -> tuple[int, datetime]:
    stats = file.stat()
    size, creation_time = stats.st_size, datetime.datetime.fromtimestamp(stats.st_ctime)
    return size, str(creation_time)


def is_stitched_scan(dataset: Path) -> bool:
    # TODO: Check dirs name, case there is an acquisition inside the previous acquisition
    return any(elem.is_dir() for elem in (dataset.iterdir()))


def list_datasets(path: Path, extension: Extension = Extension.txt, is_subscan: bool = False) -> dict:
    datasets = [elem for elem in path.iterdir() if elem.is_dir()]
    result = {}
    for dataset in sorted(datasets):
        target_file = find_file_by_extension(dataset, extension)
        if is_stitched_scan(dataset):
            sub_result = list_datasets(path=dataset, extension=extension, is_subscan=True)
            result[str(dataset)] = {"stitched_scan": True, "reference_path": str(target_file), "result": sub_result}

        else:
            dataset_size, creation_time = get_file_statistics(target_file)
            result[str(dataset)] = {"stitched_scan": False, "size": dataset_size, "created_at": creation_time,
                                    "data_path": str(target_file)}
            if not is_subscan:
                result[str(dataset)].update({"reference_path": str(target_file)})

    return result


def validate_result():
    pass


def compute_beamline_statistics():
    # TODO: Total scan time
    # TODO: Beamtime throughput
    # TODO: Total size
    # TODO: COmplete Dataset size
    pass


if __name__ == "__main__":
    path = Path("../tests/test_dirs").resolve()
    res = list_datasets(path)
    print(json.dumps(res))
