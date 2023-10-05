import dataclasses
import datetime
import enum
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path


class Extension(enum.Enum):
    h5 = ".h5"
    txt = ".txt"


@dataclass
class Scan:
    path: Path
    reference_file: Path
    created_at: datetime.datetime
    finished_at: datetime.datetime


@dataclass
class SimpleScan(Scan):
    data: Path
    size: int


@dataclass
class StitchedScan(Scan):
    data: list[SimpleScan]
    number_of_subscans: int = field(init=False)
    size: int = field(init=False)
    created_at: datetime.datetime = field(init=False)
    finished_at: datetime.datetime = field(init=False)

    def __post_init__(self):
        self.number_of_subscans = len(self.data)
        self.size = sum([elem.size for elem in self.data])
        timestamps = sorted([elem.created_at for elem in self.data])
        self.created_at = timestamps[0]  # First subscan sets the creation timestamp of the stitched scan
        self.finished_at = timestamps[-1]  # Last subscan sets the finish timestamp of the stitched scan


@dataclass
class Dataset:
    path: Path
    scan: Scan


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
    return size, creation_time


def is_stitched_scan(dataset: Path) -> bool:
    # TODO: Check dirs name, case there is an acquisition inside the previous acquisition
    return any(elem.is_dir() for elem in (dataset.iterdir()))


def list_datasets(path: Path, extension: Extension = Extension.txt, reference_file: Path = None) -> list:
    # TODO: Scans should be returned ordered by creation time
    dataset_paths = [elem for elem in path.iterdir() if elem.is_dir()]
    scans = []
    for dataset in sorted(dataset_paths):
        target_file = find_file_by_extension(dataset, extension)
        if is_stitched_scan(dataset):
            sub_scans = list_datasets(path=dataset, extension=extension, reference_file=target_file)
            scan = StitchedScan(path=dataset, reference_file=target_file, data=sub_scans)
            scans.append(scan)

        else:
            dataset_size, creation_time = get_file_statistics(target_file)
            reference_file = reference_file if reference_file is not None else target_file
            scan = SimpleScan(path=dataset, reference_file=reference_file, data=target_file, size=dataset_size,
                              created_at=creation_time, finished_at=creation_time)  # TODO: Implement finished_at
            scans.append(scan)

    return scans


def validate_result():
    pass


def compute_beamline_statistics(datasets: dict):
    # TODO: Total scan time
    # TODO: Beamtime throughput
    # TODO: Total size
    # TODO: COmplete Dataset size
    total_beamtime_size = 0
    # for dataset_path, values in datasets.items():
    #     if values["sti"]
    pass


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, datetime.datetime):
            return o.isoformat()
        elif isinstance(o, Path):
            return str(o)
        return super().default(o)


if __name__ == "__main__":
    path = Path("../tests/good_beamtime").resolve()
    print(json.dumps(list_datasets(path), cls=EnhancedJSONEncoder, indent=4))
