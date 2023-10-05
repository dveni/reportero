import dataclasses
import datetime
import enum
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union
import argparse

class Extension(enum.Enum):
    h5 = ".h5"
    txt = ".txt"
    log = ".json"


@dataclass
class Scan:
    path: Path
    reference_file: Path
    created_at: datetime.datetime
    finished_at: datetime.datetime
    size: int


@dataclass
class SimpleScan(Scan):
    data: Path


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
        self.created_at = [elem.created_at for elem in self.data][
            0]  # First subscan sets the creation timestamp of the stitched scan
        self.finished_at = [elem.finished_at for elem in self.data][
            -1]  # Last subscan sets the finish timestamp of the stitched scan


@dataclass
class Dataset:
    path: Path
    scans: list[Scan]
    number_of_scans: int = field(init=False)
    size: int = field(init=False)
    scan_time: datetime.timedelta = field(init=False)
    efficiency: float = field(init=False)

    def __post_init__(self):
        self.number_of_scans = len(self.scans)
        self.size = sum([scan.size for scan in self.scans])
        scan_times = [scan.finished_at - scan.created_at for scan in self.scans]
        self.scan_time = sum(scan_times, datetime.timedelta())
        self.efficiency = self.scan_time / (self.scans[-1].finished_at - self.scans[0].created_at)
        print((self.scans[-1].finished_at - self.scans[0].created_at).total_seconds(), self.scans[-1].finished_at,
              self.scans[0].created_at)


def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def find_file_by_extension(path: Path, extension: Extension) -> Union[Path, None]:
    files = [elem for elem in path.iterdir() if extension.value == elem.suffix]
    if len(files) > 1:
        logging.warning(
            f"More that one file with the extension {extension.value} was found in {path}, using first occurrence only.")
    if len(files) == 0:
        logging.warning(f"No target file was found in path {path}!")
        return None
    return files[0]


def get_scan_statistics(target_file: Path, log_file: Path) -> tuple[int, datetime, datetime]:
    stats = target_file.stat()
    size, creation_time = stats.st_size, datetime.datetime.fromtimestamp(stats.st_ctime)
    with open(log_file, "r") as l:
        log = json.load(l)
    return size, creation_time, creation_time  # TODO: Implement finished_at


def is_stitched_scan(dataset: Path) -> bool:
    # TODO: Check dirs name, case there is an acquisition inside the previous acquisition
    return any(elem.is_dir() for elem in (dataset.iterdir()))


def list_scans(path: Path, extension: Extension = Extension.txt, reference_file: Path = None) -> list:
    dataset_paths = [elem for elem in path.iterdir() if elem.is_dir()]
    scans = []
    for dataset in sorted(dataset_paths):
        target_file = find_file_by_extension(dataset, extension)
        log_file = find_file_by_extension(dataset, Extension.log)
        if is_stitched_scan(dataset):
            sub_scans = list_scans(path=dataset, extension=extension, reference_file=target_file)
            scan = StitchedScan(path=dataset, reference_file=target_file, data=sub_scans)
            scans.append(scan)

        else:
            dataset_size, creation_time, finished_time = get_scan_statistics(target_file, log_file=log_file)
            reference_file = reference_file if reference_file is not None else target_file
            scan = SimpleScan(path=dataset, reference_file=reference_file, data=target_file, size=dataset_size,
                              created_at=creation_time, finished_at=finished_time)
            scans.append(scan)

    # Sort by creation date
    scans = sorted(scans, key=lambda scan: scan.created_at)
    return scans


def validate_result():
    pass


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, datetime.datetime):
            return o.isoformat()
        elif isinstance(o, datetime.timedelta):
            return o.total_seconds()
        elif isinstance(o, Path):
            return str(o)
        return super().default(o)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Reportero', description='TOMCAT Beamtime reporting tool', epilog='Created with "\u2764\ufe0f" by Dani')
    parser.add_argument('-p','--path', help='Path containing all the scans of the beamtime.')
    parser.add_argument('-f', '--format', help='Output format', default='json', choices=['json', 'csv'])
    args = parser.parse_args()
    path = Path(args.path).resolve()
    dataset = Dataset(path=path, scans=list_scans(path))
    print(json.dumps(dataset, cls=EnhancedJSONEncoder, indent=4))
