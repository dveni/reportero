import argparse
import dataclasses
import datetime
import enum
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union


class Extension(enum.Enum):
    h5 = "h5"
    txt = "txt"
    log = "json"


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
    files = [elem for elem in path.iterdir() if extension.value in elem.suffix]
    if len(files) > 1:
        logging.warning(
            f"More that one file with the extension {extension.value} was found in {path}, using first occurrence only.")
    if len(files) == 0:
        logging.warning(f"No target file was found in path {path}!")
        return None
    return files[0]


@dataclass
class ScanStats:
    size: int
    created_at: datetime.datetime
    finished_at: datetime.datetime
    camera: str
    microscope: str
    objective: float
    scintillator: str
    exposure_time: int  # [ms]
    effective_pixel_size: float  # [um]
    number_of_projections: int
    number_of_darks: int
    number_of_whites: int
    region_of_interest: tuple[float, float]


# TODO: Ideally, this would not be necessary. However, it's the only file where timestamps are saved...
def _get_timestamps(log_file: Path) -> Union[tuple[datetime.datetime, datetime], None]:
    with open(log_file, "r") as file:
        text = file.read()

    # Define the patterns for matching the datetime string (thanks ChatGPT)
    start_pattern = r'scan.*started on\s+(\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})'
    end_pattern = r'scan ended at\s+:\s+(\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})'

    # Search for the pattern in the text
    start_match = re.search(start_pattern, text)
    end_match = re.search(end_pattern, text)

    if start_match and end_match:
        # Extract the matched datetime string
        start_datetime_str = start_match.group(1)
        end_datetime_str = end_match.group(1)
        # Convert the string to a datetime object
        created_at = datetime.datetime.strptime(start_datetime_str, '%a %b %d %H:%M:%S %Y')
        finished_at = datetime.datetime.strptime(end_datetime_str, '%a %b %d %H:%M:%S %Y')
        return created_at, finished_at
    else:
        # Return None if no match is found
        return None


def get_scan_statistics(target_file: Path) -> Union[ScanStats, None]:
    if target_file is None:
        return None
    stats = target_file.stat()
    size = stats.st_size
    json_file = target_file.with_suffix(suffix='.json')
    log_file = target_file.with_suffix(suffix='.log')
    created_at, finished_at = _get_timestamps(log_file)

    with open(json_file, "r") as j:
        log = json.load(j)

    breakpoint()
    roi = (log["scientificMetadata"]["detectorParameters"]["X-ROI End"] - log["scientificMetadata"]["detectorParameters"]["X-ROI Start"],
           log["scientificMetadata"]["detectorParameters"]["Y-ROI End"] - log["scientificMetadata"]["detectorParameters"]["Y-ROI Start"])

    return ScanStats(size=size, created_at=created_at, finished_at=finished_at,
        camera=log["scientificMetadata"]["detectorParameters"]["Camera"], microscope=log["scientificMetadata"]["detectorParameters"]["Microscope"],
        objective=log["scientificMetadata"]["detectorParameters"]["Objective"], scintillator=log["scientificMetadata"]["detectorParameters"]["Scintillator"],
        exposure_time=log["scientificMetadata"]["detectorParameters"]["Exposure time"],
        effective_pixel_size=log["scientificMetadata"]["detectorParameters"]["Actual pixel size"],
        number_of_projections=log["scientificMetadata"]["scanParameters"]["Number of projections"],
        number_of_darks=log["scientificMetadata"]["scanParameters"]["Number of darks"],
        number_of_whites=log["scientificMetadata"]["scanParameters"]["Number of whites"], region_of_interest=roi,

    )


def is_stitched_scan(dataset: Path) -> bool:
    # TODO: Check dirs name, case there is an acquisition inside the previous acquisition
    # Check whether elements are directories (subscans) and the dataset name is contained in subscan name
    # (by convention, the subscans are named after the dataset name).
    return any(elem.is_dir() and dataset.name in elem.name for elem in (dataset.iterdir()))


def list_scans(path: Path, extension: Extension = Extension.txt, _reference_file: Path = None) -> list:
    dataset_paths = [elem for elem in path.iterdir() if elem.is_dir() and not elem.match("logs")]
    scans = []
    for dataset in sorted(dataset_paths):
        target_file = find_file_by_extension(dataset, extension)
        if is_stitched_scan(dataset):
            sub_scans = list_scans(path=dataset, extension=extension, _reference_file=target_file)
            scan = StitchedScan(path=dataset, reference_file=target_file, data=sub_scans)
            scans.append(scan)

        else:
            dataset_size, creation_time, finished_time = get_scan_statistics(target_file)
            _reference_file = _reference_file if _reference_file is not None else target_file
            scan = SimpleScan(path=dataset, reference_file=_reference_file, data=target_file, size=dataset_size,
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
    parser = argparse.ArgumentParser(prog='Reportero', description='TOMCAT Beamtime reporting tool',
                                     epilog='Created with \u2764\ufe0f  by Dani')
    parser.add_argument('-p', '--path', help='Path containing all the scans of the beamtime.')
    parser.add_argument('-f', '--format', help='Output format', default='json', choices=['json', 'csv'])
    parser.add_argument('-e', '--extension', help='File extension of the target file.', default=Extension.h5.value,
                        choices=[e.value for e in Extension])
    args = parser.parse_args()
    path = Path(args.path).resolve()
    dataset = Dataset(path=path, scans=list_scans(path, extension=Extension[args.extension]))
    print(json.dumps(dataset, cls=EnhancedJSONEncoder, indent=4))
