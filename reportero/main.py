# TODO: Generate report with beamtime statistics and potential issues to check manually
# TODO: docs
# TODO: tests

import argparse
import csv
import datetime
import enum
import json
import logging
import re
from dataclasses import dataclass, field, is_dataclass, asdict
from pathlib import Path
from typing import Union, Tuple, Any


class Extension(enum.Enum):
    h5 = "h5"
    txt = "txt"
    log = "log"
    json = "json"


@dataclass
class ScanInfo:
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


@dataclass
class Scan:
    path: Path
    reference_file: Path
    created_at: datetime.datetime
    finished_at: datetime.datetime
    size: int
    info: ScanInfo


@dataclass
class SimpleScan(Scan):
    data: Path


@dataclass
class StitchedScan(Scan):
    data: list[SimpleScan] = field(repr=False)
    number_of_subscans: int = field(init=False)
    size: int = field(init=False)
    created_at: datetime.datetime = field(init=False)
    finished_at: datetime.datetime = field(init=False)
    info: ScanInfo = field(init=False)

    def __post_init__(self):
        self.number_of_subscans = len(self.data)
        self.size = sum([elem.size for elem in self.data])
        self.created_at = [elem.created_at for elem in self.data][
            0]  # First subscan sets the creation timestamp of the stitched scan
        self.finished_at = [elem.finished_at for elem in self.data][
            -1]  # Last subscan sets the finish timestamp of the stitched scan
        self.info = self.data[0].info  # The info of the stitched scan should be the same as in every subscan


@dataclass
class Dataset:
    path: Path
    scans: list[Scan] = field(repr=False)
    number_of_scans: int = field(init=False, default=0)
    size: tuple[float, str] = field(init=False, default=(0, 'B'))
    scan_time: datetime.timedelta = field(init=False, default=datetime.timedelta(0))
    efficiency: float = field(init=False, default=0.0)

    def __post_init__(self):
        if self.scans:
            self.number_of_scans = len(self.scans)
            self.size = sizeof_fmt(sum([scan.size for scan in self.scans]))
            scan_times = [scan.finished_at - scan.created_at for scan in self.scans]
            self.scan_time = sum(scan_times, datetime.timedelta())
            self.efficiency = self.scan_time / (self.scans[-1].finished_at - self.scans[0].created_at)


class Tomcat:
    """
    This class collect all the methods necessary to deal with the TOMCAT ecosystem.
    """
    @staticmethod
    def manage_pcoedge_h5_files(files: list[Path]) -> list[Path]:
        """
        Check if the files are from a pcoedge acquisition. If yes, return only the data file. Else, return all files.
        The pcoEdge acquisition script creates a `.h5` file for metadata and another `.h5` file with the actual data
        and the prefix corresponding to the stitching subscan. When there is a single scan, it adds the prefix `001`
        to the data `.h5` file
        :param files: Two `.h5` files
        :return:
        """
        if len(files) == 2 and all(Extension.h5.value in path.name for path in files):
            # If we are here, we are dealing with the standard pcoEdge acquisition results
            # Return the file with the data (prefix `001`)
            data_file = [f for f in files if '001' in f.name]
            if len(data_file) != 1:
                # This can happen when a data file from other scan is in the wrong folder
                logging.warning("There are two data files! Probably a wrong scan was saved in this folder... ")
                return files
            return data_file
        return files

    # TODO: Ideally, this would not be necessary if the timestamps were loggen into the json file.
    @staticmethod
    def get_timestamps(log_file: Path) -> Union[tuple[datetime.datetime, datetime], tuple[None, None]]:
        """

        :param log_file:
        :return:
        """
        with open(log_file, "r") as file:
            text = file.read()

        # Define the patterns for matching the datetime string (thanks ChatGPT)
        start_pattern = r'scan.*started on\s+(\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})'
        # TODO: I did not manage to find a regexp matching both patterns...
        end_pattern1 = re.compile(r'SCAN\s*FINISHED\s+at\s+(\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})',
                                  re.IGNORECASE)
        end_pattern2 = re.compile(r'scan\s*ended\s+at\s+:\s+(\w{3}\s\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4})',
                                  re.IGNORECASE)

        # Search for the pattern in the text
        start_match = re.search(start_pattern, text)
        end_match1 = re.search(end_pattern1, text)
        end_match2 = re.search(end_pattern2, text)

        if start_match and (end_match1 or end_match2):
            # Extract the matched datetime string
            start_datetime_str = start_match.group(1)
            end_datetime_str = end_match1.group(1) if end_match1 is not None else end_match2.group(1)
            # Convert the string to a datetime object
            created_at = datetime.datetime.strptime(start_datetime_str, '%a %b %d %H:%M:%S %Y')
            finished_at = datetime.datetime.strptime(end_datetime_str, '%a %b %d %H:%M:%S %Y')
            return created_at, finished_at
        else:
            # Return None if no match is found
            return None, None
    @staticmethod
    def ignored_folders():
        return ["log", "sin", "viewrec", "rec_", "fltp", "cpr"]

    @staticmethod
    def get_scan_info(json_file: Path)-> ScanInfo:
        with open(json_file, "r") as j:
            log = json.load(j)

        roi = (
            log["scientificMetadata"]["detectorParameters"]["X-ROI End"] -
            log["scientificMetadata"]["detectorParameters"][
                "X-ROI Start"] + 1,
            log["scientificMetadata"]["detectorParameters"]["Y-ROI End"] -
            log["scientificMetadata"]["detectorParameters"][
                "Y-ROI Start"] + 1)

        return ScanInfo(camera=log["scientificMetadata"]["detectorParameters"]["Camera"],
                                                       microscope=log["scientificMetadata"]["detectorParameters"][
                                                           "Microscope"],
                                                       objective=log["scientificMetadata"]["detectorParameters"][
                                                           "Objective"],
                                                       scintillator=log["scientificMetadata"]["detectorParameters"][
                                                           "Scintillator"], exposure_time=
                                                       log["scientificMetadata"]["detectorParameters"]["Exposure time"][
                                                           'v'], effective_pixel_size=
                                                       log["scientificMetadata"]["detectorParameters"][
                                                           "Actual pixel size"][
                                                           'v'],
                                                       number_of_projections=
                                                       log["scientificMetadata"]["scanParameters"][
                                                           "Number of projections"],
                                                       number_of_darks=log["scientificMetadata"]["scanParameters"][
                                                           "Number of darks"],
                                                       number_of_whites=log["scientificMetadata"]["scanParameters"][
                                                           "Number of flats"], region_of_interest=roi,

                                                       )
    @staticmethod
    def write_csv(dataset: Dataset, csv_file_path: Path):
        """

        :param dataset:
        :param csv_file_path:
        :return:
        """
        # Write data to the CSV file
        with open(csv_file_path, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            columns = ['path', 'created_at', 'size', 'camera', 'microscope', 'exposure_time', 'effective_pixel_size',
                       'projections', 'number_of_subscans']
            # Write header
            csv_writer.writerow(columns)

            # Write data
            for data_instance in dataset.scans:
                name = Path(getattr(data_instance, 'path')).name
                created_at = getattr(data_instance, 'created_at')
                size = sizeof_fmt(getattr(data_instance, 'size'))
                info: ScanInfo = getattr(data_instance, 'info')
                number_of_scans = getattr(data_instance, 'number_of_subscans', 1)
                csv_writer.writerow(
                    [name, created_at, size, info.camera, info.microscope, info.exposure_time,
                     info.effective_pixel_size,
                     info.number_of_projections, number_of_scans])

    @staticmethod
    def filter_config_json(files: list[Path]) -> list[Path]:
        return [json_file for json_file in files if "config" not in json_file.name]


class Report:

    def __init__(self, path: Path,  extension: Extension, output: Path, complete:bool = False,  tomcat: bool = True):
        self.path = path
        self.extension =extension
        self.output = output
        self.complete = complete
        self.tomcat = tomcat

        assert output.suffix in ['.json', '.csv'], "Please, provide an output file path with json or csv format."
        logging.basicConfig(encoding='utf-8', level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(self.output.with_suffix('.log'), mode='w'),
                                      logging.StreamHandler()])

    def generate_report(self):
        logging.info("Generating report...")
        dataset = Dataset(path=self.path, scans=self._list_scans(self.path))
        logging.info("Dataset information:")
        logging.info(dataset)
        if self.output.suffix == 'json':
            with open(self.output, 'w') as f:
                json.dump(dataset, fp=f, default=EnhancedJSONEncoder(complete=self.complete).default, indent=4)
        elif self.output.suffix == 'csv':
            assert Tomcat, "Csv report generation is tailored only for Tomcat!"
            Tomcat.write_csv(dataset, self.output)
        logging.info("Report generated successfully!")

    def _list_scans(self, path: Path, _reference_file: Path = None) -> list:
        """

        :param path:
        :param _reference_file:
        :return:
        """
        dataset_paths = [elem for elem in path.iterdir() if
                         elem.is_dir() and not self._is_path_ignored(elem)]
        scans = []
        for dataset in sorted(dataset_paths):
            target_file = self._find_file_by_extension(dataset, self.extension)
            if self._is_stitched_scan(dataset):
                sub_scans = self._list_scans(path=dataset, _reference_file=target_file)
                if not sub_scans:
                    continue
                scan = StitchedScan(path=dataset, reference_file=target_file, data=sub_scans)
                scans.append(scan)

            else:
                stats = self._get_scan_statistics(target_file)
                if stats is None:
                    continue
                created_at, finished_at, size, scan_stats = stats
                _reference_file = _reference_file if _reference_file is not None else target_file
                scan = SimpleScan(path=dataset, reference_file=_reference_file, data=target_file, size=size,
                                  created_at=created_at, finished_at=finished_at, info=scan_stats)
                scans.append(scan)

        # Sort by creation date
        scans = sorted(scans, key=lambda scan: scan.created_at)
        return scans

    def _get_scan_statistics(self,target_file: Path) -> Union[None, tuple[Any, Any, int, ScanInfo], tuple[
        float, float, int, None]]:
        """

        :param target_file:
        :return:
        """
        if target_file is None:
            return None

        stats = target_file.stat()
        size: int = stats.st_size
        created_at, finished_at = stats.st_ctime, stats.st_mtime

        if self.tomcat:
            log_file, json_file = self._find_log_files(target_file)
            if log_file is None or json_file is None:
                return None

            created_at, finished_at = Tomcat.get_timestamps(log_file)
            scan_info = Tomcat.get_scan_info(json_file)

            return created_at, finished_at, size, scan_info
        else:
            return created_at, finished_at, size, None


    def _is_path_ignored(self, path: Path) -> bool:
        return any(ignored in path.name for ignored in Tomcat.ignored_folders()) if self.tomcat else False

    def _is_stitched_scan(self, dataset: Path) -> bool:
        """

        :param dataset:
        :return:
        """
        # Check whether elements are directories (subscans).
        return any(
            elem.is_dir() and not self._is_path_ignored(elem) for elem in (dataset.iterdir()))

    def _find_file_by_extension(self, path: Path, extension: Extension) -> Union[Path, None]:
        """

        :param path:
        :param extension:
        :return:
        """

        files = [elem for elem in path.iterdir() if extension.value in elem.suffix]
        if self.tomcat and extension == Extension.h5:
            files = Tomcat.manage_pcoedge_h5_files(files)
        if self.tomcat and extension == Extension.json:
            files = Tomcat.filter_config_json(files)
        if len(files) > 1:
            logging.warning(
                f"More that one file with the extension {extension.value} was found in {path}, using first occurrence only.")
        if len(files) == 0:
            logging.warning(f"No file with extension {extension.value} was found in path {path}!")
            return None
        return files[0]

    def _find_log_files(self, target_file: Path) -> Union[tuple[Path, Path], None]:
        json_file = target_file.with_suffix(suffix='.json')
        log_file = target_file.with_suffix(suffix='.log')

        if not log_file.exists():
            log_file = self._find_file_by_extension(target_file.parent, Extension.log)
            logging.warning(f"Expected logfile was not found! Using logfile at {log_file} instead.")
        if not json_file.exists():

            json_file = self._find_file_by_extension(target_file.parent, Extension.json)
            logging.warning(f"Expected logfile was not found! Using logfile at {json_file} instead.")

        # Log files may not exist when a scan was cancelled
        return log_file, json_file

    def validate_result(self):
        # TODO: If size if less than threshold, it's likely a failed scan
        # TODO: Check dirs name, case there is an acquisition inside the previous acquisition: dataset.name in elem.name
        # TODO: Check failed scans (often named with suffixes like our manual stitched scan...)
        # TODO: and the dataset name is contained in subscan name
        #     # (by convention, the subscans are named after the dataset name)
        pass



def sizeof_fmt(num: int, suffix: str = "B") -> tuple[float, str]:
    """

    :param num:
    :param suffix:
    :return:
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return num, unit + suffix
        num /= 1024.0
    return num, unit + suffix


class EnhancedJSONEncoder(json.JSONEncoder):

    def __init__(self, complete: bool = False, **kwargs):
        super(EnhancedJSONEncoder, self).__init__(**kwargs)
        self.complete = complete

    def default(self, o):
        if is_dataclass(o):
            d = asdict(o)
            if not self.complete:
                # Hardcoded, simplest solution at this point aftger exploring how to use dict_factory unsuccessfully.
                d["scans"] = [{k: v for k, v in scan.items() if k not in ["data"]} for scan in d["scans"]]
            return d

        elif isinstance(o, datetime.datetime):
            return o.isoformat()
        elif isinstance(o, datetime.timedelta):
            return o.total_seconds()
        elif isinstance(o, Path):
            return str(o)
        return super().default(o)





if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Reportero', description='\U0001F408TOMCAT Beamtime reporting tool',
                                     epilog='Created with \u2764\ufe0f  by Dani')
    parser.add_argument('-p', '--path', help='Path containing all the scans of the beamtime.')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-e', '--extension', help='File extension of the target file.', default=Extension.h5.value,
                        choices=[e.value for e in Extension])
    parser.add_argument('-c', '--complete',
                        help='Complete dataset representation including details of every subscan. Used only for json outputs. Warning: This will create very long outputs for stitched scans with hundreds of subscans.',
                        action='store_true', default=False)
    args = parser.parse_args()

    Report(path=Path(args.path).resolve(), extension=Extension[args.extension], output=Path(args.output)).generate_report()

