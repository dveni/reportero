# Reportero: TOMCAT:cat2: Beamtime report generator

Generate reports for your beamtimes from the terminal.

## Features:
- List acquired datasets and show relevant information
- Compute relevant statistics
- Throw warnings if the file structure is not expected
- Get the report in your terminal, json format


## Usage

Install the tool (recommended to install it in a separate venv or conda env):
```
pip install git+https://github.com/dveni/reportero.git
```
Run the tool on one of your beamtime folders:
```
reportero -p <PATH TO BEAMTIME FOLDER> -o test.csv
```
> Note: You may need to use the `ignore_folders` argument to omit directories when checking for stitched scans. Inside scans, there might be folders that do not correspond to subscans. This will make the stiched scan scheck to consider that it is a subscan, and it will be skipped afterwards because no subscans were found. A warning is raised in this case. For example:
```bash
reportero -p <PATH> -o test.csv -ig dataset correct images output v2e frame
```
>will ignore folders containing the strings `['dataset', 'correct', 'images', 'output', 'v2e', 'frame']` when checking whether a given directory is a stitched scan.

This will create two files:
- test.csv: Contains a list with all the scans done during the beamtime sorted by creation time, along with relevant information. The output file can be named differently. 
- test.log: Log file showing warnings that could be potential issues (e.g.: Missing flat images files, duplicated files, etc). It is recommended to check each of them.

Additionally, you will be able to see relevant statistics (both in the logs and on the terminal):
- Total data size
- Number of scans
- Total scanning time
- Beamtime efficiency: ration between total scanning time and the difference between the finished timestamp of the last scan and the created timestamp of the first scan.

More options are explained in the help command `reportero -h`

## Conventions
- First level folders are independent acquisitions
- Subsequent levels of folders contain in their name the parent folder name (e.g.: parent_name+suffix)
- Creating a report with `csv` format outputs a specific set of columns. Only available in the TOMCAT ecosystem (should be easy to generalize).

## Acknowledgments
- Hongjian Wang for beta testing the tool