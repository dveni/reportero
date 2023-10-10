# Reportero: TOMCAT:cat2: Beamtime report generator
___
Generate reports for your beamtimes from the terminal.

## Features:
- List acquired datasets and show relevant information
- Compute relevant statistics
- Throw warnings if the file structure is not expected
- Get the report in your terminal, json format


## Usage

## Conventions
- First level folders are independent acquisitions
- Subsequent levels of folders contain in their name the parent folder name (e.g.: parent_name+suffix)
- Creating a report with `csv` format expects a specific set of columns

## Acknowledgments
- Hongjian Wang for beta testing the tool