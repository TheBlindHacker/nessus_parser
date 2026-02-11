# Nessus Parser (Python Edition)

A modern, containerized Python tool to parse Nessus XML v2 (`.nessus`) files into user-friendly Excel reports.

## Features
- **Excel Reporting**: Generates a multi-sheet Excel file with:
  - **Dashboard**: Summary charts and statistics.
  - **Host Summary**: Detailed breakdown of vulnerabilities per host.
  - **Vulnerabilities**: Separate sheets for Critical, High, Medium, Low, and Info findings.
  - **Compliance**: Dedicated sheet for compliance/audit results.
- **Dockerized**: Easy to run without installing Python dependencies locally.

## Usage
## Setup

### Prerequisites
- **Docker**: For containerized execution (Recommended).
- **Python 3.8+**: If running locally.

### Installation (Local Python)
1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/nessus_parser.git
   cd nessus_parser
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Option 1: Docker (Recommended)
Build and run the container without installing Python dependencies on your host.

1. **Build the image**:
   ```bash
   docker build -t nessus_parser .
   ```

2. **Run the parser**:
   Mount your current directory (`$(pwd)` or `${PWD}`) to `/app` so the container can read your `.nessus` file and write the Excel report back.
   ```bash
   # Linux/Mac
   docker run --rm -v $(pwd):/app nessus_parser -f your_scan.nessus

   # Windows PowerShell
   docker run --rm -v ${PWD}:/app nessus_parser -f your_scan.nessus
   ```

### Option 2: Python (Local)
Run the script directly if you have Python installed.

```bash
python nessus_parser.py -f input_file.nessus [-o output_report.xlsx]
```

**Arguments**:
- `-f`, `--file`: (Required) Path to the `.nessus` XML v2 file.
- `-o`, `--output`: (Optional) Filename for the generated Excel report. Defaults to `nessus_report_YYYYMMDDHHMMSS.xlsx`.

## Legacy Code
The original Perl script (`parse_nessus_xml.v24.pl`) has been moved to the `archive/` directory for reference. It is no longer maintained.
