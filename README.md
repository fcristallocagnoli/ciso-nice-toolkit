# Oju Decison Support System

## Authors
- Fabrizio Cristallo
- Rubén Higueras
- Pablo Serrano
- Marco López
  
## Usage
```
usage: nice_toolkit.py [-h] [--url URL] [--outdir OUTDIR] [--depth DEPTH] {init,graph,gap,recommend,risk,plan} ...

CISO DSS — NICE Framework Toolkit

positional arguments:
  {init,graph,gap,recommend,risk,plan}
    init                Bootstrap sample data files (roles_costs.csv, risk_scenarios.json, etc.)
    graph               Export edges TSV
    gap                 Gap analysis
    recommend           Multi-objective team recommendation
    risk                Risk scenario simulation
    plan                Full 2-year CISO plan + dashboard

options:
  -h, --help            show this help message and exit
  --url URL             NICE Framework JSON URL
  --outdir OUTDIR       Output directory
  --depth DEPTH         BFS depth for coverage traversal

Examples:
  # 1. Bootstrap sample data files
  python nice_toolkit.py --outdir out init

  # 2. Export NICE graph edges (for inspection)
  python nice_toolkit.py --outdir out graph

  # 3. Gap analysis
  python nice_toolkit.py --outdir out gap --current out/current_roles.txt --target out/target_roles.txt --focus soc

  # 4. Team recommendation with budget
  python nice_toolkit.py --outdir out recommend --focus soc --top 8 --budget 250000 --costs out/roles_costs.csv

  # 5. Risk simulation
  python nice_toolkit.py --outdir out risk --current out/current_roles.txt --scenarios out/risk_scenarios.json --costs out/roles_costs.csv --focus soc --top 8

  # 6. Full 2-year plan + dashboard (all-in-one)
  python nice_toolkit.py --outdir out plan --current out/current_roles.txt --scenarios out/risk_scenarios.json --costs out/roles_costs.csv --focus soc --top 8 --budget 250000
```