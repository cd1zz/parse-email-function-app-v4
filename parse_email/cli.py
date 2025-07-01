import argparse, json, pathlib, sys
from .email_parser import EmailParser

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help=".eml / .msg file to parse")
    ap.add_argument("-o", "--output", help="write JSON to file instead of stdout")
    args = ap.parse_args()

    raw = pathlib.Path(args.path).read_bytes()
    doc = EmailParser().parse(raw)

    if args.output:
        pathlib.Path(args.output).write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    else:
        json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
