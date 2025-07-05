from pathlib import Path
from phishing_email_parser.processing.msg_converter import MSGConverter

out_dir = Path("debug_artifacts").resolve()     # pick any folder you like
out_dir.mkdir(exist_ok=True)

eml_path = MSGConverter().convert_msg_to_eml("binary_sample.msg", str(out_dir))
print("EML:", eml_path)
print("All attachments are now in:", out_dir)
