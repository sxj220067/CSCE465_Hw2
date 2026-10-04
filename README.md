# CSCE 465 Homework 2

- This project covers CTR malleability, a DH handshake, and a secure record layer.
- The graded document is `report.pdf`.
- This bundle is support material, not the complete submission by itself.

## Setup

- Run this in the course VM with NAT networking.
- From the parent of `hw2`, run:

```bash
sudo apt update
sudo apt install -y python3-venv openssl
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r hw2/requirements.txt
cd hw2
python3 setup_lab.py
```

- OpenSSL 3.0 or newer is required.
- `setup_lab.py` creates missing RSA identities and the DH group file.
- It keeps existing files and rejects inconsistent RSA keys.
- The private RSA keys are local and excluded from the submission archive.

## Run the tasks

```bash
python3 baseline_ctr.py | tee task1_output.txt
python3 handshake.py | tee task2_output.txt
python3 secure_record.py 2>&1 | tee task3_output.txt
set -o pipefail
python3 -m pytest -v tests 2>&1 | tee all_tests_output.txt
```

- The observed result was 35 passed tests in 78.17 seconds.
- Random ciphertexts, signatures, and session IDs change across runs.
- The baseline receiver simulates processing and does not edit `notes.txt`.

## Files

- `baseline_ctr.py` shows the CTR tampering and replay behavior.
- `handshake.py` runs the authenticated DH exchange.
- `secure_record.py` implements the record-layer encryption and MAC checks.
- `tests/test_handshake.py` has 17 handshake tests.
- `tests/test_secure_record.py` has 18 record-layer tests.
- `report.md` is the editable report source.
- `report.pdf` is the rendered draft.
- `security_note.md` is the security note.
- `evidence/` contains screenshots and appendix material.

## AI use

- See [AI_USAGE.md](AI_USAGE.md) for the AI usage summary.
- The required conversation export still needs to be attached before submission.

## Limits

- The IV format is `session_id || sequence`.
- This can overlap CTR counters across long records.
- The report explains this limitation clearly.
- The tests verify behavior, not a proof of perfect confidentiality.

## Final steps

- Review the report and make sure it matches your own understanding.
- Run `python3 build_report_html.py` after editing `report.md`.
- Open `report.html` in the VM browser and save it as `report.pdf`.
- Copy the needed files into the VM `hw2` folder without replacing tested logs or code.
- Run `python3 package_submission.py` to build the final archive.
- Check the zip before uploading it.
