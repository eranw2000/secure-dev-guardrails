# The hook reads one line at a time, so it reports the zip extraction here because the file
# also uses tarfile. semgrep, which parses, stays quiet.
import tarfile
import zipfile

def unpack(path, dest):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)

def safe(path, dest):
    with tarfile.open(path) as tf:
        tf.extractall(dest, filter="data")
