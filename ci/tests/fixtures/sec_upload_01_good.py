# Must stay quiet: filtered tar extraction, and zipfile, which strips ../ and absolute names.
import shutil
import tarfile
import zipfile


def filtered(path, dest):
    with tarfile.open(path) as tf:
        tf.extractall(dest, filter="data")


def filtered_callable(path, dest):
    tarfile.open(path).extractall(dest, filter=tarfile.data_filter)


def zip_archive(path, dest):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)


def generic_filtered(path, dest):
    shutil.unpack_archive(path, dest, filter="data")
