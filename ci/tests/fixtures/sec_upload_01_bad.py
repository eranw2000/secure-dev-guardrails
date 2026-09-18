# Insecure on purpose: every marked line unpacks an archive with no path filter.
import shutil
import tarfile


def with_block(path, dest):
    with tarfile.open(path) as tf:
        tf.extractall(dest)  # EXPECT SEC-UPLOAD-01


def assigned(path, dest):
    tf = tarfile.open(path)
    tf.extract("member.txt", dest)  # EXPECT SEC-UPLOAD-01


def chained(path, dest):
    tarfile.open(path).extractall(dest)  # EXPECT SEC-UPLOAD-01


def generic(path, dest):
    shutil.unpack_archive(path, dest)  # EXPECT SEC-UPLOAD-01


def trusted_by_name(path, dest):
    with tarfile.open(path) as tf:
        tf.extractall(dest, filter="fully_trusted")  # EXPECT SEC-UPLOAD-01


def generic_trusted(path, dest):
    shutil.unpack_archive(path, dest, filter="fully_trusted")  # EXPECT SEC-UPLOAD-01


def class_open(path, dest):
    with tarfile.TarFile.open(path) as tf:
        tf.extractall(dest)  # EXPECT SEC-UPLOAD-01


def filter_in_a_variable(path, dest):
    chosen = "fully_trusted"
    shutil.unpack_archive(path, dest, filter=chosen)  # EXPECT SEC-UPLOAD-01


def unknown_filter(path, dest):
    with tarfile.open(path) as tf:
        tf.extractall(dest, filter=my_filter)  # EXPECT SEC-UPLOAD-01
