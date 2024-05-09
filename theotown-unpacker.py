import argparse
import io
import json
import os
import pathlib
import re
import time
import zipfile

# check if we're running in termux. deny GUI if we are
_is_termux = "TERMUX_VERSION" in os.environ
if not _is_termux:
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename, askdirectory

from hashlib import md5


_debug = False
_time_start = time.perf_counter_ns()
def debug_log(text):
    if not _debug:
        return
    
    print(f"[{int((time.perf_counter_ns() - _time_start) / 1000000000)}s] {text}")


def info_log(text):
    print(f"[{int((time.perf_counter_ns() - _time_start) / 1000000000)}s] {text}")


def load_apk_from_xapk(xapk_path: pathlib.Path) -> zipfile.ZipFile:
    xapk: zipfile.ZipFile = zipfile.ZipFile(xapk_path, "r")

    for member in xapk.namelist():
        if member == "base.apk":
            file_obj = io.BytesIO(xapk.read(member))

            return zipfile.ZipFile(file_obj, "r")
        
        if member == "manifest.json":
            manifest = json.loads(xapk.read(member).decode("utf-8"))

            for split_apk in manifest["split_apks"]:
                if split_apk["id"] != "base":
                    continue

                file_obj = io.BytesIO(xapk.read(split_apk["file"]))

                return zipfile.ZipFile(file_obj, "r")
    
    raise Exception("No base apk found in xapk.")


def get_root_dirs(apk: zipfile.ZipFile) -> set:
    # https://stackoverflow.com/a/36186422/22245176
    dirs = list(set([os.path.dirname(x) for x in apk.namelist()]))
    root_dirs = set()

    for x in dirs:
        path = pathlib.Path(x)

        if len(path.name) == 0:
            continue

        if len(path.parts) == 0:
            root_dirs.add(path.name)

            continue

        root_dirs.add(path.parts[0])
    
    return root_dirs


def decrypt_file(file_path: str, apk: zipfile.ZipFile) -> bytearray:
    dec_buf = bytearray()

    with apk.open("assets/" + file_path, "r") as lby_fobj:
        lby_b1 = lby_fobj.read(1)[0]

        len_mod = lby_b1 * 0x4165
        len_mod = len_mod * 0xA3
        len_mod = len_mod + (lby_b1 * 0x95) + 0x65

        for byte in lby_fobj.read():
            val = (byte ^ len_mod) & 0xff
            
            if val > 0x7f:
                val -= 0x80
            
            dec_buf.append(val)

            len_mod += 0xA3
    
    return dec_buf


def main(apk_path: pathlib.Path, output_dir: pathlib.Path):
    apk: zipfile.ZipFile = None

    if apk_path.suffix in (".xapks", ".xapk", ".apks"):
        debug_log("Loading xapk...")

        apk = load_apk_from_xapk(apk_path)
    else:
        apk = zipfile.ZipFile(apk_path, "r")
        root_dirs = list(get_root_dirs(apk))

        if "assets" not in root_dirs:
            # attempt one last time to load xapk
            apk = load_apk_from_xapk(apk_path)

            root_dirs = list(get_root_dirs(apk))

            if "assets" not in root_dirs:
                raise Exception("Invalid apk file.")
        
    # process files.lby first
    file_data = json.loads(decrypt_file("files.lby", apk).decode("utf-8"))

    debug_log(f"files.json hash: {file_data['files hash']}")
    debug_log(f"version: {file_data['version']}")
    debug_log(f"gversion: {file_data['gversion']}")
    debug_log(f"vh: {file_data['vh']}")
    debug_log(f"vi: {file_data['vi']}")
    debug_log(f"id: {file_data['id']}")

    info_log("Decrypting files...")

    for file in file_data["files"]:
        if not file["lby"]:
            continue

        if file["original name"].endswith(".png"):
            continue  # these don't decode properly for some reason

        apk_filename = "assets/" + file["name"]
        file_zi = apk.getinfo(apk_filename)
        file_data = apk.read(apk_filename)

        if file_zi.file_size != file["size"]:
            info_log(f"Warning: Archive and disk sizes don't match for file {file['name']}.")
        
        if md5(file_data).hexdigest() != file["hash"]:
            info_log(f"Warning: File hash doesn't match archive file hash for {file['name']}.")
        
        decrypted_file = decrypt_file(file["name"], apk)

        if len(decrypted_file) != file["original size"]:
            info_log(f"Warning: Decrypted size doesn't match original size for file {file['name']}.")
        
        if md5(decrypted_file).hexdigest() != file["original hash"]:
            info_log(f"Warning: Decrypted hash doesn't match original hash for file {file['name']}.")
        
        with open(os.path.join(output_dir, file["original name"]), "wb") as out_fobj:
            debug_log(f"Writing to {os.path.join(output_dir, file['original name'])}...")

            if file["original name"].endswith(".json"):
                # why the fuck do they have comments in the json files?
                unga_bunga = re.search(r"\/\/.*|\/\*", decrypted_file.decode("utf-8"))

                if unga_bunga:
                    out_fobj.write(decrypted_file)

                    continue

                decrypted_file = json.dumps(json.loads(decrypted_file), indent = 2)
                decrypted_file = decrypted_file.encode("utf-8")

            out_fobj.write(decrypted_file)
    
    info_log("Dumping lua scripts...")

    # dump scripts into their own folder
    with open(os.path.join(output_dir, "scripting.json"), "r") as scripts_fobj:
        output_dir = os.path.join(output_dir, "lua_src")
        
        os.makedirs(output_dir, mode=0o755, exist_ok=True)

        for script in json.loads(scripts_fobj.read()):
            path = os.path.join(output_dir, script["path"])

            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            debug_log(f"Dumping script {script['name']} to {path}...")

            with open(path, "w") as script_out:
                script_out.write(script["code"])


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-o",
        help="the directory to output to",
        type=str,
        metavar="",
        default=os.getcwd()
    )

    parser.add_argument(
        "-v",
        help="turns verbose logging on",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "apk_file",
        help="apk/xapk/apks file to process",
        type=str
    )

    args = parser.parse_args()

    return (pathlib.Path(args.apk_file), pathlib.Path(args.o), args.v)


if __name__ == "__main__":
    if _is_termux:
        xapk_file, output_dir, _debug = parse_args()
    else:
        Tk().withdraw()

        xapk_file = pathlib.Path(askopenfilename(title="Select TheoTown APK/XAPK/ZIP file"))
        output_dir = pathlib.Path(askdirectory(title="Select output directory", mustexist=True))

    main(xapk_file, output_dir)