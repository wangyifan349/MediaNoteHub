import os
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

def sha256sum(filename):
    h  = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
    except Exception as e:
        # 返回None表示读取失败
        return None, filename, e
    return h.hexdigest(), filename, None

def find_and_remove_duplicates_multithread(root_dir, max_workers=8):
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            files.append(full_path)

    hash_dict = {}
    duplicates = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(sha256sum, f): f for f in files}

        for future in as_completed(futures):
            file_hash, file_path, error = future.result()
            if error:
                print(f"读取文件失败 {file_path}: {error}")
                continue
            if file_hash in hash_dict:
                duplicates.append(file_path)
            else:
                hash_dict[file_hash] = file_path

    # 删除重复文件，保留一个
    for f in duplicates:
        try:
            print(f"删除重复文件: {f}")
            os.remove(f)
        except Exception as e:
            print(f"删除失败 {f}: {e}")

if __name__ == "__main__":
    root_directory = input("请输入要扫描的目录路径: ").strip()
    if os.path.isdir(root_directory):
        find_and_remove_duplicates_multithread(root_directory)
    else:
        print("输入的路径不是有效目录")
