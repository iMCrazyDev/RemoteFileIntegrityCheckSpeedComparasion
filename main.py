import time
from random import shuffle
import numpy as np
from files_collection import FilesCollection, ReedSolomon, ConvolutionCodes


def test_verification(n):
    start_time = time.perf_counter()
    files_collection = FilesCollection(n, generate_merkle_root=True, generate_solomones=False)
    assert len(files_collection.file_hashes) > 1
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time

    root = files_collection.get_merkle_root()
    hashes = [(hash_value, idx) for idx, hash_value in enumerate(files_collection.get_all_hashes())]

    shuffle(hashes)



    for hash_value, idx in hashes:
        path = files_collection.get_verification_path(idx)
        assert FilesCollection.verify_merkle_path(hash_value, path, root)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time

def test_consistency(n):

    files_collection = FilesCollection(n, generate_merkle_root=False, generate_solomones=False)
    assert len(files_collection.file_hashes) > 1
    computed_hashes = files_collection.get_all_hashes()
    hashes = [(hash_value, idx) for idx, hash_value in enumerate(computed_hashes)]

    shuffle(hashes)

    start_time = time.perf_counter()

    for hash_value, idx in hashes:
        assert hash_value == computed_hashes[idx], True

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time

def test_solomon(n):
    start_time = time.perf_counter()

    files_collection = FilesCollection(n, generate_merkle_root=False, generate_solomones=True)
    #solomones = files_collection.get_all_solomones()
    #hashes = files_collection.get_all_hashes()

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time
    rs = ReedSolomon(FilesCollection.generate_valid_primitive_poly())

    for idx, solomon in enumerate(solomones):
        assert rs.encode(FilesCollection.bytes_to_array_i(bytes.fromhex(hashes[idx]))) == solomon, True

def test_aes(n):
    start_time = time.perf_counter()
    files_collection = FilesCollection(n, generate_merkle_root=False, generate_solomones=False, generate_aes=True)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time
    hashes = files_collection.get_all_hashes()
    aes = files_collection.get_all_aes()

    start_time = time.perf_counter()

    for idx, hash_value in enumerate(hashes):
        assert FilesCollection.decrypt_aes(aes[idx]).decode('utf-8') == hash_value

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time

def test_convolution_codes(n):
    start_time = time.perf_counter()
    files_collection = FilesCollection(n, generate_merkle_root=False, generate_solomones=False, generate_aes=False, generate_conv=True)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time
    hashes = files_collection.get_all_hashes()
    codes = files_collection.convolution_codes
    conv = ConvolutionCodes()

    start_time = time.perf_counter()
    for idx, hash_value in enumerate(hashes):
        assert np.array_equal(conv.decode(bytes.fromhex(hash_value)), codes[idx])

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return elapsed_time

def run_performance_tests():
    results = []
    for n in [10**2, 10**3, 10**4]:
        elapsed_time = test_convolution_codes(n)
        results.append((n, elapsed_time))
        print(f"n = {n}: Time {elapsed_time:.9f} sec")
    return results

performance_results = run_performance_tests()
print("Results:", performance_results)
